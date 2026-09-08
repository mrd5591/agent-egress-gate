# agent-egress-gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go forward proxy that enforces a deny-by-default egress allowlist for headless coding agents, writes a tamper-evident audit log, and ships with the Terraform that makes it the only route off the subnet.

**Architecture:** Two listeners. The data listener proxies HTTP absolute-URI requests and CONNECT tunnels; the admin listener serves metrics, health, and policy reload, and is never exposed to the agent. Policy evaluation and audit chaining are pure packages with no I/O, so the correctness-critical logic is testable without sockets. The proxy package is tested against real `httptest` servers, including TLS.

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3`, `github.com/prometheus/client_golang`, `github.com/google/go-cmp` (test only). Terraform 1.16 with the AWS provider. GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-08-agent-egress-gate-design.md`

## Global Constraints

- Module path is `github.com/mrd5591/agent-egress-gate`. Go version floor 1.24; CI matrix covers 1.24 and 1.25 on Linux and Windows.
- Runtime dependencies limited to `yaml.v3` and `prometheus/client_golang`. Test-only dependency `go-cmp` is permitted. No CLI framework; use stdlib `flag` with subcommand flag sets.
- Deny by default. A request that matches no rule is denied. The default action is explicit in the policy file and parsing fails if it is missing.
- A rule that sets `methods` or `paths` is not eligible to authorise a CONNECT tunnel. This is a hard rule, tested directly, and the audit record must state it as the reason.
- A rule with no `ports` is eligible on ports 80 and 443 only, never "any port".
- Host pattern `*.example.com` matches one or more subdomain labels and does not match the apex `example.com`.
- Every test runs under `-race`. Coverage floor enforced in CI at 90 percent of statements; the target is higher.
- No package may hold global mutable state. Prometheus collectors take a `prometheus.Registerer` argument.
- All exported identifiers carry doc comments. `go vet` and `golangci-lint` clean.
- Terraform is validated, never applied. No AWS credentials exist in this repo and the README must say so.

---

### Task 1: Policy package

**Files:**
- Create: `internal/policy/policy.go`
- Create: `internal/policy/policy_test.go`
- Modify: `go.mod` (add `gopkg.in/yaml.v3`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  type Action string          // "allow" | "deny"
  type Kind string            // "http" | "connect"
  const (Allow Action = "allow"; Deny Action = "deny")
  const (KindHTTP Kind = "http"; KindConnect Kind = "connect")

  type Rule struct {
      Name    string   `yaml:"name"`
      Hosts   []string `yaml:"hosts"`
      Methods []string `yaml:"methods"`
      Paths   []string `yaml:"paths"`
      Ports   []int    `yaml:"ports"`
  }
  type Policy struct {
      Version int    `yaml:"version"`
      Default Action `yaml:"default"`
      Rules   []Rule `yaml:"rules"`
  }
  type Request struct {
      Kind   Kind
      Host   string
      Port   int
      Method string   // empty for CONNECT
      Path   string   // empty for CONNECT
  }
  type Decision struct {
      Action Action
      Rule   string
      Reason string
  }

  func Parse(data []byte) (*Policy, error)
  func (p *Policy) Evaluate(r Request) Decision
  ```

- [ ] **Step 1: Write the failing tests**

Table-driven, covering host matching, wildcard semantics, port defaulting, method and path constraints, and the CONNECT eligibility rule.

```go
func TestEvaluate(t *testing.T) {
    p := mustParse(t, `
version: 1
default: deny
rules:
  - name: gh
    hosts: ["api.github.com"]
    methods: ["GET"]
    paths: ["/repos/"]
  - name: registries
    hosts: ["pypi.org", "*.pypi.org"]
`)
    cases := []struct {
        name string
        req  Request
        want Decision
    }{
        {"http allowed by exact host and method and path",
            Request{KindHTTP, "api.github.com", 443, "GET", "/repos/x"},
            Decision{Allow, "gh", "matched rule gh"}},
        {"http denied on method",
            Request{KindHTTP, "api.github.com", 443, "DELETE", "/repos/x"},
            Decision{Deny, "", "no rule matched"}},
        {"http denied on path prefix",
            Request{KindHTTP, "api.github.com", 443, "GET", "/orgs/x"},
            Decision{Deny, "", "no rule matched"}},
        {"connect refused for constrained rule",
            Request{Kind: KindConnect, Host: "api.github.com", Port: 443},
            Decision{Deny, "", "rule gh matched host but constrains method or path, which cannot be enforced inside a tunnel"}},
        {"connect allowed for host-only rule",
            Request{Kind: KindConnect, Host: "pypi.org", Port: 443},
            Decision{Allow, "registries", "matched rule registries"}},
        {"wildcard matches subdomain",
            Request{Kind: KindConnect, Host: "files.pypi.org", Port: 443},
            Decision{Allow, "registries", "matched rule registries"}},
        {"wildcard does not match apex of a different rule",
            Request{Kind: KindConnect, Host: "evil.com", Port: 443},
            Decision{Deny, "", "no rule matched"}},
        {"non-default port denied without explicit ports",
            Request{Kind: KindConnect, Host: "pypi.org", Port: 8443},
            Decision{Deny, "", "no rule matched"}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := p.Evaluate(tc.req)
            if diff := cmp.Diff(tc.want, got); diff != "" {
                t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
            }
        })
    }
}
```

Parse rejection cases, each asserting a specific error substring: missing version, wrong version, missing default, unknown default value, rule without a name, duplicate rule name, rule without hosts, empty host string, wildcard not in leading position, path not starting with `/`, port out of range, unknown method token.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run Test -v`
Expected: build failure, `undefined: Parse`.

- [ ] **Step 3: Implement**

`Parse` unmarshals with `yaml.Unmarshal`, then runs `validate()`, which walks rules and returns the first error found with the offending rule name in the message. Methods are upper-cased in place. Host patterns are lower-cased in place.

`Evaluate` iterates rules in order and returns on the first match. Host matching is a helper `hostMatches(pattern, host string) bool`: exact compare after lower-casing, or, for a `*.` prefix, require `strings.HasSuffix(host, pattern[1:])` and require at least one additional label before the suffix. Port matching uses the rule's ports if set, otherwise `{80, 443}`.

For `KindConnect`, a rule with `len(Methods) > 0 || len(Paths) > 0` is skipped, but the fact is remembered so the denial reason can name the rule that nearly matched.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -race -cover`
Expected: PASS, coverage at or near 100 percent of statements.

- [ ] **Step 5: Commit**

```bash
git add internal/policy go.mod go.sum
git commit -m "Policy evaluation: deny by default, no tunnel on constrained rules"
```

---

### Task 2: Audit package

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/audit_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  type Record struct {
      Seq        uint64 `json:"seq"`
      TS         string `json:"ts"`
      Kind       string `json:"kind"`
      Method     string `json:"method,omitempty"`
      Host       string `json:"host"`
      Port       int    `json:"port"`
      Path       string `json:"path,omitempty"`
      Decision   string `json:"decision"`
      Rule       string `json:"rule,omitempty"`
      Reason     string `json:"reason,omitempty"`
      Client     string `json:"client"`
      Status     int    `json:"status,omitempty"`
      BytesUp    int64  `json:"bytes_up"`
      BytesDown  int64  `json:"bytes_down"`
      DurationMS int64  `json:"duration_ms"`
      Prev       string `json:"prev"`
      Hash       string `json:"hash"`
  }

  const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

  type Log struct{ /* unexported */ }
  func New(w io.Writer) *Log
  func Resume(w io.Writer, head string, seq uint64) *Log
  func (l *Log) Append(r Record) (Record, error)
  func (l *Log) Head() (hash string, seq uint64)

  type VerifyResult struct {
      Records int
      Head    string
      OK      bool
      BreakAt uint64
      Problem string
  }
  func Verify(r io.Reader) (VerifyResult, error)
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestAppendChainsHashes(t *testing.T) {
    var buf bytes.Buffer
    l := New(&buf)
    r1, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"})
    if err != nil { t.Fatal(err) }
    if r1.Seq != 1 { t.Errorf("Seq = %d, want 1", r1.Seq) }
    if r1.Prev != GenesisHash { t.Errorf("Prev = %q, want genesis", r1.Prev) }
    r2, err := l.Append(Record{Kind: "connect", Host: "b.com", Port: 443, Decision: "deny"})
    if err != nil { t.Fatal(err) }
    if r2.Prev != r1.Hash { t.Errorf("Prev = %q, want %q", r2.Prev, r1.Hash) }

    res, err := Verify(bytes.NewReader(buf.Bytes()))
    if err != nil { t.Fatal(err) }
    if !res.OK || res.Records != 2 { t.Errorf("Verify = %+v, want OK with 2 records", res) }
}

func TestVerifyDetectsMutatedMiddleRecord(t *testing.T) {
    // Append three records, rewrite the host on record 2, expect BreakAt == 2.
}

func TestVerifyDetectsResequencing(t *testing.T) {
    // Swap two lines; expect OK == false with a sequence problem.
}

func TestAppendIsSafeForConcurrentUse(t *testing.T) {
    // 50 goroutines appending; then Verify must report OK and 50 records.
    // Run under -race.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -v`
Expected: build failure, `undefined: New`.

- [ ] **Step 3: Implement**

`Log` holds a `sync.Mutex`, the writer, the previous hash, and the sequence counter. `Append` sets `Seq`, `TS` (RFC 3339 in UTC, injectable clock via an unexported field defaulting to `time.Now` so tests are deterministic), and `Prev`, computes the hash, sets it, marshals the completed record, and writes it followed by `\n`.

Hash input is `SHA-256` over the concatenation of the previous hash bytes and the JSON encoding of the record with `Hash` set to the empty string. Go marshals struct fields in declaration order, so the encoding is deterministic without a separate canonicaliser; the test asserts a fixed known hash for a fixed record to lock this in.

`Verify` scans with `bufio.Scanner` (buffer raised to 1 MiB to tolerate long reason strings), unmarshals each line, checks that `Seq` is exactly one greater than the last, that `Prev` equals the running hash, and that the recomputed hash equals the stored one. The first failure sets `BreakAt` and `Problem` and stops.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit
git commit -m "Hash-chained audit log with offline verifier"
```

---

### Task 3: Metrics package

**Files:**
- Create: `internal/metrics/metrics.go`
- Create: `internal/metrics/metrics_test.go`
- Modify: `go.mod` (add `github.com/prometheus/client_golang`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  type Metrics struct {
      Requests *prometheus.CounterVec   // labels: decision, rule, kind
      Duration *prometheus.HistogramVec // labels: kind
      Bytes    *prometheus.CounterVec   // labels: direction ("up"|"down")
      Tunnels  prometheus.Gauge
      Reloads  *prometheus.CounterVec   // labels: result ("ok"|"error")
  }
  func New(reg prometheus.Registerer) *Metrics
  ```

- [ ] **Step 1: Write the failing test**

```go
func TestNewRegistersAllCollectors(t *testing.T) {
    reg := prometheus.NewRegistry()
    m := New(reg)
    m.Requests.WithLabelValues("allow", "gh", "http").Inc()
    m.Tunnels.Inc()
    got := testutil.CollectAndCount(reg)
    if got == 0 { t.Fatal("no metrics registered") }
    if err := testutil.CollectAndCompare(reg, strings.NewReader(`
# HELP egressgate_requests_total Proxy requests by decision, rule and kind.
# TYPE egressgate_requests_total counter
egressgate_requests_total{decision="allow",kind="http",rule="gh"} 1
`), "egressgate_requests_total"); err != nil {
        t.Error(err)
    }
}

func TestNewTwiceOnSameRegistryPanicsNot(t *testing.T) {
    // Two independent registries must both work: proves no global state.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -v`
Expected: build failure, `undefined: New`.

- [ ] **Step 3: Implement**

Construct each collector with `promauto.With(reg)`. Names are prefixed `egressgate_`. Duration buckets are `prometheus.DefBuckets`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/metrics/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics go.mod go.sum
git commit -m "Prometheus collectors, registry injected rather than global"
```

---

### Task 4: Policy store with atomic reload

**Files:**
- Create: `internal/policy/store.go`
- Create: `internal/policy/store_test.go`

**Interfaces:**
- Consumes: `Parse`, `Policy`, `Request`, `Decision` from Task 1.
- Produces:
  ```go
  type Store struct{ /* unexported */ }
  func NewStore(p *Policy) *Store
  func LoadStore(path string) (*Store, error)
  func (s *Store) Evaluate(r Request) Decision
  func (s *Store) Reload(path string) error   // atomic; leaves old policy in place on error
  func (s *Store) Source() string
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestReloadReplacesPolicy(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "policy.yaml")
    os.WriteFile(path, []byte("version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n"), 0o600)
    s, err := LoadStore(path)
    if err != nil { t.Fatal(err) }
    if got := s.Evaluate(Request{Kind: KindConnect, Host: "b.com", Port: 443}); got.Action != Deny {
        t.Fatalf("want deny before reload, got %+v", got)
    }
    os.WriteFile(path, []byte("version: 1\ndefault: deny\nrules:\n  - name: b\n    hosts: [\"b.com\"]\n"), 0o600)
    if err := s.Reload(path); err != nil { t.Fatal(err) }
    if got := s.Evaluate(Request{Kind: KindConnect, Host: "b.com", Port: 443}); got.Action != Allow {
        t.Fatalf("want allow after reload, got %+v", got)
    }
}

func TestReloadKeepsOldPolicyOnParseError(t *testing.T) {
    // Write a valid policy, load, then write garbage and Reload.
    // Assert Reload returns an error AND the old policy still evaluates as before.
}

func TestEvaluateDuringReloadIsRaceFree(t *testing.T) {
    // One goroutine reloading in a loop, eight evaluating; run under -race.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run Store -v`
Expected: build failure, `undefined: NewStore`.

- [ ] **Step 3: Implement**

`Store` wraps `atomic.Pointer[Policy]` plus an immutable source path string. `Reload` reads and parses into a new `*Policy` and only then calls `Store`. A parse failure returns the error without touching the pointer, which is what keeps a bad edit from opening the gate.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "Atomic policy reload that survives a bad edit"
```

---

### Task 5: Proxy, HTTP path

**Files:**
- Create: `internal/proxy/proxy.go`
- Create: `internal/proxy/proxy_test.go`

**Interfaces:**
- Consumes: `policy.Request`, `policy.Decision`, `audit.Record`, `metrics.Metrics`.
- Produces:
  ```go
  type Evaluator interface{ Evaluate(policy.Request) policy.Decision }
  type Auditor interface{ Append(audit.Record) (audit.Record, error) }

  type Config struct {
      DialTimeout           time.Duration
      ResponseHeaderTimeout time.Duration
      IdleTimeout           time.Duration
      MaxTunnelBytes        int64
  }
  func DefaultConfig() Config

  type Handler struct{ /* unexported */ }
  func New(e Evaluator, a Auditor, m *metrics.Metrics, cfg Config) *Handler
  func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestAllowedRequestReachesUpstream(t *testing.T) {
    var hits int32
    up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&hits, 1)
        w.Header().Set("X-Upstream", "yes")
        io.WriteString(w, "hello")
    }))
    defer up.Close()
    // policy allows the upstream host on its ephemeral port
    gate := httptest.NewServer(newTestHandler(t, allowHost(up.URL)))
    defer gate.Close()

    client := proxiedClient(t, gate.URL)
    resp, err := client.Get(up.URL)
    if err != nil { t.Fatal(err) }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    if string(body) != "hello" { t.Errorf("body = %q, want hello", body) }
    if atomic.LoadInt32(&hits) != 1 { t.Errorf("upstream hits = %d, want 1", hits) }
}

func TestDeniedRequestNeverReachesUpstream(t *testing.T) {
    // Same shape, but the policy denies. Assert status 403 AND hits == 0.
    // The second assertion is the one that matters: a proxy that returns 403
    // after forwarding is not a gate.
}

func TestHopByHopHeadersAreStripped(t *testing.T) {
    // Upstream asserts it never sees Proxy-Authorization or Connection,
    // and never sees a header named in the client's Connection value.
}

func TestNonAbsoluteURIIsRejected(t *testing.T) {
    // A direct (origin-form) request to the data listener returns 400.
}

func TestUpstreamFailureIsAuditedAsAllowedButFailed(t *testing.T) {
    // Allowed host that refuses connections yields 502 and an audit record
    // with decision "allow" and a non-zero status.
}
```

Helper `proxiedClient` builds an `http.Client` whose `Transport.Proxy` returns the gate URL.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -v`
Expected: build failure, `undefined: New`.

- [ ] **Step 3: Implement**

`ServeHTTP` branches on `r.Method == http.MethodConnect` (Task 6) and otherwise handles the absolute-URI form. It rejects a request whose `r.URL` is not absolute with 400, because a forward proxy that accepts origin-form requests is silently acting as an origin server.

Host and port come from `r.URL.Hostname()` and `r.URL.Port()`, defaulting the port from the scheme. It builds a `policy.Request` with `Kind: KindHTTP`, evaluates, and on denial writes 403 with a short plain-text body and records the decision.

On allow it clones the request, removes hop-by-hop headers (the RFC 7230 list plus every header named in the `Connection` value), and sends it through a package-level `http.Transport` built from `Config`. Response headers are copied minus hop-by-hop, then the status, then the body via `io.Copy`, counting bytes.

Every path, allowed or denied, appends exactly one audit record and increments exactly one `Requests` counter.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy
git commit -m "HTTP forward proxying with policy enforcement before dial"
```

---

### Task 6: Proxy, CONNECT tunnelling

**Files:**
- Modify: `internal/proxy/proxy.go`
- Create: `internal/proxy/connect.go`
- Modify: `internal/proxy/proxy_test.go`
- Create: `internal/proxy/connect_test.go`

**Interfaces:**
- Consumes: everything from Task 5.
- Produces: no new exported names; `ServeHTTP` gains the CONNECT branch.

- [ ] **Step 1: Write the failing tests**

```go
func TestConnectTunnelCarriesTLSBothWays(t *testing.T) {
    up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        io.WriteString(w, "secure hello")
    }))
    defer up.Close()
    gate := httptest.NewServer(newTestHandler(t, allowHost(up.URL)))
    defer gate.Close()

    client := &http.Client{Transport: &http.Transport{
        Proxy:           proxyTo(gate.URL),
        TLSClientConfig: up.Client().Transport.(*http.Transport).TLSClientConfig,
    }}
    resp, err := client.Get(up.URL)
    if err != nil { t.Fatal(err) }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    if string(body) != "secure hello" { t.Errorf("body = %q", body) }
}

func TestConnectDeniedReturns403AndNoTunnel(t *testing.T) {
    // Denied CONNECT: client sees an error, upstream accept count stays 0.
}

func TestConnectRefusedForRuleWithMethodConstraint(t *testing.T) {
    // The design's central rule, tested end to end through a real socket:
    // a rule with methods: ["GET"] must NOT open a tunnel to its own host.
    // Assert the audit record's reason names the rule.
}

func TestTunnelIdleTimeoutClosesConnection(t *testing.T) {
    // IdleTimeout of 100ms; open a tunnel, send nothing, expect closure.
}

func TestTunnelByteCapIsEnforced(t *testing.T) {
    // MaxTunnelBytes small; upstream sends more; connection closes and the
    // audit record shows the truncation reason.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -run Connect -v`
Expected: failures; CONNECT currently falls into the absolute-URI branch and returns 400.

- [ ] **Step 3: Implement**

For CONNECT the target is in authority form in `r.Host`. Split it with `net.SplitHostPort`, defaulting the port to 443 when absent. Evaluate with `Kind: KindConnect` and an empty method and path. On denial write 403 before hijacking, so the client gets a real HTTP response rather than a dead socket.

On allow, dial the upstream with `DialTimeout` first and only hijack after the dial succeeds, so a failed dial can still produce a 502. Then write `HTTP/1.1 200 Connection Established\r\n\r\n` directly to the hijacked connection and run two `io.Copy` goroutines joined by a `sync.WaitGroup`.

Both directions share a deadline helper that resets the read deadline on every successful read, giving a true idle timeout rather than an absolute one. A `MaxTunnelBytes` above zero wraps each side in an `io.LimitedReader` and marks the record when the cap trips.

The active-tunnel gauge is incremented after the 200 is written and decremented in a `defer`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy
git commit -m "CONNECT tunnelling; constrained rules cannot authorise a tunnel"
```

---

### Task 7: Admin server

**Files:**
- Create: `internal/adminsrv/adminsrv.go`
- Create: `internal/adminsrv/adminsrv_test.go`

**Interfaces:**
- Consumes: `policy.Store`, `metrics.Metrics`.
- Produces:
  ```go
  type Reloader interface {
      Reload(path string) error
      Source() string
  }
  func Handler(reg *prometheus.Registry, m *metrics.Metrics, r Reloader, ready func() bool) http.Handler
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestHealthzAlwaysOK(t *testing.T)
func TestReadyzReflectsReadyFunc(t *testing.T)      // 200 when true, 503 when false
func TestMetricsExposesRegistry(t *testing.T)        // body contains egressgate_
func TestReloadRequiresPOST(t *testing.T)            // GET /reload returns 405
func TestReloadReportsParseFailure(t *testing.T)     // 500 and the reload_total{result="error"} counter moves
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adminsrv/ -v`
Expected: build failure, `undefined: Handler`.

- [ ] **Step 3: Implement**

A `http.ServeMux` with four routes. `/metrics` uses `promhttp.HandlerFor(reg, promhttp.HandlerOpts{})`. `/reload` calls `r.Reload(r.Source())` and increments `Reloads` with the right label. The mux is returned rather than a running server so tests use `httptest` without binding ports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adminsrv/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adminsrv
git commit -m "Admin listener: metrics, health, readiness, reload"
```

---

### Task 8: CLI

**Files:**
- Create: `cmd/egressgate/main.go`
- Create: `cmd/egressgate/run.go`
- Create: `cmd/egressgate/run_test.go`

**Interfaces:**
- Consumes: every package above.
- Produces:
  ```go
  func run(args []string, stdout, stderr io.Writer) int
  ```
  `main` is three lines: call `run(os.Args[1:], os.Stdout, os.Stderr)` and `os.Exit` on the result. All logic is in `run` so the CLI is testable without spawning processes.

Subcommands:
- `serve --policy P --listen :8080 --admin :9090 --audit FILE [timeout flags]`
- `verify --audit FILE` — exit 0 when the chain holds, 1 when it breaks
- `check --policy P METHOD URL` — prints the decision, exit 0 on allow, 1 on deny

- [ ] **Step 1: Write the failing tests**

```go
func TestCheckAllowExitsZero(t *testing.T) {
    dir := t.TempDir()
    p := writePolicy(t, dir, "version: 1\ndefault: deny\nrules:\n  - name: gh\n    hosts: [\"api.github.com\"]\n")
    var out, errOut bytes.Buffer
    code := run([]string{"check", "--policy", p, "GET", "https://api.github.com/x"}, &out, &errOut)
    if code != 0 { t.Fatalf("exit = %d, stderr = %s", code, errOut.String()) }
    if !strings.Contains(out.String(), "allow") { t.Errorf("stdout = %q", out.String()) }
}

func TestCheckDenyExitsOne(t *testing.T)
func TestVerifyOnGoodChainExitsZero(t *testing.T)
func TestVerifyOnTamperedChainExitsOneAndNamesSeq(t *testing.T)
func TestServeStartsAndShutsDownCleanly(t *testing.T) {
    // Start serve on :0 in a goroutine with a cancellable context, poll
    // /healthz until it answers, then cancel and assert run returns 0.
}
func TestUnknownSubcommandExitsTwo(t *testing.T)
func TestMissingRequiredFlagExitsTwo(t *testing.T)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/egressgate/ -v`
Expected: build failure, `undefined: run`.

- [ ] **Step 3: Implement**

`run` switches on `args[0]`, builds a `flag.FlagSet` per subcommand with output directed at the passed `stderr`, and returns 2 for usage errors, 1 for operational failures, 0 for success.

`serve` wires the store, audit log, metrics registry, proxy handler and admin handler, starts both `http.Server`s, and waits on a context cancelled by `SIGINT`/`SIGTERM`. Shutdown calls `Shutdown` on both servers with a five second deadline and prints the audit chain head so an operator can record it. To keep the test honest, `serve` accepts an injectable context through an unexported variable that the test sets, rather than only reading real signals.

Both servers get `ReadHeaderTimeout` set, which is the `gosec` G112 finding and a genuine slowloris defence.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/egressgate/ -race -cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd
git commit -m "CLI: serve, verify, check"
```

---

### Task 9: CI and quality gates

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `.golangci.yml`
- Create: `scripts/coverage.sh`

- [ ] **Step 1: Write the coverage gate**

`scripts/coverage.sh` runs `go test -race -covermode=atomic -coverprofile=coverage.out ./...`, extracts the total with `go tool cover -func`, compares against `${COVERAGE_FLOOR:-90}` using integer arithmetic on the percentage times ten, and exits 1 with a clear message when it falls short. The floor lives in the script so CI and a local run agree, matching the convention the sibling Python repo uses.

- [ ] **Step 2: Verify the gate fails when it should**

Run: `COVERAGE_FLOOR=100 ./scripts/coverage.sh`
Expected: non-zero exit and a message naming the actual percentage.

- [ ] **Step 3: Write the workflow**

Two jobs. `go`: matrix over `ubuntu-latest`/`windows-latest` and Go `1.24`/`1.25`, running `go vet ./...`, `golangci-lint`, `scripts/coverage.sh` (bash is available on the Windows runner), and `go build ./...`. `terraform`: `fmt -check -recursive`, `init -backend=false`, `validate` in both the module and the example, and `tflint`. Add `govulncheck` to the Go job.

`.golangci.yml` enables `errcheck`, `govet`, `staticcheck`, `unused`, `gosec`, `revive`, `misspell`, `bodyclose`.

- [ ] **Step 4: Run the whole gate locally**

Run: `go vet ./... && ./scripts/coverage.sh`
Expected: PASS with the coverage percentage printed.

- [ ] **Step 5: Commit**

```bash
git add .github .golangci.yml scripts
git commit -m "CI: race tests, coverage floor, lint, govulncheck, terraform validate"
```

---

### Task 10: Terraform module and example

**Files:**
- Create: `terraform/modules/egress-gate/{main.tf,variables.tf,outputs.tf,versions.tf,iam.tf,network.tf}`
- Create: `terraform/examples/complete/{main.tf,variables.tf,outputs.tf,versions.tf}`
- Create: `terraform/README.md`

- [ ] **Step 1: Write `versions.tf` and pin**

`required_version = "~> 1.9"`, AWS provider `~> 5.60`. Pinning is the difference between a module that builds in a year and one that does not.

- [ ] **Step 2: Write the module**

`network.tf` holds the two security groups and is the security argument of the whole repo:

```hcl
resource "aws_security_group" "gate" {
  name_prefix = "${var.name}-gate-"
  vpc_id      = var.vpc_id
  description = "Egress gate: accepts proxy traffic from agents, reaches the internet"
}

resource "aws_vpc_security_group_ingress_rule" "gate_from_agents" {
  security_group_id            = aws_security_group.gate.id
  referenced_security_group_id = aws_security_group.agent.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "Proxy traffic from agent tasks only"
}

resource "aws_vpc_security_group_egress_rule" "agent_to_gate_only" {
  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = aws_security_group.gate.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "The only outbound rule an agent task has"
}
```

`main.tf` holds the ECR repository with immutable tags and scan-on-push, the CloudWatch log group with a retention variable, the ECS task definition running the container with `--policy` pointed at a file materialised from SSM, and the ECS service placed in private subnets with `assign_public_ip = false`.

`iam.tf` holds the execution role with the AWS managed execution policy plus an inline policy granting `ssm:GetParameter` on exactly `var.policy_parameter_arn` and `logs:CreateLogStream`/`logs:PutLogEvents` on exactly the created log group ARN. No wildcards on resources.

`variables.tf` gives every variable a type, a description, and a validation block where a constraint exists (port range, retention in the allowed CloudWatch set, non-empty subnet list).

`outputs.tf` exports the two security group IDs, the service name, the log group name, and the ECR repository URL. The agent security group ID is the important one, because that is what a caller attaches to its agent tasks.

- [ ] **Step 3: Write the example root**

`terraform/examples/complete` creates a small VPC with two private subnets and a NAT gateway, an SSM parameter holding a starter policy, and calls the module. It exists so `validate` runs against a real caller, not just the module in isolation.

- [ ] **Step 4: Validate**

Run, in both directories: `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate`.
Expected: `Success! The configuration is valid.` in both.

- [ ] **Step 5: Commit**

```bash
git add terraform
git commit -m "Terraform: Fargate service and the security groups that make it unavoidable"
```

---

### Task 11: Documentation

**Files:**
- Create: `README.md`
- Create: `policy.example.yaml`
- Modify: `docs/superpowers/specs/2026-09-08-agent-egress-gate-design.md` (mark decisions that changed during implementation)

- [ ] **Step 1: Write the README**

Structure matching the sibling repos: a two-line statement of what it is, a runnable quick start, a "Why" section, a table of what it enforces, the CONNECT rule stated prominently as a design decision rather than buried, the audit format, the Terraform story including the explicit "validated, not applied" note, and cross-links to `agentic-harness-jvm` and `agent-eval-mcp`.

- [ ] **Step 2: Verify every command in the README actually runs**

Run each fenced command in a scratch directory and confirm the output matches what the README claims. A README with a command that does not run is the fastest way to lose a reviewer.

- [ ] **Step 3: Commit**

```bash
git add README.md policy.example.yaml docs
git commit -m "README and example policy"
```

---

## Self-Review

**Spec coverage.** Every section of the design maps to a task: problem and framing to Task 11, policy format to Tasks 1 and 4, the CONNECT rule to Tasks 1 and 6, the audit record to Task 2, architecture and the admin/data split to Tasks 5 through 8, Terraform to Task 10, testing to every task, success criteria to Tasks 9 through 11.

**Placeholder scan.** No TBDs. Each test step names concrete assertions. Where a test body is described rather than transcribed (Task 2's mutation test, Task 5's denial test), the assertion that matters is stated explicitly so the executor cannot write a weaker test by accident.

**Type consistency.** `Evaluate(policy.Request) policy.Decision` is the same signature in Tasks 1, 4, and 5. `Append(audit.Record) (audit.Record, error)` matches between Tasks 2 and 5. `Reload(path string) error` matches between Tasks 4 and 7. `metrics.New(prometheus.Registerer)` matches between Tasks 3, 7, and 8.

**Known risk.** Task 5 and Task 6 both modify `internal/proxy/proxy_test.go`. The shared helpers (`newTestHandler`, `allowHost`, `proxiedClient`) are introduced in Task 5 and reused in Task 6; they belong in a `helpers_test.go` created during Task 5 so the two tasks do not collide on one file.
