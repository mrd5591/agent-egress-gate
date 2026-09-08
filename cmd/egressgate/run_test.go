package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

const testPolicy = `
version: 1
default: deny
rules:
  - name: gh
    hosts: ["api.github.com"]
    methods: ["GET"]
    paths: ["/repos/"]
  - name: registries
    hosts: ["pypi.org", "*.pypi.org"]
`

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// runCLI executes the command and returns its exit code and streams.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	code, _, errOut := runCLI(t)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	for _, want := range []string{"serve", "verify", "check"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("usage does not mention %q:\n%s", want, errOut)
		}
	}
}

func TestUnknownSubcommandExitsTwo(t *testing.T) {
	code, _, errOut := runCLI(t, "frobnicate")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "frobnicate") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", errOut)
	}
}

func TestCheckAllowsAPermittedRequest(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, out, errOut := runCLI(t, "check", "--policy", p, "GET", "http://api.github.com/repos/x")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "allow") {
		t.Errorf("stdout = %q, want it to say allow", out)
	}
	if !strings.Contains(out, "gh") {
		t.Errorf("stdout = %q, want it to name the matching rule", out)
	}
}

func TestCheckDeniesAndExitsOne(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, out, _ := runCLI(t, "check", "--policy", p, "GET", "http://evil.example.com/")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "deny") {
		t.Errorf("stdout = %q, want it to say deny", out)
	}
}

// check must model a tunnel the same way the proxy does, or it would tell an
// operator their HTTPS rule works when the gate will refuse it.
func TestCheckModelsConnectForHTTPSURLs(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)

	code, out, _ := runCLI(t, "check", "--policy", p, "GET", "https://api.github.com/repos/x")
	if code != 1 {
		t.Errorf("exit = %d, want 1; a method-constrained rule cannot authorise a tunnel", code)
	}
	if !strings.Contains(out, "tunnel") {
		t.Errorf("stdout = %q, want it to explain the tunnel restriction", out)
	}

	code2, out2, _ := runCLI(t, "check", "--policy", p, "GET", "https://pypi.org/simple/")
	if code2 != 0 {
		t.Errorf("exit = %d, want 0 for a host-only rule; stdout = %s", code2, out2)
	}
}

func TestCheckRequiresAPolicy(t *testing.T) {
	code, _, errOut := runCLI(t, "check", "GET", "http://example.com/")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "policy") {
		t.Errorf("stderr = %q, want it to mention the missing flag", errOut)
	}
}

func TestCheckRejectsAMissingPolicyFile(t *testing.T) {
	code, _, _ := runCLI(t, "check", "--policy", filepath.Join(t.TempDir(), "nope.yaml"), "GET", "http://x.com/")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestCheckRejectsAMalformedURL(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, _, errOut := runCLI(t, "check", "--policy", p, "GET", "not-a-url")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "URL") && !strings.Contains(errOut, "url") {
		t.Errorf("stderr = %q, want it to name the bad URL", errOut)
	}
}

func TestCheckRequiresMethodAndURL(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, _, _ := runCLI(t, "check", "--policy", p, "GET")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func goodChain(t *testing.T, dir string) string {
	t.Helper()
	var buf bytes.Buffer
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	return writeFile(t, dir, "audit.log", buf.String())
}

func TestVerifyOnAGoodChainExitsZero(t *testing.T) {
	path := goodChain(t, t.TempDir())
	code, out, errOut := runCLI(t, "verify", "--audit", path)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "3") {
		t.Errorf("stdout = %q, want the record count", out)
	}
	if !strings.Contains(strings.ToLower(out), "intact") && !strings.Contains(strings.ToLower(out), "ok") {
		t.Errorf("stdout = %q, want a clear verdict", out)
	}
}

func TestVerifyOnATamperedChainExitsOneAndNamesTheSequence(t *testing.T) {
	dir := t.TempDir()
	path := goodChain(t, dir)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(body), `"host":"b.com"`, `"host":"evil.com"`, 1)
	if tampered == string(body) {
		t.Fatal("test setup failed to alter the log")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, _ := runCLI(t, "verify", "--audit", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "2") {
		t.Errorf("stdout = %q, want the breaking sequence number", out)
	}
}

func TestVerifyRequiresAnAuditPath(t *testing.T) {
	code, _, errOut := runCLI(t, "verify")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "audit") {
		t.Errorf("stderr = %q, want it to mention the missing flag", errOut)
	}
}

func TestVerifyOnAMissingFileExitsOne(t *testing.T) {
	code, _, _ := runCLI(t, "verify", "--audit", filepath.Join(t.TempDir(), "absent.log"))
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestServeStartsProxiesAndShutsDownCleanly(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	stop := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
	})

	type result struct {
		code   int
		stdout string
		stderr string
	}
	done := make(chan result, 1)
	out := &syncBuffer{}
	errOut := &syncBuffer{}

	go func() {
		code := runWithStop(
			[]string{"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
				"--admin", "127.0.0.1:0", "--audit", auditPath},
			out, errOut, stop)
		done <- result{code, out.String(), errOut.String()}
	}()

	// The startup line is a diagnostic, so it belongs on stderr: stdout is
	// reserved for audit records.
	adminAddr := waitForAdminAddrIn(t, errOut)

	resp, err := http.Get("http://" + adminAddr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}

	readyResp, err := http.Get("http://" + adminAddr + "/readyz")
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	io.Copy(io.Discard, readyResp.Body)
	readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusOK {
		t.Errorf("readyz status = %d, want 200", readyResp.StatusCode)
	}

	close(stop)

	select {
	case r := <-done:
		if r.code != 0 {
			t.Errorf("exit = %d, want 0; stderr = %s", r.code, r.stderr)
		}
		if !strings.Contains(r.stderr, "chain head") {
			t.Errorf("shutdown did not report the audit chain head on stderr:\n%s", r.stderr)
		}
		if strings.TrimSpace(r.stdout) != "" {
			t.Errorf("stdout carried diagnostics; it is the default audit sink and must carry "+
				"audit records only:\n%s", r.stdout)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestServeRejectsAnInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	bad := writeFile(t, dir, "policy.yaml", "version: 99\ndefault: deny\nrules: []\n")
	code, _, errOut := runCLI(t, "serve", "--policy", bad, "--listen", "127.0.0.1:0",
		"--admin", "127.0.0.1:0", "--audit", filepath.Join(dir, "a.log"))
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "version") {
		t.Errorf("stderr = %q, want the validation error", errOut)
	}
}

func TestServeRequiresAPolicy(t *testing.T) {
	code, _, errOut := runCLI(t, "serve")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "policy") {
		t.Errorf("stderr = %q, want it to mention the missing flag", errOut)
	}
}

func TestServeRejectsAnUnwritableAuditPath(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "policy.yaml", testPolicy)
	// A directory is never a valid audit file.
	code, _, _ := runCLI(t, "serve", "--policy", p, "--listen", "127.0.0.1:0",
		"--admin", "127.0.0.1:0", "--audit", dir)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestHelpFlagExitsZero(t *testing.T) {
	code, _, _ := runCLI(t, "--help")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

// The tests below cover URL and startup shapes the earlier ones did not
// reach. They are regression tests for under-specified edges, not new
// behaviour.

func TestCheckHonoursAnExplicitPort(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, out, _ := runCLI(t, "check", "--policy", p, "GET", "http://api.github.com:8080/repos/x")
	if code != 1 {
		t.Errorf("exit = %d, want 1; 8080 is outside the default 80/443 pair", code)
	}
	if !strings.Contains(out, ":8080") {
		t.Errorf("stdout = %q, want it to show the port it evaluated", out)
	}
}

func TestCheckTreatsAnEmptyPathAsRoot(t *testing.T) {
	body := "version: 1\ndefault: deny\nrules:\n  - name: root\n    hosts: [\"example.com\"]\n    paths: [\"/\"]\n"
	p := writeFile(t, t.TempDir(), "policy.yaml", body)
	code, out, _ := runCLI(t, "check", "--policy", p, "GET", "http://example.com")
	if code != 0 {
		t.Errorf("exit = %d, want 0; an empty path should evaluate as /; stdout = %s", code, out)
	}
}

func TestCheckRejectsARelativeURL(t *testing.T) {
	p := writeFile(t, t.TempDir(), "policy.yaml", testPolicy)
	code, _, errOut := runCLI(t, "check", "--policy", p, "GET", "/repos/x")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "absolute") {
		t.Errorf("stderr = %q, want it to require an absolute URL", errOut)
	}
}

func TestServeFailsWhenTheDataPortIsTaken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	dir := t.TempDir()
	p := writeFile(t, dir, "policy.yaml", testPolicy)
	code, _, errOut := runCLI(t, "serve", "--policy", p,
		"--listen", busy.Addr().String(), "--admin", "127.0.0.1:0",
		"--audit", filepath.Join(dir, "a.log"))
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "listening") {
		t.Errorf("stderr = %q, want it to name the bind failure", errOut)
	}
}

func TestServeFailsWhenTheAdminPortIsTaken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	dir := t.TempDir()
	p := writeFile(t, dir, "policy.yaml", testPolicy)
	code, _, errOut := runCLI(t, "serve", "--policy", p,
		"--listen", "127.0.0.1:0", "--admin", busy.Addr().String(),
		"--audit", filepath.Join(dir, "a.log"))
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "listening") {
		t.Errorf("stderr = %q, want it to name the bind failure", errOut)
	}
}

func TestBadFlagExitsTwo(t *testing.T) {
	for _, sub := range []string{"serve", "verify", "check"} {
		t.Run(sub, func(t *testing.T) {
			code, _, _ := runCLI(t, sub, "--nonexistent-flag")
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
		})
	}
}

// syncBuffer is a writer the server goroutine and the test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// The address helper lives in audit_stream_test.go, which reads either
// stream so the tests do not themselves decide which one the banner is on.
