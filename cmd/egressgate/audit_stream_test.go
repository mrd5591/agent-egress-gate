package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

// startServe runs the gate in the background and returns its streams plus a
// stop function. It waits until the admin address has been announced.
func startServe(t *testing.T, args ...string) (stdout, stderr *syncBuffer, adminAddr string, stop func() int) {
	t.Helper()

	out, errOut := &syncBuffer{}, &syncBuffer{}
	stopCh := make(chan struct{})
	done := make(chan int, 1)

	go func() { done <- runWithStop(args, out, errOut, stopCh) }()

	addr := waitForAdminAddrIn(t, out, errOut)

	var stopped atomic.Bool
	stop = func() int {
		if stopped.CompareAndSwap(false, true) {
			close(stopCh)
		}
		select {
		case code := <-done:
			return code
		case <-time.After(20 * time.Second):
			t.Fatal("serve did not shut down")
			return -1
		}
	}
	t.Cleanup(func() {
		if !stopped.Load() {
			stop()
		}
	})
	return out, errOut, addr, stop
}

// waitForAdminAddrIn looks for the startup line on either stream, so the test
// does not itself decide which one it belongs on.
func waitForAdminAddrIn(t *testing.T, streams ...*syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, s := range streams {
			for _, line := range strings.Split(s.String(), "\n") {
				if !strings.Contains(line, "admin=") {
					continue
				}
				for _, field := range strings.Fields(line) {
					if addr, ok := strings.CutPrefix(field, "admin="); ok {
						return addr
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server never announced its admin address")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// driveDeniedRequests sends n proxied requests to a host the policy does not
// allow, and returns once every one of them has been refused.
//
// Deny is the cheapest traffic there is: the gate decides before it dials, so
// no upstream has to exist and no name has to resolve, and every refusal is
// still a full audit record on the real data path. The admin endpoints, which
// these tests used to poke instead, write no record at all.
func driveDeniedRequests(t *testing.T, proxyAddr string, n int) {
	t.Helper()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("proxy address %q: %v", proxyAddr, err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}

	for i := 0; i < n; i++ {
		// .invalid never resolves, which is the point: a 403 here proves the
		// gate refused rather than failed to reach anything.
		resp, err := client.Get("http://denied.example.invalid/")
		if err != nil {
			t.Fatalf("proxied request %d: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("proxied request %d: status = %d, want 403; the gate did not deny it",
				i+1, resp.StatusCode)
		}
	}
}

// auditRecordsIn decodes a log into the records it holds, so a test can assert
// about sequence numbers and chain links rather than only about whether the
// whole file verifies.
func auditRecordsIn(t *testing.T, log string) []audit.Record {
	t.Helper()
	var recs []audit.Record
	for _, line := range strings.Split(log, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("audit line %q does not decode: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// With no --audit flag the audit log goes to stdout, which is how the
// container ships and how the ECS awslogs driver collects it. That stream has
// to be nothing but audit records, or the verifier this project is built
// around cannot read its own output.
//
// So it has to carry records in the first place. Verifying an empty stream
// succeeds trivially and would keep succeeding if audit records stopped
// reaching stdout entirely, which is the one failure this test exists to
// catch: the CI container job pipes container stdout straight into verify.
func TestStdoutAuditStreamVerifiesCleanly(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)

	stdout, stderr, adminAddr, stop := startServe(t,
		"serve", "--policy", policyPath, "--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")

	resp, err := http.Get("http://" + adminAddr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()

	const denials = 2
	driveDeniedRequests(t, fieldFrom(t, stderr.String(), "proxy="), denials)

	if code := stop(); code != 0 {
		t.Fatalf("exit = %d", code)
	}

	res, err := audit.Verify(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	// Asserted before OK, and separately, because an empty stream is OK.
	if res.Records != denials {
		t.Fatalf("stdout carried %d audit records, want %d; stdout was:\n%s",
			res.Records, denials, stdout.String())
	}
	if res.TruncatedTail {
		t.Errorf("the stdout audit stream ends mid-record:\n%s", stdout.String())
	}
	if !res.OK {
		t.Errorf("the audit stream this deployment produces does not verify: %q at record %d\n"+
			"stdout was:\n%s", res.Problem, res.BreakAt, stdout.String())
	}
}

// An ordinary restart must continue the chain. Beginning a second chain in
// the same file makes every deploy look identical to tampering.
//
// This is the regression test for the bug where audit.Resume existed and
// nothing called it, so it has to be written in a way that cannot pass over an
// empty file: both runs drive real traffic, the record count is asserted
// explicitly, and the assertion that matters is the join itself — the first
// record of the second run continues the sequence and points at the last
// record of the first. A whole-file Verify alone would be weaker, because a
// file with no records verifies.
func TestRestartContinuesTheChain(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	const perRun = 2
	var firstRun []audit.Record

	for run := 0; run < 2; run++ {
		_, stderr, _, stop := startServe(t,
			"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
			"--admin", "127.0.0.1:0", "--audit", auditPath)

		driveDeniedRequests(t, fieldFrom(t, stderr.String(), "proxy="), perRun)

		if code := stop(); code != 0 {
			t.Fatalf("run %d exit = %d; stderr = %s", run, code, stderr.String())
		}

		if run == 0 {
			firstRun = auditRecordsIn(t, readFileString(t, auditPath))
			if len(firstRun) != perRun {
				t.Fatalf("first run wrote %d records, want %d; a chain test over an "+
					"empty log proves nothing", len(firstRun), perRun)
			}
		}
	}

	body := readFileString(t, auditPath)
	all := auditRecordsIn(t, body)
	if len(all) != 2*perRun {
		t.Fatalf("log holds %d records after two runs, want %d:\n%s", len(all), 2*perRun, body)
	}

	last, resumed := firstRun[len(firstRun)-1], all[len(firstRun)]
	if resumed.Seq != last.Seq+1 {
		t.Errorf("the restart's first record has seq %d, want %d: it began a second "+
			"chain instead of continuing the first\nlog was:\n%s", resumed.Seq, last.Seq+1, body)
	}
	if resumed.Prev != last.Hash {
		t.Errorf("the restart's first record has prev %s, want the previous run's head %s\n"+
			"log was:\n%s", resumed.Prev, last.Hash, body)
	}

	res, err := audit.Verify(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.Records != 2*perRun {
		t.Errorf("Verify counted %d records, want %d", res.Records, 2*perRun)
	}
	if !res.OK {
		t.Errorf("chain broke across a restart: %q at record %d\nlog was:\n%s",
			res.Problem, res.BreakAt, body)
	}
}

// readFileString is os.ReadFile with the test's error handling folded in.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Appending to a log whose existing tail does not verify would produce a file
// that can never be verified again. Refusing to start is the correct posture.
func TestServeRefusesToAppendToABrokenChain(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	if err := os.WriteFile(auditPath, []byte("{\"seq\":1,\"host\":\"a.com\",\"hash\":\"deadbeef\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Bounded, because a serve that does not refuse would block on signals
	// and hang the whole package rather than failing this one test.
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	stopCh := make(chan struct{})
	go func() {
		out, errOut := &syncBuffer{}, &syncBuffer{}
		code := runWithStop([]string{"serve", "--policy", policyPath,
			"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0", "--audit", auditPath},
			out, errOut, stopCh)
		done <- result{code, errOut.String()}
	}()

	select {
	case r := <-done:
		if r.code != 1 {
			t.Errorf("exit = %d, want 1", r.code)
		}
		// The phrase, not the word: "chain" alone appears in the shutdown
		// banner and in several slog lines that also land on stderr, so it
		// would be satisfied by a gate that started anyway.
		if !strings.Contains(r.stderr, "refusing to append to") {
			t.Errorf("stderr = %q, want it to explain the broken chain", r.stderr)
		}
	case <-time.After(15 * time.Second):
		close(stopCh)
		<-done
		t.Fatal("serve started against a broken audit chain instead of refusing")
	}
}
