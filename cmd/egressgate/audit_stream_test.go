package main

import (
	"net/http"
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

// With no --audit flag the audit log goes to stdout, which is how the
// container ships and how the ECS awslogs driver collects it. That stream has
// to be nothing but audit records, or the verifier this project is built
// around cannot read its own output.
func TestStdoutAuditStreamVerifiesCleanly(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)

	stdout, _, adminAddr, stop := startServe(t,
		"serve", "--policy", policyPath, "--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")

	resp, err := http.Get("http://" + adminAddr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()

	if code := stop(); code != 0 {
		t.Fatalf("exit = %d", code)
	}

	res, err := audit.Verify(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("the audit stream this deployment produces does not verify: %q at record %d\n"+
			"stdout was:\n%s", res.Problem, res.BreakAt, stdout.String())
	}
}

// An ordinary restart must continue the chain. Beginning a second chain in
// the same file makes every deploy look identical to tampering.
func TestRestartContinuesTheChain(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	for run := 0; run < 2; run++ {
		_, _, adminAddr, stop := startServe(t,
			"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
			"--admin", "127.0.0.1:0", "--audit", auditPath)

		resp, err := http.Get("http://" + adminAddr + "/healthz")
		if err != nil {
			t.Fatalf("run %d healthz: %v", run, err)
		}
		resp.Body.Close()

		if code := stop(); code != 0 {
			t.Fatalf("run %d exit = %d", run, code)
		}
	}

	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("chain broke across a restart: %q at record %d\nlog was:\n%s",
			res.Problem, res.BreakAt, body)
	}
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
		if !strings.Contains(r.stderr, "chain") {
			t.Errorf("stderr = %q, want it to explain the broken chain", r.stderr)
		}
	case <-time.After(15 * time.Second):
		close(stopCh)
		<-done
		t.Fatal("serve started against a broken audit chain instead of refusing")
	}
}
