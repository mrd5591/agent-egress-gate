package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

// writeTornLog produces a log whose final record was cut off mid-write, the
// shape a process killed by SIGKILL or an OOM leaves behind.
func writeTornLog(t *testing.T, path string) {
	t.Helper()

	var buf strings.Builder
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.SplitAfter(buf.String(), "\n")
	torn := lines[0] + lines[1] + lines[2][:len(lines[2])/2]
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A gate that resumed but left the partial bytes in place would append its
// next record onto the end of the torn line, producing a file that can never
// verify. The partial record has to go.
func TestRestartAfterATornWriteProducesAVerifiableLog(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	writeTornLog(t, auditPath)

	_, stderr, adminAddr, stop := startServe(t,
		"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
		"--admin", "127.0.0.1:0", "--audit", auditPath)

	// Generate one record so the resumed chain is actually extended.
	resp, err := http.Get("http://" + adminAddr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()

	proxyAddr := fieldFrom(t, stderr.String(), "proxy=")
	conn, err := http.Get("http://" + proxyAddr + "/") // origin-form: denied, but audited
	if err == nil {
		conn.Body.Close()
	}

	if code := stop(); code != 0 {
		t.Fatalf("exit = %d; stderr = %s", code, stderr.String())
	}

	if !strings.Contains(stderr.String(), "ended mid-record") {
		t.Errorf("startup did not report the torn tail:\n%s", stderr.String())
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
		t.Errorf("log does not verify after resuming from a torn write: %q at record %d\n%s",
			res.Problem, res.BreakAt, body)
	}
	if res.Records < 3 {
		t.Errorf("Records = %d, want the 2 surviving records plus at least one new one", res.Records)
	}
}

// A genuinely altered record is different, and must still stop the gate.
func TestServeStillRefusesATamperedLog(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	var buf strings.Builder
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	altered := strings.Replace(buf.String(), `"host":"a.com"`, `"host":"evil.com"`, 1)
	if err := os.WriteFile(auditPath, []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := runCLI(t, "serve", "--policy", policyPath,
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0", "--audit", auditPath)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "already broken") {
		t.Errorf("stderr = %q, want it to name the broken chain", errOut)
	}
	// The operator needs somewhere to go, or the next move is deleting the log.
	if !strings.Contains(errOut, "new file") {
		t.Errorf("stderr = %q, want it to offer a way forward", errOut)
	}
}
