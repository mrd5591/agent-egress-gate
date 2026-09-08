package main

import (
	"bytes"
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

// serveExpectingRefusal runs serve with a stop signal that has already fired,
// so a gate that wrongly accepts the log shuts down at once and the assertion
// below reports a wrong exit code. Calling run directly would leave that
// regression blocked in the select waiting for a signal, and a hung suite says
// far less than a failed one.
func serveExpectingRefusal(t *testing.T, args ...string) (int, string) {
	t.Helper()
	stop := make(chan struct{})
	close(stop)
	var out, errOut bytes.Buffer
	code := runWithStop(args, &out, &errOut, stop)
	return code, errOut.String()
}

// completeLogMissingItsNewline writes a valid chain whose last byte, and only
// last byte, is absent. Every record in it verifies.
func completeLogMissingItsNewline(t *testing.T, path string) string {
	t.Helper()

	var buf strings.Builder
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	body := strings.TrimSuffix(buf.String(), "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return body
}

// The attack this whole distinction exists to survive. Altering a record and
// deleting the final newline used to be read as a torn write: the gate started,
// discarded the altered record as debris, and left a log that verifies clean.
// Tamper evidence that erases the evidence is worse than none, because the
// clean verify is then a positive statement that nothing happened.
func TestServeRefusesATamperedLogWhoseFinalNewlineWasRemoved(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	var buf strings.Builder
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com", "c.blocked.test"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "deny"}); err != nil {
			t.Fatal(err)
		}
	}
	tampered := strings.Replace(buf.String(), `"host":"c.blocked.test"`, `"host":"c.allowed.test"`, 1)
	if !strings.Contains(tampered, "c.allowed.test") {
		t.Fatal("test setup failed to rewrite the final record")
	}
	tampered = strings.TrimSuffix(tampered, "\n")
	if err := os.WriteFile(auditPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	code, errOut := serveExpectingRefusal(t, "serve", "--policy", policyPath,
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0", "--audit", auditPath)
	if code != exitFail {
		t.Errorf("exit = %d, want %d; the gate started on an altered log\nstderr = %s",
			code, exitFail, errOut)
	}
	if !strings.Contains(errOut, "already broken") {
		t.Errorf("stderr = %q, want it to name the broken chain", errOut)
	}

	// The other half of the failure, and the half that made it deadly: the
	// gate must not have touched the file. A log it rewrote is no longer
	// evidence of anything.
	after, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != tampered {
		t.Errorf("the audit log was modified on a refused start\n got %d bytes\nwant %d bytes",
			len(after), len(tampered))
	}
}

// A record that verifies but lost its newline is not debris. Truncating back
// to the previous newline would delete a complete, verified record, which is
// the gate destroying its own evidence to tidy up. The missing byte is added
// instead and the chain continues.
func TestRestartAppendsTheMissingNewlineRatherThanDroppingTheRecord(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "policy.yaml", testPolicy)
	auditPath := filepath.Join(dir, "audit.log")

	before := completeLogMissingItsNewline(t, auditPath)

	_, stderr, adminAddr, stop := startServe(t,
		"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
		"--admin", "127.0.0.1:0", "--audit", auditPath)

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

	if strings.Contains(stderr.String(), "Discarded") {
		t.Errorf("the gate discarded a record that verifies:\n%s", stderr.String())
	}

	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), before) {
		t.Errorf("the existing records were rewritten rather than extended:\n%s", body)
	}
	if !strings.Contains(string(body), "c.com") {
		t.Errorf("the third record was destroyed:\n%s", body)
	}

	res, err := audit.Verify(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("log does not verify after resuming: %q at record %d\n%s", res.Problem, res.BreakAt, body)
	}
	if res.Records < 4 {
		t.Errorf("Records = %d, want the 3 existing records plus at least one new one", res.Records)
	}
}

// Exit codes carry the verdict for anything wired to them, so the tampered
// case must not keep borrowing the torn-write code.
func TestVerifyExitsOneOnATamperedUnterminatedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var buf strings.Builder
	l := audit.New(&buf)
	for _, host := range []string{"a.com", "b.com"} {
		if _, err := l.Append(audit.Record{Kind: "http", Host: host, Port: 443, Decision: "deny"}); err != nil {
			t.Fatal(err)
		}
	}
	tampered := strings.TrimSuffix(strings.Replace(buf.String(), `"host":"b.com"`, `"host":"evil.com"`, 1), "\n")
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, _ := runCLI(t, "verify", "--audit", path)
	if code != exitFail {
		t.Errorf("exit = %d, want %d for an altered record", code, exitFail)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Errorf("stdout = %q, want it to report the break", out)
	}
}

// The file still does not end at a record boundary, so it still does not get
// the clean exit code: 0 is reserved for a log that is intact and complete.
func TestVerifyExitsThreeOnAFinalRecordMissingItsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	completeLogMissingItsNewline(t, path)

	code, out, _ := runCLI(t, "verify", "--audit", path)
	if code != exitTruncated {
		t.Errorf("exit = %d, want %d", code, exitTruncated)
	}
	if !strings.Contains(out, "chain intact: 3 records") {
		t.Errorf("stdout = %q, want all 3 records counted", out)
	}
	if !strings.Contains(out, "newline") {
		t.Errorf("stdout = %q, want it to name the missing newline as the difference", out)
	}
}
