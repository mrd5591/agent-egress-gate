package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

// writeLog builds an audit log on disk and returns its path plus the chain
// head and last sequence number it ended on.
func writeLog(t *testing.T, dir, name string, records int, head string, seq uint64) (string, string, uint64) {
	t.Helper()
	var buf bytes.Buffer
	l := audit.Resume(&buf, head, seq)
	for i := 0; i < records; i++ {
		if _, err := l.Append(audit.Record{
			Kind: "http", Host: "example.com", Port: 443, Decision: "allow",
		}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	newHead, newSeq := l.Head()
	return path, newHead, newSeq
}

func runVerify(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"verify"}, args...), &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

// The vacuous green: an empty log verifies, so "chain intact: 0 records" exits
// 0 and a caller wired to the exit status cannot tell "nothing was recorded"
// from "everything verified".
func TestVerifyMinRecordsRejectsAVacuousLog(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("writing the empty log: %v", err)
	}

	// Today's behaviour, unchanged when nobody asks for a floor.
	if code, out := runVerify(t, "--audit", empty); code != exitOK {
		t.Errorf("verify on an empty log = %d, want %d (the default must not change)\n%s", code, exitOK, out)
	}

	code, out := runVerify(t, "--audit", empty, "--min-records", "1")
	if code != exitFail {
		t.Errorf("verify --min-records 1 on an empty log = %d, want %d\n%s", code, exitFail, out)
	}
	if !strings.Contains(out, "--min-records") {
		t.Errorf("output does not explain the failure:\n%s", out)
	}
}

// A whitespace-only log is the same vacuity wearing a different hat: Verify
// skips blank lines, so it counts zero records and reports intact.
func TestVerifyMinRecordsRejectsAWhitespaceOnlyLog(t *testing.T) {
	dir := t.TempDir()
	blank := filepath.Join(dir, "blank.log")
	if err := os.WriteFile(blank, []byte("\n\n   \n"), 0o600); err != nil {
		t.Fatalf("writing the blank log: %v", err)
	}

	if code, out := runVerify(t, "--audit", blank, "--min-records", "1"); code != exitFail {
		t.Errorf("verify --min-records 1 on a whitespace-only log = %d, want %d\n%s", code, exitFail, out)
	}
}

// A log that meets the floor still passes, and the floor is a minimum rather
// than an equality.
func TestVerifyMinRecordsAcceptsAFullLog(t *testing.T) {
	dir := t.TempDir()
	path, _, _ := writeLog(t, dir, "full.log", 3, audit.GenesisHash, 0)

	for _, min := range []string{"1", "3"} {
		if code, out := runVerify(t, "--audit", path, "--min-records", min); code != exitOK {
			t.Errorf("verify --min-records %s on a 3-record log = %d, want %d\n%s", min, code, exitOK, out)
		}
	}
	if code, out := runVerify(t, "--audit", path, "--min-records", "4"); code != exitFail {
		t.Errorf("verify --min-records 4 on a 3-record log = %d, want %d\n%s", code, exitFail, out)
	}
}

func TestVerifyRejectsANegativeMinRecords(t *testing.T) {
	dir := t.TempDir()
	path, _, _ := writeLog(t, dir, "x.log", 1, audit.GenesisHash, 0)
	if code, _ := runVerify(t, "--audit", path, "--min-records", "-1"); code != exitUsage {
		t.Errorf("verify --min-records -1 = %d, want %d", code, exitUsage)
	}
}

// A rotated segment continues an earlier chain, so it starts at neither
// genesis nor sequence zero. Verifying it from genesis reports BROKEN on a log
// that is perfectly intact.
func TestVerifyFromReadsARotatedSegment(t *testing.T) {
	dir := t.TempDir()
	_, head, seq := writeLog(t, dir, "first.log", 3, audit.GenesisHash, 0)
	second, _, _ := writeLog(t, dir, "second.log", 2, head, seq)

	code, out := runVerify(t, "--audit", second)
	if code != exitFail {
		t.Errorf("verify on a rotated segment = %d, want %d without --from-head\n%s", code, exitFail, out)
	}
	if !strings.Contains(out, "sequence jumped") {
		t.Errorf("output does not name the sequence jump:\n%s", out)
	}

	code, out = runVerify(t, "--audit", second, "--from-head", head, "--from-seq", "3")
	if code != exitOK {
		t.Errorf("verify --from-head on a rotated segment = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "chain intact: 2 records") {
		t.Errorf("output does not report the segment intact:\n%s", out)
	}
}

// The two flags compose: a segment can be both continued and required to hold
// evidence.
func TestVerifyFromCombinesWithMinRecords(t *testing.T) {
	dir := t.TempDir()
	_, head, seq := writeLog(t, dir, "first.log", 2, audit.GenesisHash, 0)
	second, _, _ := writeLog(t, dir, "second.log", 1, head, seq)

	if code, out := runVerify(t, "--audit", second, "--from-head", head, "--from-seq", "2", "--min-records", "2"); code != exitFail {
		t.Errorf("verify of a 1-record segment with --min-records 2 = %d, want %d\n%s", code, exitFail, out)
	}
	if code, out := runVerify(t, "--audit", second, "--from-head", head, "--from-seq", "2", "--min-records", "1"); code != exitOK {
		t.Errorf("verify of a 1-record segment with --min-records 1 = %d, want %d\n%s", code, exitOK, out)
	}
}

// A sequence offset with no head verifies from genesis while counting from
// somewhere else, which is a shape no writer produces. Refusing beats
// answering a question the caller did not ask.
func TestVerifyRejectsFromSeqWithoutFromHead(t *testing.T) {
	dir := t.TempDir()
	path, _, _ := writeLog(t, dir, "x.log", 1, audit.GenesisHash, 0)
	code, out := runVerify(t, "--audit", path, "--from-seq", "3")
	if code != exitUsage {
		t.Errorf("verify --from-seq without --from-head = %d, want %d\n%s", code, exitUsage, out)
	}
}

// A segment spliced onto the wrong predecessor must still fail: --from-head is
// a way to read a segment, not a way to launder a break.
func TestVerifyFromRejectsAWrongHead(t *testing.T) {
	dir := t.TempDir()
	_, head, seq := writeLog(t, dir, "first.log", 2, audit.GenesisHash, 0)
	second, _, _ := writeLog(t, dir, "second.log", 1, head, seq)

	wrong := strings.Repeat("ab", 32)
	if code, out := runVerify(t, "--audit", second, "--from-head", wrong, "--from-seq", "2"); code != exitFail {
		t.Errorf("verify with the wrong head = %d, want %d\n%s", code, exitFail, out)
	}
}

// check must model the gate exactly. The proxy refuses a path that does not
// normalise with 400, before consulting the policy; check used to report the
// policy's answer instead and say "allow" for a request the gate rejects.
func TestCheckRefusesPathsTheGateWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	policyYAML := "version: 1\ndefault: deny\nrules:\n" +
		"  - name: allowed\n    hosts: [example.com]\n    ports: [80]\n    paths: ['/allowed/']\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	check := func(url string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"check", "--policy", policyPath, "GET", url}, &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}

	// The control: a path that does normalise and the policy allows.
	if code, out := check("http://example.com/allowed/x"); code != exitOK {
		t.Fatalf("check on an allowed path = %d, want %d\n%s", code, exitOK, out)
	}

	for _, raw := range []string{
		"http://example.com/allowed/../secret",
		"http://example.com/allowed/%2e%2e/secret",
		"http://example.com/allowed%2fx",
	} {
		code, out := check(raw)
		if code == exitOK {
			t.Errorf("check %s = allow, but the gate answers 400 for it\n%s", raw, out)
		}
		if !strings.Contains(out, "refused") {
			t.Errorf("check %s does not say the request is refused:\n%s", raw, out)
		}
	}
}

// An https URL is modelled as a CONNECT tunnel, which carries no path at all,
// so the normalisation check must not fire there and turn an ordinary answer
// into a refusal.
func TestCheckStillAnswersForTunnels(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	policyYAML := "version: 1\ndefault: deny\nrules:\n" +
		"  - name: allowed\n    hosts: [example.com]\n    ports: [443]\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"check", "--policy", policyPath, "GET", "https://example.com/a/../b"}, &stdout, &stderr)
	out := stdout.String() + stderr.String()
	if code != exitOK {
		t.Errorf("check on an allowed tunnel = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "CONNECT tunnel") {
		t.Errorf("check did not model the https URL as a tunnel:\n%s", out)
	}
}
