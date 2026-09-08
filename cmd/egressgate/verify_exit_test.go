package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

func tornLogAt(t *testing.T, dir string) string {
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

	path := filepath.Join(dir, "torn.log")
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A truncated tail is the one thing the chain cannot tell apart from a
// deliberately removed tail without a separately recorded head. Exiting 0
// would let a CI gate wired to the exit status walk past a torn log without
// anyone reading the message, and would put a deliberate truncation in the
// same bucket as a crash. It gets its own exit code so a caller can decide.
func TestVerifyExitsDistinctlyOnATruncatedTail(t *testing.T) {
	path := tornLogAt(t, t.TempDir())

	code, out, _ := runCLI(t, "verify", "--audit", path)
	if code != exitTruncated {
		t.Errorf("exit = %d, want %d for a truncated tail", code, exitTruncated)
	}
	if code == exitOK {
		t.Error("a torn log must not pass a gate wired to the exit status")
	}
	if code == exitFail {
		t.Error("a torn log is not the same as a broken chain and should not share its code")
	}
	if !strings.Contains(out, "head") {
		t.Errorf("stdout = %q, want it to point at comparing the recorded head", out)
	}
}

func TestVerifyExitsZeroOnACompleteLog(t *testing.T) {
	dir := t.TempDir()
	path := goodChain(t, dir)

	code, _, _ := runCLI(t, "verify", "--audit", path)
	if code != exitOK {
		t.Errorf("exit = %d, want 0", code)
	}
}

func TestVerifyExitCodesAreDistinct(t *testing.T) {
	seen := map[int]string{
		exitOK:        "ok",
		exitFail:      "broken",
		exitUsage:     "usage",
		exitTruncated: "truncated",
	}
	if len(seen) != 4 {
		t.Errorf("exit codes collide: %v", seen)
	}
}
