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

// brokenLogAt alters a record in the middle of an otherwise good chain: the
// classic tamper, where every record after the altered one stops matching.
//
// Deliberately not the final record, and deliberately still newline
// terminated, so that this stays a plain broken chain under any refinement of
// how an unterminated final line is classified.
func brokenLogAt(t *testing.T, dir string) string {
	t.Helper()

	path := goodChain(t, dir)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(body), `"host":"b.com"`, `"host":"evil.com"`, 1)
	if altered == string(body) {
		t.Fatal("test setup failed to alter the log")
	}
	if err := os.WriteFile(path, []byte(altered), 0o600); err != nil {
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
	// The two checks that used to follow, for exitOK and exitFail, could not
	// fire: neither is exitTruncated, so the line above had already failed.

	// The note, not the word "head": "head:" prints on every intact chain, so
	// matching it says nothing about the operator being told what to do with
	// a torn one. This message is the whole remedy for the one alteration the
	// chain cannot detect by itself.
	for _, want := range []string{"the log ends mid-record", "compare the head above"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
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

// Each documented exit code, produced by the condition that documents it.
//
// This replaces a test that built a map of the four constants and asserted
// its length was four. That assertion could never fire: a map literal of four
// distinct constant keys always has four entries, and making two of the
// constants equal is a duplicate key, so the package would stop compiling
// before any test ran. It tested the compiler.
//
// What is worth pinning is not that the numbers differ but that each
// condition still reaches its own number, since a caller wires a gate to the
// exit status and cannot see the message. The collision check below is
// therefore over the codes actually observed, so folding two outcomes onto
// one code fails here at runtime rather than passing quietly.
func TestVerifyExitCodeMatchesTheDocumentedCondition(t *testing.T) {
	cases := []struct {
		name string
		path string
		want int
	}{
		{"an intact, complete chain", goodChain(t, t.TempDir()), exitOK},
		{"a chain broken by an altered record", brokenLogAt(t, t.TempDir()), exitFail},
		{"a chain that stops mid-record", tornLogAt(t, t.TempDir()), exitTruncated},
	}

	seen := make(map[int]string, len(cases))
	for _, tc := range cases {
		code, out, errOut := runCLI(t, "verify", "--audit", tc.path)
		if code != tc.want {
			t.Errorf("%s: exit = %d, want %d\nstdout: %s\nstderr: %s",
				tc.name, code, tc.want, out, errOut)
		}
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s both exit %d; a gate wired to the exit status "+
				"cannot tell them apart", other, tc.name, code)
		}
		seen[code] = tc.name
	}
}
