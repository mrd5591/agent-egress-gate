package audit

import (
	"bytes"
	"strings"
	"testing"
)

// A process killed mid-write leaves a partial final line. That is an
// interrupted write, not evidence of tampering, and the two must not be
// conflated: refusing to start on a truncated tail turns an OOM kill into a
// permanent crash loop, and the only way out would be editing the audit log,
// which is the exact action the chain exists to make suspicious.
func TestVerifyTreatsAPartialFinalLineAsTruncation(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	full := buf.String()
	// Cut the third record in half, leaving no trailing newline.
	lines := strings.SplitAfter(full, "\n")
	partial := lines[0] + lines[1] + lines[2][:len(lines[2])/2]

	res, err := Verify(strings.NewReader(partial))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false (%q at %d); a truncated final write is not a broken chain",
			res.Problem, res.BreakAt)
	}
	if !res.TruncatedTail {
		t.Error("TruncatedTail = false, want true")
	}
	if res.Records != 2 {
		t.Errorf("Records = %d, want the 2 complete records", res.Records)
	}
	if res.LastSeq != 2 {
		t.Errorf("LastSeq = %d, want 2", res.LastSeq)
	}
}

// A complete but altered record is tampering, and must still be reported as a
// break even when it is the last line in the file.
func TestVerifyStillRejectsAnAlteredFinalRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	altered := strings.Replace(buf.String(), `"host":"b.com"`, `"host":"evil.com"`, 1)
	res, err := Verify(strings.NewReader(altered))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true on an altered final record")
	}
	if res.TruncatedTail {
		t.Error("TruncatedTail = true; the line was complete, so this is tampering, not truncation")
	}
	if res.BreakAt != 2 {
		t.Errorf("BreakAt = %d, want 2", res.BreakAt)
	}
}

// A break in the middle is tampering regardless of how the file ends.
func TestVerifyRejectsAMidChainBreakEvenWithATruncatedTail(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.SplitAfter(buf.String(), "\n")
	broken := strings.Replace(lines[0], `"host":"a.com"`, `"host":"evil.com"`, 1)
	input := broken + lines[1] + lines[2][:len(lines[2])/2]

	res, err := Verify(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true despite an altered first record")
	}
	if res.BreakAt != 1 {
		t.Errorf("BreakAt = %d, want 1", res.BreakAt)
	}
}

// A log that ends cleanly is not truncated.
func TestVerifyOnACleanlyTerminatedLog(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK || res.TruncatedTail {
		t.Errorf("Verify() = %+v, want OK with no truncation", res)
	}
}
