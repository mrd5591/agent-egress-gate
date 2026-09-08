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

// The dangerous case, and the reason an unterminated line is judged rather
// than assumed: deleting the final newline is a one-byte edit any editor makes
// for free, and it must not launder an altered record into "the machine was
// killed mid-write". If it did, the caller would discard the altered record as
// debris and the log would end up indistinguishable from a clean one, which is
// worse than no chain at all: tamper evidence that erases the evidence.
func TestVerifyRejectsATamperedFinalRecordWithNoTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "deny"}); err != nil {
			t.Fatal(err)
		}
	}

	altered := strings.Replace(buf.String(), `"host":"c.com"`, `"host":"ok.com"`, 1)
	if !strings.Contains(altered, "ok.com") {
		t.Fatal("test setup failed to rewrite the final record")
	}
	// The whole attack: the same edit, minus the terminator.
	altered = strings.TrimSuffix(altered, "\n")

	res, err := Verify(strings.NewReader(altered))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true on an altered final record that lost its newline")
	}
	if res.TruncatedTail {
		t.Error("TruncatedTail = true; the record decoded in full, so this is tampering, not a torn write")
	}
	if res.BreakAt != 3 {
		t.Errorf("BreakAt = %d, want 3", res.BreakAt)
	}
	if !strings.Contains(res.Problem, "hash") {
		t.Errorf("Problem = %q, want it to name the hash mismatch", res.Problem)
	}
}

// A record that decodes and verifies but lost only its newline is complete
// evidence, not debris. It is counted, and the caller is told to append the
// missing byte rather than to throw the record away.
func TestVerifyCountsACompleteFinalRecordMissingItsNewline(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	var last Record
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		r, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"})
		if err != nil {
			t.Fatal(err)
		}
		last = r
	}

	res, err := Verify(strings.NewReader(strings.TrimSuffix(buf.String(), "\n")))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Fatalf("OK = false (%q at %d); the record verifies", res.Problem, res.BreakAt)
	}
	if res.Records != 3 {
		t.Errorf("Records = %d, want 3; the final record is complete and must be counted", res.Records)
	}
	if res.LastSeq != 3 {
		t.Errorf("LastSeq = %d, want 3", res.LastSeq)
	}
	if res.Head != last.Hash {
		t.Errorf("Head = %q, want the final record's hash %q", res.Head, last.Hash)
	}
	if !res.UnterminatedFinalRecord {
		t.Error("UnterminatedFinalRecord = false, want true")
	}
	if res.TruncatedTail {
		t.Error("TruncatedTail = true; nothing was torn, so the caller must not discard anything")
	}
}

// The degenerate shape of the same case: the whole file is one record and one
// missing byte. Truncating back to the last newline would empty the file.
func TestVerifyOnASingleCompleteRecordWithNoNewline(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	// A host and reason carrying the three characters encoding/json escapes,
	// because the unterminated path re-hashes the line like any other and the
	// escaping is the thing an independent reimplementation gets wrong.
	if _, err := l.Append(Record{
		Kind:     "http",
		Host:     "a&b.example.com",
		Port:     443,
		Decision: "deny",
		Reason:   "blocked <script> & such",
	}); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(strings.NewReader(strings.TrimSuffix(buf.String(), "\n")))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK || res.Records != 1 || !res.UnterminatedFinalRecord || res.TruncatedTail {
		t.Errorf("Verify() = %+v, want one counted record flagged as unterminated", res)
	}
}

// CRLF is not a torn write. This repo is developed on Windows, and a log that
// travelled through a tool that rewrote its line endings must still verify
// rather than read as evidence of an edit.
func TestVerifyAcceptsCRLFLineEndings(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	crlf := strings.ReplaceAll(buf.String(), "\n", "\r\n")
	res, err := Verify(strings.NewReader(crlf))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK || res.Records != 2 || res.TruncatedTail || res.UnterminatedFinalRecord {
		t.Errorf("Verify() = %+v, want 2 clean records", res)
	}

	// The same file with its last newline gone still ends in a carriage
	// return, so the final line is a complete record plus a stray CR. It is
	// counted like any other, or a byte that means nothing to the chain would
	// decide whether a record survives.
	res, err = Verify(strings.NewReader(strings.TrimSuffix(crlf, "\n")))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK || res.Records != 2 || !res.UnterminatedFinalRecord || res.TruncatedTail {
		t.Errorf("Verify() = %+v, want 2 records with the last flagged unterminated", res)
	}
}
