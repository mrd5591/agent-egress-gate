package audit

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"
)

// A rotated segment is a chain that does not begin at genesis. Verify assumes
// it does, so the segment is the case that used to be unverifiable: the tool
// reported BROKEN on a log that was perfectly intact.
func TestVerifyFromAcceptsARotatedSegment(t *testing.T) {
	var first bytes.Buffer
	l := newTestLog(&first)
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	head, seq := l.Head()

	// Rotation: a fresh file, and Resume continues the chain into it.
	var second bytes.Buffer
	cont := Resume(&second, head, seq)
	cont.now = fixedClock()
	for i := 0; i < 2; i++ {
		if _, err := cont.Append(Record{Kind: "connect", Host: "b.com", Port: 443, Decision: "allow"}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	// The bug: Verify starts from genesis and sequence 0, so it reads the
	// segment's first record (sequence 4) as a jump.
	res, err := Verify(bytes.NewReader(second.Bytes()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("Verify() accepted a rotated segment; it cannot know where the chain was, so it must not")
	}
	if !strings.Contains(res.Problem, "sequence jumped from 0 to 4") {
		t.Errorf("Problem = %q, want the sequence jump that motivates VerifyFrom", res.Problem)
	}

	// The fix: tell it where the chain was.
	res, err = VerifyFrom(bytes.NewReader(second.Bytes()), head, seq)
	if err != nil {
		t.Fatalf("VerifyFrom() error = %v", err)
	}
	if !res.OK {
		t.Fatalf("VerifyFrom() reported BROKEN at %d: %s", res.BreakAt, res.Problem)
	}
	if res.Records != 2 {
		t.Errorf("Records = %d, want 2", res.Records)
	}
	if res.LastSeq != 5 {
		t.Errorf("LastSeq = %d, want 5", res.LastSeq)
	}
	wantHead, _ := cont.Head()
	if res.Head != wantHead {
		t.Errorf("Head = %q, want %q", res.Head, wantHead)
	}
}

// VerifyFrom must still catch a segment spliced onto the wrong predecessor,
// or it would be a way to launder a break rather than a way to read a segment.
func TestVerifyFromRejectsTheWrongPredecessor(t *testing.T) {
	var first bytes.Buffer
	l := newTestLog(&first)
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	head, seq := l.Head()

	var second bytes.Buffer
	cont := Resume(&second, head, seq)
	cont.now = fixedClock()
	if _, err := cont.Append(Record{Kind: "http", Host: "b.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	wrong := strings.Repeat("ab", 32)
	res, err := VerifyFrom(bytes.NewReader(second.Bytes()), wrong, seq)
	if err != nil {
		t.Fatalf("VerifyFrom() error = %v", err)
	}
	if res.OK {
		t.Fatal("VerifyFrom() accepted a segment whose Prev does not match the head it was given")
	}
	if !strings.Contains(res.Problem, "prev hash") {
		t.Errorf("Problem = %q, want a prev-hash mismatch", res.Problem)
	}
}

// An empty head means genesis, so VerifyFrom degrades to Verify rather than
// treating "" as a hash nothing can match.
func TestVerifyFromTreatsEmptyHeadAsGenesis(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	res, err := VerifyFrom(bytes.NewReader(buf.Bytes()), "", 0)
	if err != nil {
		t.Fatalf("VerifyFrom() error = %v", err)
	}
	if !res.OK || res.Records != 1 {
		t.Errorf("VerifyFrom(genesis) = %+v, want an intact single-record chain", res)
	}
}

// The point of a fixed-width fraction: sorting the timestamp column as text
// has to agree with chronological order. RFC3339Nano trims trailing zeros, so
// a timestamp on a microsecond boundary is shorter than its neighbours and
// sorts before times that precede it.
func TestTimestampsSortLexicographically(t *testing.T) {
	base := time.Date(2026, 9, 8, 14, 2, 11, 0, time.UTC)
	offsets := []time.Duration{
		500 * time.Millisecond,
		0,
		1500 * time.Nanosecond,
		250 * time.Microsecond,
		999999999 * time.Nanosecond,
	}

	chronological := make([]string, 0, len(offsets))
	for _, d := range offsets {
		chronological = append(chronological, base.Add(d).Format(TimeFormat))
	}
	sort.Slice(chronological, func(i, j int) bool { return chronological[i] < chronological[j] })

	if !sort.StringsAreSorted(chronological) {
		t.Fatalf("timestamps do not sort as strings: %v", chronological)
	}
	for i := 1; i < len(chronological); i++ {
		a, err := time.Parse(time.RFC3339Nano, chronological[i-1])
		if err != nil {
			t.Fatalf("parsing %q: %v", chronological[i-1], err)
		}
		b, err := time.Parse(time.RFC3339Nano, chronological[i])
		if err != nil {
			t.Fatalf("parsing %q: %v", chronological[i], err)
		}
		if !a.Before(b) {
			t.Errorf("string order disagrees with time order: %q sorts before %q", chronological[i-1], chronological[i])
		}
	}

	// Every rendering is the same width, which is the property that makes the
	// above hold for any pair rather than just these five.
	width := len(chronological[0])
	for _, ts := range chronological {
		if len(ts) != width {
			t.Errorf("TimeFormat produced %q (%d chars), want fixed width %d", ts, len(ts), width)
		}
	}

	// And the old layout genuinely lacked the property, so this test is not
	// pinning something that was already true.
	trimmed := base.Add(250 * time.Microsecond).Format(time.RFC3339Nano)
	full := base.Add(1500 * time.Nanosecond).Format(time.RFC3339Nano)
	if trimmed <= full {
		t.Errorf("expected RFC3339Nano to mis-sort %q against %q; if it no longer does, this guard can go", trimmed, full)
	}
}
