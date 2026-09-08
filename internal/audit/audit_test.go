package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	ts := time.Date(2026, 9, 8, 14, 2, 11, 0, time.UTC)
	return func() time.Time { return ts }
}

func newTestLog(w *bytes.Buffer) *Log {
	l := New(w)
	l.now = fixedClock()
	return l
}

func TestAppendChainsHashes(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)

	r1, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if r1.Seq != 1 {
		t.Errorf("Seq = %d, want 1", r1.Seq)
	}
	if r1.Prev != GenesisHash {
		t.Errorf("Prev = %q, want genesis", r1.Prev)
	}
	if r1.Hash == "" {
		t.Error("Hash is empty")
	}
	if r1.TS != "2026-09-08T14:02:11Z" {
		t.Errorf("TS = %q, want the injected clock's time", r1.TS)
	}

	r2, err := l.Append(Record{Kind: "connect", Host: "b.com", Port: 443, Decision: "deny"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if r2.Seq != 2 {
		t.Errorf("Seq = %d, want 2", r2.Seq)
	}
	if r2.Prev != r1.Hash {
		t.Errorf("Prev = %q, want previous hash %q", r2.Prev, r1.Hash)
	}

	res, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("Verify() OK = false, problem = %q at seq %d", res.Problem, res.BreakAt)
	}
	if res.Records != 2 {
		t.Errorf("Records = %d, want 2", res.Records)
	}
	if res.Head != r2.Hash {
		t.Errorf("Head = %q, want %q", res.Head, r2.Hash)
	}
}

// The chain is only useful if the hash is reproducible from the record alone.
// Pinning one value catches a field reordering or a marshalling change that
// would otherwise silently invalidate every previously written log.
func TestHashIsStableForAKnownRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	r, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow", Rule: "r"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	// Cross-checked against an independent SHA-256 implementation rather than
	// copied from this package's own output.
	const want = "5beffb94d4a5036f45f5299a4f9e6fdf6de718ff69fbe8e27460776cdf62c19e"
	if r.Hash != want {
		t.Errorf("Hash = %q, want %q\n"+
			"If this changed deliberately, every existing audit log is now unverifiable; "+
			"say so in the commit message.", r.Hash, want)
	}
}

// encoding/json escapes <, > and & even inside strings. That is invisible
// here because the same package writes and verifies, but it is exactly what
// an independent verifier in another language would get wrong, so the
// behaviour is pinned rather than left to be rediscovered.
func TestChainSurvivesHTMLSignificantCharacters(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)

	if _, err := l.Append(Record{
		Kind:     "http",
		Host:     "a&b.example.com",
		Port:     443,
		Decision: "deny",
		Reason:   "blocked <script> & such",
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	if !strings.Contains(buf.String(), `\u0026`) {
		t.Errorf("expected encoding/json to escape the ampersand; line was:\n%s", buf.String())
	}

	res, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("chain broke on escaped characters: %q at %d", res.Problem, res.BreakAt)
	}
}

func TestOneRecordPerLine(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 80, Decision: "allow"}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d lines, want 3", len(lines))
	}
	for i, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestVerifyDetectsMutatedMiddleRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], `"host":"b.com"`, `"host":"evil.com"`, 1)
	if !strings.Contains(lines[1], "evil.com") {
		t.Fatal("test setup failed to rewrite the record")
	}
	tampered := strings.Join(lines, "\n") + "\n"

	res, err := Verify(strings.NewReader(tampered))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("Verify() OK = true on a tampered chain")
	}
	if res.BreakAt != 2 {
		t.Errorf("BreakAt = %d, want 2", res.BreakAt)
	}
	if !strings.Contains(res.Problem, "hash") {
		t.Errorf("Problem = %q, want it to mention the hash", res.Problem)
	}
}

func TestVerifyDetectsARemovedRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "allow"}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	shortened := lines[0] + "\n" + lines[2] + "\n"

	res, err := Verify(strings.NewReader(shortened))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("Verify() OK = true after a record was removed")
	}
	if res.BreakAt != 3 {
		t.Errorf("BreakAt = %d, want 3 (the record whose seq skipped)", res.BreakAt)
	}
	if !strings.Contains(res.Problem, "sequence") {
		t.Errorf("Problem = %q, want it to mention the sequence", res.Problem)
	}
}

func TestVerifyRejectsMalformedLine(t *testing.T) {
	res, err := Verify(strings.NewReader("{not json}\n"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("Verify() OK = true on malformed input")
	}
	if !strings.Contains(res.Problem, "decode") {
		t.Errorf("Problem = %q, want it to mention decoding", res.Problem)
	}
}

func TestVerifyIgnoresBlankLines(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	res, err := Verify(strings.NewReader("\n" + buf.String() + "\n\n"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK || res.Records != 1 {
		t.Errorf("Verify() = %+v, want OK with 1 record", res)
	}
}

func TestVerifyOnEmptyInput(t *testing.T) {
	res, err := Verify(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Error("an empty log should verify")
	}
	if res.Records != 0 {
		t.Errorf("Records = %d, want 0", res.Records)
	}
	if res.Head != GenesisHash {
		t.Errorf("Head = %q, want genesis", res.Head)
	}
}

func TestResumeContinuesAnExistingChain(t *testing.T) {
	var first bytes.Buffer
	l := newTestLog(&first)
	r1, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	head, seq := l.Head()

	var second bytes.Buffer
	l2 := Resume(&second, head, seq)
	l2.now = fixedClock()
	r2, err := l2.Append(Record{Kind: "http", Host: "b.com", Port: 443, Decision: "allow"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if r2.Seq != 2 {
		t.Errorf("Seq = %d, want 2", r2.Seq)
	}
	if r2.Prev != r1.Hash {
		t.Errorf("Prev = %q, want %q", r2.Prev, r1.Hash)
	}

	res, err := Verify(strings.NewReader(first.String() + second.String()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("joined chain does not verify: %q at %d", res.Problem, res.BreakAt)
	}
}

func TestHeadOnAFreshLog(t *testing.T) {
	l := New(&bytes.Buffer{})
	head, seq := l.Head()
	if head != GenesisHash {
		t.Errorf("Head = %q, want genesis", head)
	}
	if seq != 0 {
		t.Errorf("seq = %d, want 0", seq)
	}
}

var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

var errReadFailed = errors.New("read failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errReadFailed }

func TestVerifyReturnsReaderErrors(t *testing.T) {
	if _, err := Verify(failingReader{}); err == nil {
		t.Fatal("Verify() error = nil, want the reader's error")
	}
}

func TestResumeWithEmptyHeadStartsFromGenesis(t *testing.T) {
	l := Resume(&bytes.Buffer{}, "", 0)
	if head, _ := l.Head(); head != GenesisHash {
		t.Errorf("Head = %q, want genesis", head)
	}
}

func TestAppendReturnsWriteErrors(t *testing.T) {
	l := New(failingWriter{})
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err == nil {
		t.Fatal("Append() error = nil, want the writer's error")
	}
}

// A write failure must not advance the chain, or the next record would carry a
// Prev nothing can be checked against.
func TestAppendDoesNotAdvanceChainOnWriteError(t *testing.T) {
	l := New(failingWriter{})
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err == nil {
		t.Fatal("Append() error = nil, want an error")
	}
	head, seq := l.Head()
	if head != GenesisHash || seq != 0 {
		t.Errorf("Head() = %q, %d after a failed write; want genesis, 0", head, seq)
	}
}

func TestAppendIsSafeForConcurrentUse(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	l := New(&lockedWriter{mu: &mu, w: &buf})

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
				t.Errorf("Append() error = %v", err)
			}
		}()
	}
	wg.Wait()

	res, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !res.OK {
		t.Errorf("chain broken after concurrent appends: %q at %d", res.Problem, res.BreakAt)
	}
	if res.Records != n {
		t.Errorf("Records = %d, want %d", res.Records, n)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
