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
	// Fixed-width nanoseconds, not time.RFC3339Nano's trimmed fraction: an
	// evidence log has to sort lexicographically. See audit.TimeFormat.
	if r1.TS != "2026-09-08T14:02:11.000000000Z" {
		t.Errorf("TS = %q, want the injected clock's time at fixed width", r1.TS)
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
//
// Every field is populated, and that is the point rather than thoroughness for
// its own sake. An omitempty field left at its zero value emits no key at all,
// so a pin built from a sparse record cannot see two absent fields swap
// places: it stays green while the hash of every real record carrying those
// fields changes. Half of Record is omitempty, so half the reordering this
// test claims to prevent used to be invisible to it.
//
// The host, path and reason carry &, < and > on purpose: they pin the escaped
// forms encoding/json emits for those three characters, which is the one
// detail a verifier reimplemented in another language gets wrong by default.
func TestHashIsStableForAKnownRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	r, err := l.Append(Record{
		// TS is set explicitly, not left to the clock. The constant below was
		// derived by hand from this exact pre-image, so the record it pins must
		// not shift when the *default* timestamp layout changes: that layout is
		// an output choice, while this is a statement about the hash function
		// over a fixed set of bytes. Leaving it implicit once made a formatting
		// change look like every existing log had become unverifiable.
		TS:         "2026-09-08T14:02:11Z",
		Kind:       "connect",
		Method:     "GET",
		Host:       "a&b.example.com",
		Port:       8443,
		Path:       "/repos/<owner>/x",
		Decision:   "deny",
		Rule:       "rule-1",
		Reason:     "blocked <script> & such",
		Client:     "127.0.0.1:5555",
		Status:     403,
		BytesUp:    841,
		BytesDown:  5324,
		DurationMS: 180,
	})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	// Derived independently: the pre-image was written out by hand from the
	// field order above and hashed with a SHA-256 implementation outside Go,
	// rather than copied from this package's own output, which would only
	// prove the package agrees with itself.
	const want = "10c3c8232c39eb1e337888b7516101746b4da1adf9e36a55b05aff5154e20965"
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

// The chain covers a record's fields, not the bytes of the line it sits on,
// so anything the line can hold beside the record is a place to hide things.
// DisallowUnknownFields closes that for extra keys inside the object; a second
// JSON value concatenated after it is the same hole one step over. Decoding
// one value and stopping would leave a forged record sitting in the file,
// readable by anything that walks the line as a JSON stream, and invisible to
// the verifier that is supposed to be the last word on the file's contents.
func TestVerifyRejectsASecondRecordSplicedOntoALine(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if _, err := l.Append(Record{Kind: "http", Host: host, Port: 443, Decision: "deny"}); err != nil {
			t.Fatal(err)
		}
	}

	forged, err := json.Marshal(Record{
		Seq: 4, TS: "2026-09-08T14:02:11Z", Kind: "connect",
		Host: "exfil.attacker.test", Port: 443, Decision: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	lines[2] += string(forged)
	spliced := strings.Join(lines, "\n") + "\n"

	// The premise, asserted rather than assumed: that line really does carry
	// two records to any reader that does not stop after the first.
	dec := json.NewDecoder(strings.NewReader(lines[2]))
	var first, second Record
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("test setup: first value does not decode: %v", err)
	}
	if err := dec.Decode(&second); err != nil {
		t.Fatalf("test setup: second value does not decode: %v", err)
	}
	if second.Host != "exfil.attacker.test" {
		t.Fatalf("test setup: second value is %+v", second)
	}

	res, err := Verify(strings.NewReader(spliced))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true with a forged record spliced onto an audited line")
	}
	if res.BreakAt != 3 {
		t.Errorf("BreakAt = %d, want 3 (the line the extra bytes are on)", res.BreakAt)
	}
	if !strings.Contains(res.Problem, "trailing") {
		t.Errorf("Problem = %q, want it to name the trailing bytes", res.Problem)
	}
}

// The prev link is what makes the chain a chain, and it needs a test of its
// own because the hash check normally fires first and hides its absence. This
// record's hash is computed over the real previous head, so the recomputed
// hash matches and only the prev field lies. Without the prev check the log
// verifies while claiming a history it does not have, which is exactly what an
// offline reader following prev links would be misled by.
func TestVerifyRejectsARecordWhosePrevLinkLies(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	r1, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Record{Kind: "http", Host: "b.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Prev = strings.Repeat("ab", 32) // a head no record in this log ever had
	// Hashed against the true predecessor, so the hash check cannot save us.
	h, err := chainHash(r1.Hash, rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Hash = h
	forged, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(strings.NewReader(lines[0] + "\n" + string(forged) + "\n"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true for a record whose prev names a hash no record has")
	}
	if res.BreakAt != 2 {
		t.Errorf("BreakAt = %d, want 2", res.BreakAt)
	}
	if !strings.Contains(res.Problem, "prev") {
		t.Errorf("Problem = %q, want it to name the prev link", res.Problem)
	}
}

// An unknown key changes no field the hash covers, so the chain still
// verifies over it. Rejecting the line is the only thing that stops the log's
// own format being a place to stash bytes.
func TestVerifyRejectsAnUnknownFieldSplicedIntoARecord(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLog(&buf)
	if _, err := l.Append(Record{Kind: "http", Host: "a.com", Port: 443, Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	spliced := strings.Replace(buf.String(), `{"seq":1,`, `{"seq":1,"note":"anything at all",`, 1)
	if !strings.Contains(spliced, "anything at all") {
		t.Fatal("test setup failed to splice the extra key")
	}

	res, err := Verify(strings.NewReader(spliced))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.OK {
		t.Fatal("OK = true for a record carrying a key the format does not define")
	}
	if !strings.Contains(res.Problem, "decode") {
		t.Errorf("Problem = %q, want it to report the failed decode", res.Problem)
	}
}
