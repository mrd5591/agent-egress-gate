// Package audit writes a hash-chained, append-only record of every proxy
// decision, and verifies such a chain offline.
//
// Each record carries the hash of the one before it, so altering a record in
// the middle of a log invalidates every record after it. That gives tamper
// evidence without a signing key or a key-management story. It does not give
// tamper resistance: an attacker who can rewrite the whole file can rebuild a
// consistent chain. Recording the head hash somewhere the attacker cannot
// reach is what closes that gap, and Head exists for exactly that purpose.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// GenesisHash is the Prev value of the first record in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one proxy decision.
//
// Field order is part of the hash input, because the chain hashes the JSON
// encoding and Go marshals struct fields in declaration order. Reordering
// these fields invalidates every previously written log;
// TestHashIsStableForAKnownRecord pins one value so that cannot happen by
// accident. Its record populates every field, including the omitempty ones,
// because a field left at its zero value emits no key and so cannot be seen
// to move.
type Record struct {
	Seq        uint64 `json:"seq"`
	TS         string `json:"ts"`
	Kind       string `json:"kind"`
	Method     string `json:"method,omitempty"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Path       string `json:"path,omitempty"`
	Decision   string `json:"decision"`
	Rule       string `json:"rule,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Client     string `json:"client,omitempty"`
	Status     int    `json:"status,omitempty"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
	DurationMS int64  `json:"duration_ms"`
	Prev       string `json:"prev"`
	Hash       string `json:"hash"`
}

// Log appends records to a writer, maintaining the chain. It is safe for
// concurrent use.
type Log struct {
	mu   sync.Mutex
	w    io.Writer
	prev string
	seq  uint64
	now  func() time.Time
}

// New starts a fresh chain whose first record follows the genesis hash.
func New(w io.Writer) *Log {
	return &Log{w: w, prev: GenesisHash, now: time.Now}
}

// Resume continues an existing chain from a known head and sequence number,
// so a restarted process does not begin a second, unconnected chain.
func Resume(w io.Writer, head string, seq uint64) *Log {
	if head == "" {
		head = GenesisHash
	}
	return &Log{w: w, prev: head, seq: seq, now: time.Now}
}

// Append fills in the sequence number, timestamp and chain fields, writes the
// record as one JSON line, and returns the completed record.
//
// A failed write leaves the chain untouched. Advancing it would mean the next
// record referenced a hash that never reached the log, which turns one lost
// write into an unverifiable remainder.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	r.Seq = l.seq + 1
	if r.TS == "" {
		// Nanosecond resolution, because two decisions in the same second are
		// otherwise indistinguishable by timestamp, which matters when the log
		// is the evidence.
		r.TS = l.now().UTC().Format(time.RFC3339Nano)
	}
	r.Prev = l.prev
	r.Hash = ""

	hash, err := chainHash(l.prev, r)
	if err != nil {
		return Record{}, err
	}
	r.Hash = hash

	line, err := json.Marshal(r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: encode record: %w", err)
	}
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("audit: write record: %w", err)
	}

	l.prev = r.Hash
	l.seq = r.Seq
	return r, nil
}

// Head returns the current chain head and the last sequence number written.
// Recording these outside the log is what makes truncation of the tail
// detectable.
func (l *Log) Head() (string, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prev, l.seq
}

// chainHash computes SHA-256 over the previous hash followed by the JSON
// encoding of the record with an empty Hash field.
//
// The hashed bytes are exactly what encoding/json produces, and it escapes
// the three HTML-significant characters: < becomes \u003c, > becomes
// \u003e, and & becomes \u0026. Writer and verifier both use this package,
// so the chain is self-consistent. Anyone reimplementing the verifier in
// another language must reproduce that escaping, or every record whose host
// or reason contains one of those characters will fail to verify; Python's
// json.dumps, for one, does not escape them by default.
//
// The marshalling error is unreachable today: Record holds only strings and
// integers, and encoding/json fails only on channels, functions, complex
// numbers, cyclic structures and invalid floats. It is handled rather than
// discarded so that adding a field of some richer type surfaces as an error
// instead of a silently truncated chain. That is also why this branch, and
// the matching one in Append, are the only statements in this package with no
// test covering them.
func chainHash(prev string, r Record) (string, error) {
	r.Hash = ""
	body, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("audit: encode record for hashing: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyResult reports whether a chain holds and, when it does not, exactly
// where it stops holding.
type VerifyResult struct {
	Records int
	// LastSeq is the sequence number of the final verified record. It is
	// stated rather than inferred from Records, because equating the two
	// assumes the chain starts at one, which a resumed log need not.
	LastSeq uint64
	Head    string
	OK      bool
	BreakAt uint64
	Problem string
	// TruncatedTail reports that the log ended mid-record: its final line
	// arrived without a terminating newline. That is an interrupted write, a
	// process killed or a disk filled, not evidence of tampering. Every
	// complete record before it still verifies and OK stays true.
	//
	// The distinction is operational, not pedantic. Treating a torn final
	// write as a broken chain turns an OOM kill into a gate that refuses to
	// start, whose only remedy would be editing the audit log, which is
	// precisely the act the chain exists to make suspicious.
	TruncatedTail bool
	// UnterminatedFinalRecord reports that the final line held a complete
	// record that decoded and verified, but carried no terminating newline.
	// The record is counted: it is evidence, not debris.
	//
	// It is a separate field from TruncatedTail rather than a second meaning
	// for it, because the two demand opposite responses. A torn tail must be
	// cut off before anything is appended; this one must have a newline added,
	// and cutting it off would destroy a record that verifies.
	UnterminatedFinalRecord bool
}

// Verify walks a log and recomputes the chain. It returns an error only if
// the underlying reader fails; a broken chain is a result, not an error,
// because "this log was altered" is an answer the caller asked for.
func Verify(r io.Reader) (VerifyResult, error) {
	res := VerifyResult{OK: true, Head: GenesisHash}

	// A bufio.Reader rather than a Scanner, because whether the final line
	// carried its newline is the difference between a torn write and a
	// tampered record, and a Scanner does not report it.
	br := bufio.NewReaderSize(r, 64*1024)

	var prev = GenesisHash
	var lastSeq uint64

	for {
		raw, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return res, fmt.Errorf("audit: read log: %w", err)
		}

		// ReadString reports no error when it found the delimiter, so EOF here
		// always means this is the last line, and a missing newline always
		// means the file stops in the middle of one. Both facts are captured
		// now because chainHash below reuses err.
		atEOF := errors.Is(err, io.EOF)
		terminated := strings.HasSuffix(raw, "\n")
		// TrimSpace also removes a carriage return, so a log whose line
		// endings were rewritten to CRLF in transit still verifies rather than
		// reading as an edited file.
		line := strings.TrimSpace(raw)

		if line == "" {
			if atEOF {
				break
			}
			continue
		}

		// A missing final newline decides nothing on its own. It is equally
		// what a process killed mid-write leaves and what any editor produces
		// for free, so the line is decoded and checked like every other, and
		// only its verdict says which it was. Assuming a torn write here is
		// what let a one-byte deletion turn tamper detection into tamper
		// erasure: the caller discarded the "partial" record as debris and the
		// altered log came out looking clean.
		unterminated := !terminated && atEOF

		// DisallowUnknownFields because the chain covers the record's fields,
		// not the bytes of the line. Without it, arbitrary keys can be spliced
		// into an audited line and the chain still verifies, which would make
		// the log's own format a place to hide things.
		var rec Record
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&rec); derr != nil {
			// The one place an unterminated line is read leniently, and only
			// because JSON that stops in the middle is precisely what a killed
			// process leaves behind. Refusing to start on that would turn one
			// OOM kill into a crash loop whose only remedy is editing the
			// audit log, which is the act the chain exists to make suspicious.
			if unterminated {
				res.TruncatedTail = true
				break
			}
			res.OK = false
			res.BreakAt = lastSeq + 1
			res.Problem = fmt.Sprintf("could not decode record: %v", derr)
			return res, nil
		}

		// Decode reads one JSON value and stops, saying nothing about what
		// follows it on the line. That is the same hole DisallowUnknownFields
		// closes, one step over: a forged record concatenated onto an audited
		// line is invisible to a verifier that stops after the first value,
		// while any reader walking the line as a JSON stream sees both. The
		// decoder must be exhausted, so anything but EOF is a break. A torn
		// write cannot produce this shape either, because each record and its
		// newline go out in one Write.
		if derr := dec.Decode(new(Record)); !errors.Is(derr, io.EOF) {
			res.OK = false
			res.BreakAt = lastSeq + 1
			res.Problem = "trailing bytes after the record on its line"
			return res, nil
		}

		if rec.Seq != lastSeq+1 {
			res.OK = false
			res.BreakAt = rec.Seq
			res.Problem = fmt.Sprintf("sequence jumped from %d to %d", lastSeq, rec.Seq)
			return res, nil
		}

		if rec.Prev != prev {
			res.OK = false
			res.BreakAt = rec.Seq
			res.Problem = fmt.Sprintf("prev hash %s does not match the previous record's hash %s", rec.Prev, prev)
			return res, nil
		}

		want, err := chainHash(prev, rec)
		if err != nil {
			return res, err
		}
		if want != rec.Hash {
			res.OK = false
			res.BreakAt = rec.Seq
			res.Problem = fmt.Sprintf("record hash %s does not match the recomputed hash %s", rec.Hash, want)
			return res, nil
		}

		prev = rec.Hash
		lastSeq = rec.Seq
		res.Records++
		res.Head = rec.Hash
		res.LastSeq = rec.Seq

		// A complete record that lost only its newline. It verified, so it is
		// evidence and it counts; the caller is told the file needs a byte
		// added rather than a record removed. Conflating this with a torn tail
		// would have the caller delete a record that verifies.
		//
		// This is also the only way out of the loop from down here: a
		// terminated line leaves ReadString with no error, so the file's end
		// arrives as the empty line above.
		if unterminated {
			res.UnterminatedFinalRecord = true
			break
		}
	}

	return res, nil
}
