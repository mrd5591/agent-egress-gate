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
// these fields invalidates every previously written log; TestHashIsStable
// pins one value so that cannot happen by accident.
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

		terminated := strings.HasSuffix(raw, "\n")
		line := strings.TrimSpace(raw)

		if line == "" {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}

		// An unterminated final line is an interrupted write. Stop here and
		// report the truncation; the records before it stand.
		if !terminated && errors.Is(err, io.EOF) {
			res.TruncatedTail = true
			break
		}

		// DisallowUnknownFields because the chain covers the record's fields,
		// not the bytes of the line. Without it, arbitrary keys can be spliced
		// into an audited line and the chain still verifies, which would make
		// the log's own format a place to hide things.
		var rec Record
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			res.OK = false
			res.BreakAt = lastSeq + 1
			res.Problem = fmt.Sprintf("could not decode record: %v", err)
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

		if errors.Is(err, io.EOF) {
			break
		}
	}

	return res, nil
}
