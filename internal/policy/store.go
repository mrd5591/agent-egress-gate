package policy

import (
	"fmt"
	"os"
	"sync/atomic"
)

// Store holds the policy currently in force and swaps it atomically on
// reload. Evaluate is safe to call from every connection goroutine while a
// reload is in flight.
type Store struct {
	current atomic.Pointer[Policy]
	source  string
}

// NewStore wraps an already-parsed policy. Used by tests and by callers that
// build a policy in memory; Source is empty because there is no file behind
// it.
func NewStore(p *Policy) *Store {
	s := &Store{}
	s.current.Store(p)
	return s
}

// LoadStore reads and validates a policy file.
func LoadStore(path string) (*Store, error) {
	p, err := readPolicy(path)
	if err != nil {
		return nil, err
	}
	s := &Store{source: path}
	s.current.Store(p)
	return s, nil
}

// Source returns the path the policy was loaded from, or the empty string for
// an in-memory policy.
func (s *Store) Source() string { return s.source }

// Evaluate applies the policy currently in force.
func (s *Store) Evaluate(r Request) Decision {
	return s.current.Load().Evaluate(r)
}

// Reload replaces the policy from disk. On any failure the previous policy
// stays in force and the error is returned.
//
// The ordering matters: read and parse first, swap only on success. A reload
// that cleared the policy before parsing would open the gate for as long as
// it took an operator to notice, and a typo in a YAML file should never be
// able to do that.
func (s *Store) Reload(path string) error {
	p, err := readPolicy(path)
	if err != nil {
		return err
	}
	s.current.Store(p)
	return nil
}

func readPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}
