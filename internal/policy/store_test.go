package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const policyA = "version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n"
const policyB = "version: 1\ndefault: deny\nrules:\n  - name: b\n    hosts: [\"b.com\"]\n"

func writePolicy(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func connectTo(host string) Request {
	return Request{Kind: KindConnect, Host: host, Port: 443}
}

func TestLoadStoreReadsFromDisk(t *testing.T) {
	path := writePolicy(t, t.TempDir(), policyA)
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}
	if got := s.Evaluate(connectTo("a.com")); got.Action != Allow {
		t.Errorf("Evaluate(a.com) = %+v, want allow", got)
	}
	if got := s.Source(); got != path {
		t.Errorf("Source() = %q, want %q", got, path)
	}
}

func TestLoadStoreReportsAMissingFile(t *testing.T) {
	_, err := LoadStore(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("LoadStore() error = nil, want a not-found error")
	}
}

func TestLoadStoreReportsAnInvalidPolicy(t *testing.T) {
	path := writePolicy(t, t.TempDir(), "version: 9\ndefault: deny\nrules: []\n")
	if _, err := LoadStore(path); err == nil {
		t.Fatal("LoadStore() error = nil, want a validation error")
	}
}

func TestReloadReplacesPolicy(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, policyA)
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}
	if got := s.Evaluate(connectTo("b.com")); got.Action != Deny {
		t.Fatalf("Evaluate(b.com) = %+v before reload, want deny", got)
	}

	writePolicy(t, dir, policyB)
	if err := s.Reload(path); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if got := s.Evaluate(connectTo("b.com")); got.Action != Allow {
		t.Errorf("Evaluate(b.com) = %+v after reload, want allow", got)
	}
	if got := s.Evaluate(connectTo("a.com")); got.Action != Deny {
		t.Errorf("Evaluate(a.com) = %+v after reload, want deny", got)
	}
}

// A bad edit to the policy file must not widen what is permitted. Keeping the
// last good policy is the whole reason reload is a separate operation from
// load.
func TestReloadKeepsTheOldPolicyOnParseError(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, policyA)
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}

	writePolicy(t, dir, "version: 1\ndefault: nonsense\nrules: []\n")
	err = s.Reload(path)
	if err == nil {
		t.Fatal("Reload() error = nil, want a validation error")
	}
	if !strings.Contains(err.Error(), "default") {
		t.Errorf("Reload() error = %q, want it to name the bad field", err)
	}

	if got := s.Evaluate(connectTo("a.com")); got.Action != Allow {
		t.Errorf("Evaluate(a.com) = %+v after a failed reload, want the old policy still in force", got)
	}
}

func TestReloadReportsAMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, policyA)
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}
	if err := s.Reload(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Fatal("Reload() error = nil, want a not-found error")
	}
}

func TestEvaluateDuringReloadIsRaceFree(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, policyA)
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				if err := s.Reload(path); err != nil {
					t.Errorf("Reload() error = %v", err)
					return
				}
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Evaluate(connectTo("a.com"))
			}
		}()
	}

	for i := 0; i < 8; i++ {
		// Give the readers time to interleave with the writer before stopping.
		s.Evaluate(connectTo("a.com"))
	}
	close(done)
	wg.Wait()
}

func TestNewStoreWrapsAnInMemoryPolicy(t *testing.T) {
	p := mustParse(t, policyA)
	s := NewStore(p)
	if got := s.Evaluate(connectTo("a.com")); got.Action != Allow {
		t.Errorf("Evaluate(a.com) = %+v, want allow", got)
	}
	if got := s.Source(); got != "" {
		t.Errorf("Source() = %q, want empty for an in-memory policy", got)
	}
}
