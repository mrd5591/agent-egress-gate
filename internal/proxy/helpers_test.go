package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
	"github.com/mrd5591/agent-egress-gate/internal/metrics"
	"github.com/mrd5591/agent-egress-gate/internal/policy"
)

// syncBuffer collects audit output. The proxy writes from connection
// goroutines, so the test sink has to be safe for concurrent use or the race
// detector will (correctly) fail the test for the wrong reason.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// gate is a running proxy plus the things a test needs to inspect afterwards.
type gate struct {
	server *httptest.Server
	audit  *syncBuffer
	reg    *prometheus.Registry
}

func (g *gate) URL() string { return g.server.URL }

// auditRecords parses everything the gate wrote.
func (g *gate) auditRecords(t *testing.T) []audit.Record {
	t.Helper()
	var out []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(g.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var r audit.Record
		if err := unmarshalRecord(line, &r); err != nil {
			t.Fatalf("audit line is not valid JSON: %v\nline: %s", err, line)
		}
		out = append(out, r)
	}
	return out
}

// lastAuditRecord is the common case: one request, one record.
func (g *gate) lastAuditRecord(t *testing.T) audit.Record {
	t.Helper()
	recs := g.auditRecords(t)
	if len(recs) == 0 {
		t.Fatal("no audit records written")
	}
	return recs[len(recs)-1]
}

// hostRule builds a policy allowing exactly the host and port of rawURL, with
// the given extra constraints. Tests need this because httptest servers bind
// ephemeral ports, which are never in the default 80/443 pair.
func hostRule(t *testing.T, name, rawURL string, methods, paths []string) policy.Rule {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", rawURL, err)
	}
	port := 0
	if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil {
		t.Fatalf("no port in %q", rawURL)
	}
	return policy.Rule{
		Name:    name,
		Hosts:   []string{u.Hostname()},
		Ports:   []int{port},
		Methods: methods,
		Paths:   paths,
	}
}

func allowHost(t *testing.T, rawURL string) *policy.Policy {
	t.Helper()
	return &policy.Policy{Version: 1, Default: policy.Deny, Rules: []policy.Rule{
		hostRule(t, "allowed", rawURL, nil, nil),
	}}
}

func denyAll() *policy.Policy {
	return &policy.Policy{Version: 1, Default: policy.Deny}
}

// newGate starts a proxy in front of the given policy.
func newGate(t *testing.T, pol *policy.Policy, cfg Config) *gate {
	t.Helper()
	g := &gate{audit: &syncBuffer{}, reg: prometheus.NewRegistry()}
	h := New(policy.NewStore(pol), audit.New(g.audit), metrics.New(g.reg), cfg, nil)
	g.server = httptest.NewServer(h)
	t.Cleanup(g.server.Close)
	return g
}

// proxiedClient returns a client that sends everything through the gate.
func proxiedClient(t *testing.T, gateURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(gateURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", gateURL, err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}
