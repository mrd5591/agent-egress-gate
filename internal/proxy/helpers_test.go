package proxy

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
//
// It waits, because a tunnel's record is written when the tunnel closes, not
// when it opens. A client that has finished reading a response may still hold
// the tunnel open for reuse, so the record can lag the response by a moment.
func (g *gate) lastAuditRecord(t *testing.T) audit.Record {
	t.Helper()
	recs := g.waitForAuditRecords(t, 1)
	return recs[len(recs)-1]
}

// waitForAuditRecords polls until at least n records exist or the test's
// patience runs out.
func (g *gate) waitForAuditRecords(t *testing.T, n int) []audit.Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recs := g.auditRecords(t)
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d audit records, only %d were written", n, len(recs))
		}
		time.Sleep(10 * time.Millisecond)
	}
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

// countingListener counts the connections a listener accepts, and reports the
// peer address of each one.
//
// Accepts, not handler invocations. That distinction is the whole containment
// claim: a gate that dialled an upstream and only then answered 403 opens a
// real TCP connection to a host the policy forbade, and on the CONNECT path it
// completes no TLS handshake and runs no handler at all. A test counting
// handler calls stays green while the containment is gone, which is exactly
// the weaker test the README warns about.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
	// seen carries every accepted peer address. The send is non-blocking, so a
	// listener built without a channel (or one whose buffer overflows) costs a
	// dropped signal rather than a wedged accept loop.
	seen chan net.Addr
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the upstream: %v", err)
	}
	l := &countingListener{Listener: base, seen: make(chan net.Addr, 64)}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
		select {
		case l.seen <- c.RemoteAddr():
		default:
		}
	}
	return c, err
}

func (l *countingListener) count() int64 { return l.accepted.Load() }

// addr is the authority a CONNECT request names, and url is the form the
// policy helpers parse. Nothing here ever speaks TLS; the https scheme only
// tells hostRule which port to pin.
func (l *countingListener) addr() string  { return l.Addr().String() }
func (l *countingListener) https() string { return "https://" + l.addr() }

// serveNothing runs an accept loop that holds every connection open and reads
// nothing from it. Something has to call Accept, or a connection the gate
// should never have opened sits unnoticed in the kernel's backlog and is never
// counted. Connections are tracked and closed together, because registering a
// cleanup from inside the goroutine would race the end of the test.
func serveNothing(t *testing.T, l *countingListener) {
	t.Helper()
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
}

// assertNoAccepts is the containment assertion: the upstream accepted nothing.
//
// It cannot simply read the counter. A connection the gate dialled has
// completed its handshake and is sitting in the kernel's accept queue before
// the dial returns, but the accept loop may not have counted it yet, so an
// immediate read could pass on a gate that had already reached the host. So
// the test opens a connection of its own and waits for that one to be
// accepted. The accept queue is FIFO and the counter is incremented inside
// Accept, so by the time our own connection surfaces, anything the gate queued
// ahead of it has been counted. No sleeps and no timing margins: the only
// clock here is the guard against hanging forever.
func assertNoAccepts(t *testing.T, l *countingListener) {
	t.Helper()

	probe, err := net.Dial("tcp", l.addr())
	if err != nil {
		t.Fatalf("dialling the upstream to synchronise with its accept loop: %v", err)
	}
	defer func() { _ = probe.Close() }()
	want := probe.LocalAddr().String()

	var extra []string
	for {
		select {
		case peer := <-l.seen:
			if peer.String() == want {
				if len(extra) != 0 {
					t.Errorf("upstream accepted %d connection(s) on a denied request, want 0; peers: %v",
						len(extra), extra)
				}
				return
			}
			extra = append(extra, peer.String())
		case <-time.After(10 * time.Second):
			t.Fatalf("the upstream never accepted the probe connection (accepts so far: %d)", l.count())
		}
	}
}
