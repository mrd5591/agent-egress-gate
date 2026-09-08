package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// dialTunnel opens a CONNECT tunnel through the gate by hand and leaves it
// open. The net/http client is no use here: it owns its connections and would
// close or reuse them on its own schedule, and the whole point of these tests
// is to control exactly when the tunnel ends.
func dialTunnel(t *testing.T, gateURL, authority string) net.Conn {
	t.Helper()

	u, err := url.Parse(gateURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", gateURL, err)
	}
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dialling the gate: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		t.Fatalf("writing CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading the CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	return c
}

// waitForTunnels blocks until the handler has n registered tunnels.
func waitForTunnels(t *testing.T, h *Handler, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for h.activeTunnels() != n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d live tunnel(s), have %d", n, h.activeTunnels())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The finding this closes: a tunnel open at shutdown left no audit record at
// all. A CONNECT record is written when the tunnel closes, http.Server.Shutdown
// does not wait on hijacked connections, and nothing else tracked them - so the
// normal end of a CI job, where every tunnel is open at SIGTERM, produced
// silence in the evidence log.
func TestShutdownAuditsATunnelThatIsStillOpen(t *testing.T) {
	upstream := newCountingListener(t)
	serveNothing(t, upstream)

	g := newGate(t, allowHost(t, upstream.https()), DefaultConfig())
	conn := dialTunnel(t, g.URL(), upstream.addr())

	// The tunnel is open and idle, which is the state the finding is about.
	waitForTunnels(t, g.handler, 1)
	if recs := g.auditRecords(t); len(recs) != 0 {
		t.Fatalf("a record was written while the tunnel was still open: %+v", recs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	// Shutdown returning is itself the guarantee: it waits for the record, so
	// no polling is needed here and a missing record is a real failure rather
	// than a slow one.
	recs := g.auditRecords(t)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records after shutdown, want 1", len(recs))
	}
	if recs[0].Kind != "connect" {
		t.Errorf("Kind = %q, want connect", recs[0].Kind)
	}
	if recs[0].Decision != "allow" {
		t.Errorf("Decision = %q, want allow", recs[0].Decision)
	}
	wantHost, _, err := net.SplitHostPort(upstream.addr())
	if err != nil {
		t.Fatalf("splitting the upstream address: %v", err)
	}
	if recs[0].Host != wantHost {
		t.Errorf("Host = %q, want %q", recs[0].Host, wantHost)
	}

	if n := g.handler.activeTunnels(); n != 0 {
		t.Errorf("activeTunnels() = %d after shutdown, want 0", n)
	}
	_ = conn.Close()
}

// Shutdown must drain every tunnel, not just one, and it must leave the chain
// contiguous: the records are written through the ordinary path, so they carry
// consecutive sequence numbers like any others.
func TestShutdownAuditsEveryOpenTunnel(t *testing.T) {
	upstream := newCountingListener(t)
	serveNothing(t, upstream)

	g := newGate(t, allowHost(t, upstream.https()), DefaultConfig())
	const tunnels = 4
	for i := 0; i < tunnels; i++ {
		dialTunnel(t, g.URL(), upstream.addr())
	}
	waitForTunnels(t, g.handler, tunnels)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	recs := g.auditRecords(t)
	if len(recs) != tunnels {
		t.Fatalf("got %d audit records after shutdown, want %d", len(recs), tunnels)
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("record %d has Seq %d, want %d; the chain must stay contiguous", i, r.Seq, i+1)
		}
	}
}

// A CONNECT arriving after shutdown has begun must be refused and audited,
// not opened. An unaudited tunnel is the exact hole this work closes, so the
// gap between "shutting down" and "listener closed" must not reopen it.
func TestConnectAfterShutdownIsRefusedAndAudited(t *testing.T) {
	upstream := newCountingListener(t)
	serveNothing(t, upstream)

	g := newGate(t, allowHost(t, upstream.https()), DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	u, err := url.Parse(g.URL())
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dialling the gate: %v", err)
	}
	defer func() { _ = c.Close() }()

	authority := upstream.addr()
	if _, err := c.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		t.Fatalf("writing CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading the CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 for a CONNECT during shutdown", resp.StatusCode)
	}

	recs := g.waitForAuditRecords(t, 1)
	// The policy still said allow, and the record says so: Decision is the
	// policy answer, not the outcome. What refused the tunnel is carried by
	// the status and the reason, matching how the other non-policy refusals
	// on this path record themselves.
	if recs[0].Decision != "allow" {
		t.Errorf("Decision = %q, want the policy answer (allow)", recs[0].Decision)
	}
	if recs[0].Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want 503", recs[0].Status)
	}
	if !strings.Contains(recs[0].Reason, "shutting down") {
		t.Errorf("Reason = %q, want it to say the gate was shutting down", recs[0].Reason)
	}
}

// Shutdown reports rather than hangs when a tunnel will not finish in time.
// The deadline is what keeps a wedged tunnel from holding the process open
// forever; the error is what stops that from being silent.
func TestShutdownReportsTunnelsThatMissTheDeadline(t *testing.T) {
	upstream := newCountingListener(t)
	serveNothing(t, upstream)

	g := newGate(t, allowHost(t, upstream.https()), DefaultConfig())
	dialTunnel(t, g.URL(), upstream.addr())
	waitForTunnels(t, g.handler, 1)

	// A deadline already in the past, so Shutdown takes the ctx branch
	// deterministically rather than by winning a race. The tunnel it strands
	// is closed by the gate's own cleanup when the test ends.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	err := g.handler.Shutdown(ctx)
	if err == nil {
		t.Fatal("Shutdown() returned nil on an expired context, want an error naming the stranded tunnels")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "audit record") {
		t.Errorf("error = %v, want it to say records are missing", err)
	}
}

// The connection-pool bounds. Zero means unlimited on http.Transport, so a
// Config assembled field by field - which cmd/egressgate does - must not opt
// out of them by omission.
func TestTransportBoundsAreAlwaysSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"DefaultConfig", DefaultConfig()},
		{"a Config that mentions none of them", Config{DialTimeout: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := New(nil, nil, nil, tc.cfg, nil).transport
			if tr.IdleConnTimeout <= 0 {
				t.Errorf("IdleConnTimeout = %v, want a bound", tr.IdleConnTimeout)
			}
			if tr.MaxIdleConns <= 0 {
				t.Errorf("MaxIdleConns = %d, want a bound", tr.MaxIdleConns)
			}
			if tr.MaxConnsPerHost <= 0 {
				t.Errorf("MaxConnsPerHost = %d, want a bound", tr.MaxConnsPerHost)
			}
			if tr.TLSHandshakeTimeout <= 0 {
				t.Errorf("TLSHandshakeTimeout = %v, want a bound", tr.TLSHandshakeTimeout)
			}
		})
	}
}

// An explicit value survives; the defaults fill gaps, they do not overwrite.
func TestTransportBoundsRespectAnExplicitConfig(t *testing.T) {
	tr := New(nil, nil, nil, Config{
		IdleConnTimeout:     3 * time.Second,
		MaxIdleConns:        7,
		MaxConnsPerHost:     9,
		TLSHandshakeTimeout: 4 * time.Second,
	}, nil).transport

	if tr.IdleConnTimeout != 3*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 3s", tr.IdleConnTimeout)
	}
	if tr.MaxIdleConns != 7 {
		t.Errorf("MaxIdleConns = %d, want 7", tr.MaxIdleConns)
	}
	if tr.MaxConnsPerHost != 9 {
		t.Errorf("MaxConnsPerHost = %d, want 9", tr.MaxConnsPerHost)
	}
	if tr.TLSHandshakeTimeout != 4*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 4s", tr.TLSHandshakeTimeout)
	}
}
