package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/policy"
)

// Regression tests for issues found in the 2026-09-08 code review.

// The transport reads the request body on its own goroutine and RoundTrip
// returns as soon as headers arrive, so an upstream that answers before
// draining the body has the handler reading the byte counter while the
// transport is still writing it. Fails under -race before the fix.
func TestByteCounterIsSafeWhenUpstreamAnswersEarly(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer immediately without reading the body.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, "too big")
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	client := proxiedClient(t, g.URL())

	for i := 0; i < 20; i++ {
		body := strings.NewReader(strings.Repeat("x", 1<<20))
		req, err := http.NewRequest(http.MethodPost, up.URL, body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // a reset mid-upload is fine; the race is what matters
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// A rule of paths: ["/allowed/"] must not be satisfied by a path that the
// upstream will route somewhere else. Otherwise `paths` claims an enforcement
// it does not perform, which is the exact failure the CONNECT rule exists to
// avoid.
func TestDotSegmentsCannotSatisfyAPathRule(t *testing.T) {
	var seen atomic.Value
	seen.Store("")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.RequestURI())
		io.WriteString(w, "reached")
	}))
	defer up.Close()

	pol := allowHost(t, up.URL)
	pol.Rules[0].Paths = []string{"/allowed/"}
	g := newGate(t, pol, DefaultConfig())

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{
		"/allowed/../secret",
		"/allowed/..%2f..%2fsecret",
		"/allowed/./../secret",
	} {
		t.Run(target, func(t *testing.T) {
			seen.Store("")
			conn, err := net.Dial("tcp", gu.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			host := strings.TrimPrefix(up.URL, "http://")
			fmt.Fprintf(conn, "GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", up.URL, target, host)
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("reading response: %v", err)
			}
			got := string(buf[:n])

			if strings.HasPrefix(got, "HTTP/1.1 2") {
				t.Errorf("request was allowed; response = %q", got)
			}
			if reached := seen.Load().(string); reached != "" {
				t.Errorf("upstream received %q; a path rule was bypassed", reached)
			}
		})
	}
}

// The ordinary case must keep working: a path that is already normalised is
// forwarded untouched.
func TestNormalisedPathsStillPass(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.RequestURI()
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	pol := allowHost(t, up.URL)
	pol.Rules[0].Paths = []string{"/allowed/"}
	g := newGate(t, pol, DefaultConfig())

	resp, err := proxiedClient(t, g.URL()).Get(up.URL + "/allowed/thing?q=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	select {
	case uri := <-got:
		if uri != "/allowed/thing?q=1" {
			t.Errorf("upstream received %q, want the path and query unchanged", uri)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// A quiet client during a long download must not kill the tunnel. The idle
// timeout is a property of the tunnel, not of each direction.
func TestActiveDownloadSurvivesAQuietClient(t *testing.T) {
	const streamFor = 2 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		deadline := time.Now().Add(streamFor)
		chunk := make([]byte, 512)
		for time.Now().Before(deadline) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	cfg := DefaultConfig()
	cfg.IdleTimeout = 400 * time.Millisecond // far shorter than the stream

	upURL := "https://" + ln.Addr().String()
	g := newGate(t, allowHost(t, upURL), cfg)

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}

	// The client now says nothing at all while the upstream streams.
	start := time.Now()
	var total int
	for {
		n, err := conn.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	lived := time.Since(start)

	if lived < streamFor-300*time.Millisecond {
		t.Errorf("tunnel died after %v carrying %d bytes; the upstream was still streaming, "+
			"so a quiet client must not trip the idle timeout", lived, total)
	}
}

// A tunnel that is genuinely idle in both directions must still close.
func TestTunnelStillClosesWhenBothSidesAreQuiet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	held := make(chan net.Conn, 4)
	t.Cleanup(func() {
		close(held)
		for c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case held <- c:
			default:
			}
		}
	}()

	cfg := DefaultConfig()
	cfg.IdleTimeout = 300 * time.Millisecond

	upURL := "https://" + ln.Addr().String()
	g := newGate(t, allowHost(t, upURL), cfg)

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 256)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}

	start := time.Now()
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("read succeeded; an idle tunnel was never closed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("idle tunnel took %v to close, want close to %v", elapsed, cfg.IdleTimeout)
	}
}

// A stream that ends exactly on the cap was not truncated, and the audit
// record must not claim it was.
func TestCapIsNotReportedWhenAStreamEndsExactlyOnIt(t *testing.T) {
	const capBytes = 4096

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := c.Write(make([]byte, capBytes)); err != nil {
			return
		}
	}()

	cfg := DefaultConfig()
	cfg.MaxTunnelBytes = capBytes

	upURL := "https://" + ln.Addr().String()
	g := newGate(t, allowHost(t, upURL), cfg)

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}

	rec := g.lastAuditRecord(t)
	if rec.BytesDown > capBytes {
		t.Errorf("audit BytesDown = %d, want at most the %d byte cap", rec.BytesDown, capBytes)
	}
	if strings.Contains(rec.Reason, "cap") {
		t.Errorf("audit Reason = %q; the stream ended exactly on the cap and was not truncated", rec.Reason)
	}
}

// The containment claim is about connections, not handler invocations. A gate
// that dialled the upstream and then hung up would pass a handler-count test
// while providing no containment.
func TestDeniedRequestOpensNoConnectionToUpstream(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingListener{Listener: base}

	up := &httptest.Server{
		Listener: counting,
		Config:   &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
	}
	up.Start()
	defer up.Close()

	g := newGate(t, denyAll(), DefaultConfig())
	before := counting.count()

	resp, err := proxiedClient(t, g.URL()).Get(up.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := counting.count() - before; got != 0 {
		t.Errorf("upstream accepted %d connections on a denied request, want 0", got)
	}
}

type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func (l *countingListener) count() int64 { return l.accepted.Load() }

// Under default: allow, a CONNECT with no host would rejoin as ":443" and
// dial the gate itself.
func TestConnectWithNoHostIsRejected(t *testing.T) {
	pol := &policy.Policy{Version: 1, Default: policy.Allow}
	g := newGate(t, pol, DefaultConfig())

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "400") {
		t.Errorf("proxy response = %q, want 400", got)
	}
}
