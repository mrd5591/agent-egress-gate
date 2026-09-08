package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/policy"
)

// tlsProxiedClient sends HTTPS through the gate, trusting the httptest
// server's self-signed certificate.
func tlsProxiedClient(t *testing.T, gateURL string, up *httptest.Server) *http.Client {
	t.Helper()
	gu, err := url.Parse(gateURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", gateURL, err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(gu),
		TLSClientConfig: up.Client().Transport.(*http.Transport).TLSClientConfig,
	}}
}

func TestConnectTunnelCarriesTLSBothWays(t *testing.T) {
	var hits int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		io.WriteString(w, "secure hello")
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	client := tlsProxiedClient(t, g.URL(), up)
	resp, err := client.Get(up.URL)
	if err != nil {
		t.Fatalf("Get() through tunnel error = %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" {
		t.Errorf("body = %q, want %q", body, "secure hello")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}

	// The tunnel's audit record is written when the tunnel closes. The client
	// would otherwise hold it open for reuse and the record would never land.
	client.CloseIdleConnections()

	rec := g.lastAuditRecord(t)
	if rec.Kind != string(policy.KindConnect) {
		t.Errorf("audit Kind = %q, want connect", rec.Kind)
	}
	if rec.Decision != "allow" {
		t.Errorf("audit Decision = %q, want allow", rec.Decision)
	}
	if rec.Path != "" {
		t.Errorf("audit Path = %q, want empty; the gate cannot see inside a tunnel", rec.Path)
	}
	if rec.BytesUp == 0 || rec.BytesDown == 0 {
		t.Errorf("audit bytes up/down = %d/%d, want both non-zero", rec.BytesUp, rec.BytesDown)
	}
}

func TestConnectDeniedNeverOpensATunnel(t *testing.T) {
	var hits int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer up.Close()

	g := newGate(t, denyAll(), DefaultConfig())
	_, err := tlsProxiedClient(t, g.URL(), up).Get(up.URL)
	if err == nil {
		t.Fatal("Get() error = nil, want a proxy refusal")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("upstream was contacted %d times on a denied CONNECT", n)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "deny" {
		t.Errorf("audit Decision = %q, want deny", rec.Decision)
	}
	if rec.Kind != string(policy.KindConnect) {
		t.Errorf("audit Kind = %q, want connect", rec.Kind)
	}
}

// The design's central rule, exercised through a real socket: a rule that
// constrains a method cannot be used to authorise a tunnel, because the gate
// cannot see the method once TLS starts.
func TestConnectRefusedForARuleThatConstrainsMethod(t *testing.T) {
	var hits int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer up.Close()

	pol := allowHost(t, up.URL)
	pol.Rules[0].Methods = []string{"GET"}

	g := newGate(t, pol, DefaultConfig())
	if _, err := tlsProxiedClient(t, g.URL(), up).Get(up.URL); err == nil {
		t.Fatal("Get() error = nil; a method-constrained rule must not open a tunnel")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("upstream was contacted %d times", n)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "deny" {
		t.Fatalf("audit Decision = %q, want deny", rec.Decision)
	}
	if !strings.Contains(rec.Reason, "cannot be enforced inside a tunnel") {
		t.Errorf("audit Reason = %q, want it to explain why the rule was ineligible", rec.Reason)
	}
	if !strings.Contains(rec.Reason, "allowed") {
		t.Errorf("audit Reason = %q, want it to name the near-miss rule", rec.Reason)
	}
}

func TestConnectToUnreachableUpstreamReturnsBadGateway(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := up.URL
	up.Close()

	g := newGate(t, allowHost(t, deadURL), DefaultConfig())
	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(deadURL, "https://")

	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "502") {
		t.Errorf("proxy response = %q, want 502", got)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "allow" {
		t.Errorf("audit Decision = %q, want allow; the policy permitted it and the dial failed", rec.Decision)
	}
	if rec.Status != http.StatusBadGateway {
		t.Errorf("audit Status = %d, want 502", rec.Status)
	}
}

// A denied CONNECT must produce a readable HTTP response, not a dropped
// socket. An agent that gets a closed connection cannot tell a policy denial
// from a network fault.
func TestDeniedConnectReturnsAReadableResponse(t *testing.T) {
	g := newGate(t, denyAll(), DefaultConfig())
	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "403") {
		t.Errorf("proxy response = %q, want 403", got)
	}
	if !strings.Contains(got, "denied by policy") {
		t.Errorf("proxy response = %q, want it to say why", got)
	}
}

func TestConnectDefaultsToPort443WhenAbsent(t *testing.T) {
	g := newGate(t, denyAll(), DefaultConfig())
	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT bare.example.com HTTP/1.1\r\nHost: bare.example.com\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}

	rec := g.lastAuditRecord(t)
	if rec.Host != "bare.example.com" {
		t.Errorf("audit Host = %q, want bare.example.com", rec.Host)
	}
	if rec.Port != 443 {
		t.Errorf("audit Port = %d, want 443", rec.Port)
	}
}

func TestTunnelIdleTimeoutClosesTheConnection(t *testing.T) {
	// An upstream that accepts and then says nothing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Hold accepted connections open without sending anything. They are
	// tracked and closed together, because registering a cleanup from inside
	// this goroutine would race the end of the test.
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	cfg := DefaultConfig()
	cfg.IdleTimeout = 150 * time.Millisecond

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
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}

	// The tunnel is open and idle. It must close on its own.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("read succeeded; the idle tunnel was never closed")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("tunnel took %v to close, want close to the %v idle timeout", elapsed, cfg.IdleTimeout)
	}
}

func TestTunnelByteCapClosesTheConnection(t *testing.T) {
	// An upstream that floods once the tunnel opens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				chunk := make([]byte, 4096)
				for i := 0; i < 200; i++ {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	cfg := DefaultConfig()
	cfg.MaxTunnelBytes = 8192

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

	total := 0
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		total += n
		if err != nil {
			break
		}
		if total > 1<<20 {
			t.Fatal("read past the cap; MaxTunnelBytes was not enforced")
		}
	}

	// The CONNECT response line plus at most the cap.
	if total > int(cfg.MaxTunnelBytes)+512 {
		t.Errorf("received %d bytes, want at most the %d byte cap plus the response line",
			total, cfg.MaxTunnelBytes)
	}

	rec := g.lastAuditRecord(t)
	if rec.BytesDown > cfg.MaxTunnelBytes {
		t.Errorf("audit BytesDown = %d, want at most %d", rec.BytesDown, cfg.MaxTunnelBytes)
	}
}

// A client that sends its first bytes in the same packet as the CONNECT
// request must not lose them. Those bytes sit in the server's read buffer
// after hijacking, and a tunnel that reads from the raw connection instead of
// the buffered reader silently drops them.
func TestTunnelDoesNotDropBytesBufferedWithTheConnectRequest(t *testing.T) {
	got := make(chan string, 1)
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
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		got <- string(buf[:n])
	}()

	upURL := "https://" + ln.Addr().String()
	g := newGate(t, allowHost(t, upURL), DefaultConfig())

	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// One write: the CONNECT request and the first payload bytes together.
	payload := "EARLY-PAYLOAD"
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", ln.Addr(), ln.Addr(), payload)

	select {
	case s := <-got:
		if !strings.Contains(s, payload) {
			t.Errorf("upstream received %q, want it to contain %q", s, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the early payload; buffered bytes were dropped")
	}
}

func TestConnectWithMalformedAuthorityIsRejected(t *testing.T) {
	g := newGate(t, denyAll(), DefaultConfig())
	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT host:notaport HTTP/1.1\r\nHost: host:notaport\r\n\r\n")
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
