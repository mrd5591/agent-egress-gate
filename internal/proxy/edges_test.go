package proxy

import (
	"errors"
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

	"github.com/mrd5591/agent-egress-gate/internal/audit"
	"github.com/mrd5591/agent-egress-gate/internal/metrics"
	"github.com/mrd5591/agent-egress-gate/internal/policy"

	"github.com/prometheus/client_golang/prometheus"
)

func TestSplitAuthority(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com:443", "example.com", 443, false},
		{"example.com:8443", "example.com", 8443, false},
		{"example.com", "example.com", 443, false},
		{"[::1]:443", "::1", 443, false},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443, false},
		{"", "", 0, true},
		{"example.com:notaport", "", 0, true},
		{"example.com:0", "", 0, true},
		{"example.com:65536", "", 0, true},
		{"example.com:-1", "", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			host, port, err := splitAuthority(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitAuthority(%q) error = nil, want an error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitAuthority(%q) error = %v", tc.in, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("splitAuthority(%q) = %q, %d; want %q, %d", tc.in, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

// An IPv6 upstream must survive the whole path, not just the parser.
func TestConnectToIPv6Upstream(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
		io.Copy(io.Discard, c)
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	pol := &policy.Policy{Version: 1, Default: policy.Deny, Rules: []policy.Rule{
		{Name: "v6", Hosts: []string{"::1"}, Ports: []int{port}},
	}}
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

	authority := ln.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "200") {
		t.Fatalf("proxy response = %q, want 200 for an allowed IPv6 host", got)
	}

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("IPv6 upstream never accepted a connection")
	}
}

func TestDefaultPortFor(t *testing.T) {
	if got := defaultPortFor("https"); got != 443 {
		t.Errorf("defaultPortFor(https) = %d, want 443", got)
	}
	if got := defaultPortFor("http"); got != 80 {
		t.Errorf("defaultPortFor(http) = %d, want 80", got)
	}
}

func TestClientIPFallsBackToTheRawAddress(t *testing.T) {
	r := &http.Request{RemoteAddr: "not-a-host-port"}
	if got := clientIP(r); got != "not-a-host-port" {
		t.Errorf("clientIP() = %q, want the raw address back", got)
	}
	r2 := &http.Request{RemoteAddr: "10.0.0.5:5555"}
	if got := clientIP(r2); got != "10.0.0.5" {
		t.Errorf("clientIP() = %q, want 10.0.0.5", got)
	}
}

func TestCountingReaderWithNoBody(t *testing.T) {
	c := &countingReader{}
	n, err := c.Read(make([]byte, 4))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("Read() = %d, %v; want 0, EOF", n, err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestBadPortInAbsoluteURIIsRejected(t *testing.T) {
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

	fmt.Fprint(conn, "GET http://example.com:99999/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// failingAuditor stands in for a full disk. The gate must keep enforcing even
// when it can no longer record what it enforced, because refusing to proxy
// would turn a logging fault into an outage.
type failingAuditor struct{}

func (failingAuditor) Append(audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New("disk full")
}

func TestEnforcementContinuesWhenAuditingFails(t *testing.T) {
	var reached int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	reg := prometheus.NewRegistry()
	h := New(policy.NewStore(denyAll()), failingAuditor{}, metrics.New(reg), DefaultConfig(), nil)
	gate := httptest.NewServer(h)
	defer gate.Close()

	resp, err := proxiedClient(t, gate.URL).Get(up.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 even though auditing failed", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&reached); n != 0 {
		t.Errorf("upstream was contacted %d times on a denied request", n)
	}
}

// hijacklessRecorder is an http.ResponseWriter that cannot be hijacked, which
// is what a CONNECT would meet behind an HTTP/2 server.
type hijacklessRecorder struct{ *httptest.ResponseRecorder }

func TestConnectWithoutHijackSupportFailsCleanly(t *testing.T) {
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
			c.Close()
		}
	}()

	var port int
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	fmt.Sscanf(portStr, "%d", &port)

	pol := &policy.Policy{Version: 1, Default: policy.Deny, Rules: []policy.Rule{
		{Name: "local", Hosts: []string{"127.0.0.1"}, Ports: []int{port}},
	}}

	buf := &syncBuffer{}
	reg := prometheus.NewRegistry()
	h := New(policy.NewStore(pol), audit.New(buf), metrics.New(reg), DefaultConfig(), nil)

	rec := hijacklessRecorder{httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodConnect, "http://"+ln.Addr().String(), nil)
	req.Host = ln.Addr().String()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the writer cannot be hijacked", rec.Code)
	}
	if !strings.Contains(buf.String(), "hijack") && !strings.Contains(buf.String(), "unsupported") {
		t.Errorf("audit did not explain the failure: %s", buf.String())
	}
}
