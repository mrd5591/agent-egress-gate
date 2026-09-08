package proxy

import (
	"bufio"
	"encoding/json"
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

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
)

func unmarshalRecord(line string, r *audit.Record) error {
	return json.Unmarshal([]byte(line), r)
}

func TestAllowedRequestReachesUpstream(t *testing.T) {
	var hits int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("X-Upstream", "yes")
		io.WriteString(w, "hello")
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	resp, err := proxiedClient(t, g.URL()).Get(up.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Errorf("upstream header not copied through, got %q", got)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "allow" || rec.Rule != "allowed" {
		t.Errorf("audit = %+v, want an allow on rule %q", rec, "allowed")
	}
	if rec.Status != http.StatusOK {
		t.Errorf("audit Status = %d, want 200", rec.Status)
	}
	if rec.BytesDown != int64(len("hello")) {
		t.Errorf("audit BytesDown = %d, want %d", rec.BytesDown, len("hello"))
	}
}

// The assertion that matters is the second one. A proxy that forwards the
// request and then returns 403 is not a gate.
func TestDeniedRequestNeverReachesUpstream(t *testing.T) {
	var hits int32
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer up.Close()

	g := newGate(t, denyAll(), DefaultConfig())
	resp, err := proxiedClient(t, g.URL()).Get(up.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("upstream was contacted %d times on a denied request", n)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "deny" {
		t.Errorf("audit Decision = %q, want deny", rec.Decision)
	}
	if rec.Reason == "" {
		t.Error("audit Reason is empty on a denial")
	}
}

func TestMethodConstraintIsEnforcedOnPlainHTTP(t *testing.T) {
	var hits int32
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer up.Close()

	pol := allowHost(t, up.URL)
	pol.Rules[0].Methods = []string{"GET"}
	g := newGate(t, pol, DefaultConfig())

	req, err := http.NewRequest(http.MethodDelete, up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := proxiedClient(t, g.URL()).Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

func TestPathConstraintIsEnforcedOnPlainHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	pol := allowHost(t, up.URL)
	pol.Rules[0].Paths = []string{"/allowed/"}
	g := newGate(t, pol, DefaultConfig())
	client := proxiedClient(t, g.URL())

	resp, err := client.Get(up.URL + "/allowed/thing")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed path status = %d, want 200", resp.StatusCode)
	}

	resp2, err := client.Get(up.URL + "/secret/thing")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("denied path status = %d, want 403", resp2.StatusCode)
	}
}

// Hop-by-hop headers belong to a single connection and must not be relayed.
// A raw socket is used so the test controls the exact bytes on the wire;
// http.Transport rewrites some of these on its own.
func TestHopByHopHeadersAreStripped(t *testing.T) {
	seen := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	gu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", gu.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s/ HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Proxy-Authorization: Basic c2VjcmV0\r\n"+
		"Connection: X-Single-Hop\r\n"+
		"X-Single-Hop: should-not-survive\r\n"+
		"X-End-To-End: should-survive\r\n"+
		"\r\n", up.URL, strings.TrimPrefix(up.URL, "http://"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	select {
	case h := <-seen:
		for _, name := range []string{"Proxy-Authorization", "Connection", "X-Single-Hop"} {
			if v := h.Get(name); v != "" {
				t.Errorf("upstream saw hop-by-hop header %s: %q", name, v)
			}
		}
		if got := h.Get("X-End-To-End"); got != "should-survive" {
			t.Errorf("end-to-end header not forwarded, got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the request")
	}

	// Drain so the deferred close does not race the proxy's write.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	bufio.NewReader(conn).ReadString('\n')
}

func TestOriginFormRequestIsRejected(t *testing.T) {
	g := newGate(t, denyAll(), DefaultConfig())

	// A direct request to the data port, not routed through a proxy config,
	// arrives in origin form and must be refused rather than treated as a
	// request to the gate itself.
	resp, err := http.Get(g.URL() + "/healthz")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "forward proxy") {
		t.Errorf("body = %q, want it to explain that this is a forward proxy", body)
	}
}

func TestUnreachableUpstreamReturnsBadGateway(t *testing.T) {
	// Start a server, capture its URL, then stop it so the port refuses.
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := up.URL
	up.Close()

	g := newGate(t, allowHost(t, deadURL), DefaultConfig())
	resp, err := proxiedClient(t, g.URL()).Get(deadURL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}

	rec := g.lastAuditRecord(t)
	if rec.Decision != "allow" {
		t.Errorf("audit Decision = %q, want allow; policy permitted it, the network failed", rec.Decision)
	}
	if rec.Status != http.StatusBadGateway {
		t.Errorf("audit Status = %d, want 502", rec.Status)
	}
}

func TestRequestBodyIsForwardedAndCounted(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	const payload = "the quick brown fox"
	resp, err := proxiedClient(t, g.URL()).Post(up.URL, "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	resp.Body.Close()

	select {
	case b := <-got:
		if b != payload {
			t.Errorf("upstream body = %q, want %q", b, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the body")
	}

	rec := g.lastAuditRecord(t)
	if rec.BytesUp != int64(len(payload)) {
		t.Errorf("audit BytesUp = %d, want %d", rec.BytesUp, len(payload))
	}
}

func TestRedirectsAreNotFollowedByTheGate(t *testing.T) {
	var finalHits int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&finalHits, 1)
	}))
	defer final.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Only the redirector is allowed. If the gate followed the redirect
	// itself, it would reach an unlisted host without a policy check.
	g := newGate(t, allowHost(t, redirector.URL), DefaultConfig())
	client := proxiedClient(t, g.URL())
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(redirector.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 passed through", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&finalHits); n != 0 {
		t.Errorf("gate followed the redirect to an unlisted host %d times", n)
	}
}

func TestMetricsRecordEveryDecision(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	g := newGate(t, allowHost(t, up.URL), DefaultConfig())
	client := proxiedClient(t, g.URL())

	resp, err := client.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := testutil.CollectAndCount(g.reg, "egressgate_requests_total"); got != 1 {
		t.Errorf("requests_total series = %d, want 1", got)
	}
	if got := testutil.CollectAndCount(g.reg, "egressgate_bytes_total"); got == 0 {
		t.Error("bytes_total was never recorded")
	}
}
