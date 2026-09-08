// Package proxy is the data plane: an HTTP forward proxy that consults a
// policy before it opens any connection to an upstream.
//
// The ordering is the whole point. Every path evaluates the policy first and
// dials second, so a denied request never becomes a packet. A proxy that
// forwards and then reports 403 would satisfy every status-code assertion in
// a test suite while providing no containment at all.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
	"github.com/mrd5591/agent-egress-gate/internal/metrics"
	"github.com/mrd5591/agent-egress-gate/internal/policy"
)

// Evaluator answers policy questions. The proxy holds this as an interface so
// the policy can be swapped underneath it at runtime.
type Evaluator interface {
	Evaluate(policy.Request) policy.Decision
}

// Auditor records decisions.
type Auditor interface {
	Append(audit.Record) (audit.Record, error)
}

// Config carries the timeouts and limits that keep one misbehaving upstream
// from consuming the gate.
type Config struct {
	// DialTimeout bounds the TCP connect to an upstream.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds how long an upstream may take to send
	// response headers after the request is written.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout closes a CONNECT tunnel in which neither direction has moved
	// bytes for this long. It is an idle timeout on the tunnel as a whole, not
	// a lifetime cap and not a per-direction one, so a long download whose
	// client has nothing to say is not killed.
	IdleTimeout time.Duration
	// MaxTunnelBytes caps each direction of a CONNECT tunnel independently.
	// Zero means no cap.
	//
	// This is a resource guard, not an exfiltration control, and the
	// difference matters. It applies only to tunnels: the plain-HTTP path
	// enforces no cap in either direction, so an agent allowed one host over
	// HTTP can still POST without bound. Read it as "one tunnel cannot consume
	// the gate", not as "an agent cannot send more than this out".
	MaxTunnelBytes int64

	// The four fields below bound the plain-HTTP transport's connection pool.
	// Each is zero-valued by default and zero means *unlimited* on
	// http.Transport, unlike http.DefaultTransport which sets all but one of
	// them. A gate that built its transport from a bare struct therefore held
	// an idle socket open for every upstream it had ever contacted. New fills
	// any of these left at zero from transportDefaults, so a caller that
	// constructs a Config by hand still gets bounds.

	// IdleConnTimeout is how long an idle keep-alive connection is retained.
	IdleConnTimeout time.Duration
	// MaxIdleConns caps idle connections across all upstreams.
	MaxIdleConns int
	// MaxConnsPerHost caps total connections to one upstream, in-flight and
	// idle. DefaultTransport leaves this unlimited; the gate does not, because
	// one agent looping on one host should not be able to exhaust the gate's
	// file descriptors.
	MaxConnsPerHost int
	// TLSHandshakeTimeout bounds the TLS handshake with an upstream.
	TLSHandshakeTimeout time.Duration
}

// transportDefaults are the connection-pool bounds applied to any Config field
// left at zero. The first, second and fourth mirror http.DefaultTransport.
// MaxConnsPerHost has no DefaultTransport value to mirror — DefaultTransport
// leaves it unlimited — so it is chosen here: high enough that ordinary
// parallel CI fetches never queue, low enough to bound the damage from a
// runaway client.
var transportDefaults = Config{
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        100,
	MaxConnsPerHost:     64,
	TLSHandshakeTimeout: 10 * time.Second,
}

// DefaultConfig returns timeouts suitable for CI traffic: generous enough for
// a large package download, short enough that a hung upstream does not pin a
// goroutine for the life of the process.
func DefaultConfig() Config {
	return Config{
		DialTimeout:           10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleTimeout:           5 * time.Minute,
		MaxTunnelBytes:        0,

		IdleConnTimeout:     transportDefaults.IdleConnTimeout,
		MaxIdleConns:        transportDefaults.MaxIdleConns,
		MaxConnsPerHost:     transportDefaults.MaxConnsPerHost,
		TLSHandshakeTimeout: transportDefaults.TLSHandshakeTimeout,
	}
}

// withTransportDefaults fills any connection-pool bound left at zero.
//
// This is applied in New rather than left to the caller because zero means
// unlimited on http.Transport. A caller assembling a Config field by field —
// which cmd/egressgate does, from its flags — would otherwise silently opt out
// of every bound by not mentioning it.
func withTransportDefaults(cfg Config) Config {
	if cfg.IdleConnTimeout == 0 {
		cfg.IdleConnTimeout = transportDefaults.IdleConnTimeout
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = transportDefaults.MaxIdleConns
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = transportDefaults.MaxConnsPerHost
	}
	if cfg.TLSHandshakeTimeout == 0 {
		cfg.TLSHandshakeTimeout = transportDefaults.TLSHandshakeTimeout
	}
	return cfg
}

// Handler is the proxy. It implements http.Handler so it can be served by an
// ordinary http.Server and tested with httptest.
type Handler struct {
	eval      Evaluator
	audit     Auditor
	metrics   *metrics.Metrics
	cfg       Config
	log       *slog.Logger
	transport *http.Transport
	dialer    *net.Dialer

	// Live CONNECT tunnels, so Shutdown can end them and collect their audit
	// records. A tunnel's record is written when the tunnel closes, so without
	// this a tunnel open at SIGTERM — the normal case at the end of a CI job —
	// leaves no trace at all: http.Server.Shutdown does not wait on hijacked
	// connections, and nothing else was tracking them.
	tunnelMu     sync.Mutex
	tunnels      map[uint64]tunnelConns
	nextTunnelID uint64
	closing      bool
	tunnelWG     sync.WaitGroup
}

// tunnelConns is both ends of one hijacked tunnel. Closing either unblocks the
// copy goroutines in pump, which is how a tunnel is ended from outside.
type tunnelConns struct {
	client   net.Conn
	upstream net.Conn
}

// New builds a Handler. A nil logger falls back to the default slog logger.
func New(e Evaluator, a Auditor, m *metrics.Metrics, cfg Config, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = withTransportDefaults(cfg)
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	return &Handler{
		eval:    e,
		audit:   a,
		metrics: m,
		cfg:     cfg,
		log:     logger,
		dialer:  dialer,
		transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
			Proxy:                 nil, // the gate is the proxy; it must not chain to another
			ForceAttemptHTTP2:     false,
			IdleConnTimeout:       cfg.IdleConnTimeout,
			MaxIdleConns:          cfg.MaxIdleConns,
			MaxConnsPerHost:       cfg.MaxConnsPerHost,
			TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		},
	}
}

// registerTunnel records a hijacked tunnel so Shutdown can end it and wait for
// its audit record. It reports false when the gate is already shutting down,
// in which case the caller must not start the tunnel at all.
//
// The refusal is what closes the race. Registration and the closing flag share
// one mutex, so a tunnel either registers before Shutdown snapshots the set —
// and is therefore closed and waited for — or is refused outright. Neither
// order leaves a tunnel running that nobody is waiting on.
//
// The returned function unregisters and releases the wait. It must run *after*
// the record is written, which a deferred call in handleConnect achieves:
// deferred calls run after the function body, and the body is what calls
// finish.
func (h *Handler) registerTunnel(client, upstream net.Conn) (unregister func(), ok bool) {
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()

	if h.closing {
		return nil, false
	}
	if h.tunnels == nil {
		h.tunnels = make(map[uint64]tunnelConns)
	}
	h.nextTunnelID++
	id := h.nextTunnelID
	h.tunnels[id] = tunnelConns{client: client, upstream: upstream}
	h.tunnelWG.Add(1)

	return func() {
		h.tunnelMu.Lock()
		delete(h.tunnels, id)
		h.tunnelMu.Unlock()
		h.tunnelWG.Done()
	}, true
}

// Shutdown ends every live CONNECT tunnel and waits until each has written its
// audit record, or until ctx expires.
//
// Call it after http.Server.Shutdown and before reading the audit chain head.
// http.Server.Shutdown deliberately does not wait on hijacked connections, so
// it returns while tunnels are still running; reading the head at that point
// prints a head that later records invalidate, and the tunnels themselves are
// never audited.
//
// After Shutdown no new tunnel starts: a CONNECT arriving in the gap answers
// 503 and is audited as such, which is a truthful record rather than a missing
// one.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.tunnelMu.Lock()
	h.closing = true
	live := make([]tunnelConns, 0, len(h.tunnels))
	for _, c := range h.tunnels {
		live = append(live, c)
	}
	h.tunnelMu.Unlock()

	// Closing both ends unblocks pump's copies, so each handleConnect returns
	// and writes its record through the ordinary path. Nothing here writes a
	// record itself: a shutdown record assembled out here would carry byte
	// counts nobody had finished counting.
	for _, c := range live {
		_ = c.client.Close()
		_ = c.upstream.Close()
	}

	done := make(chan struct{})
	go func() {
		h.tunnelWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		h.tunnelMu.Lock()
		stranded := len(h.tunnels)
		h.tunnelMu.Unlock()
		return fmt.Errorf(
			"proxy: %d tunnel(s) had not written an audit record when the shutdown deadline passed: %w",
			stranded, ctx.Err())
	}
}

// isClosing reports whether Shutdown has begun.
func (h *Handler) isClosing() bool {
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()
	return h.closing
}

// activeTunnels reports how many tunnels are registered. It exists for tests;
// the exported view of the same number is the egressgate_active_tunnels gauge.
func (h *Handler) activeTunnels() int {
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()
	return len(h.tunnels)
}

// hopByHopHeaders are defined per-connection by RFC 7230 section 6.1 and must
// not be forwarded. Proxy-Connection is not in the RFC but is widely sent and
// equally must not be relayed.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHop strips per-connection headers. Headers named in the
// Connection field are removed first, because deleting Connection itself
// first would lose the list of what else to remove.
func removeHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// ServeHTTP dispatches to the tunnel or the plain-HTTP path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := audit.Record{
		Kind:   string(policy.KindHTTP),
		Method: r.Method,
		Client: clientIP(r),
	}

	// A forward proxy is addressed with an absolute request URI. An
	// origin-form request means something is pointed at the gate directly,
	// which is a configuration error worth reporting rather than guessing at.
	if !r.URL.IsAbs() {
		rec.Decision = string(policy.Deny)
		rec.Reason = "request URI is not absolute; this port is a forward proxy, not an origin server"
		rec.Host = r.Host
		rec.Path = r.URL.Path
		h.finish(&rec, start, http.StatusBadRequest)
		http.Error(w, "egressgate: this is a forward proxy; configure it as one and send an absolute request URI",
			http.StatusBadRequest)
		return
	}

	host := r.URL.Hostname()
	port := defaultPortFor(r.URL.Scheme)
	if p := r.URL.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			rec.Decision = string(policy.Deny)
			rec.Reason = fmt.Sprintf("unparseable port %q", p)
			rec.Host = host
			h.finish(&rec, start, http.StatusBadRequest)
			http.Error(w, "egressgate: bad port in request URI", http.StatusBadRequest)
			return
		}
		port = n
	}

	rec.Host = host
	rec.Port = port
	rec.Path = r.URL.Path

	// A path prefix rule is only an enforcement if the path it matches is the
	// path the upstream will route on. "/allowed/../secret" matches the prefix
	// "/allowed/" and reaches "/secret" on any origin server that normalises,
	// and "%2e%2e" hides the same trick from a naive comparison. Rather than
	// rewrite what the client asked for, the gate refuses a request whose
	// normalised path differs from the one it would forward.
	if norm, ok := normalisedPath(r.URL); !ok {
		rec.Decision = string(policy.Deny)
		rec.Reason = fmt.Sprintf(
			"path %q contains dot-segments or encoded separators; it normalises to %q, "+
				"so a path rule could not be enforced on what the upstream would route",
			r.URL.Path, norm)
		h.finish(&rec, start, http.StatusBadRequest)
		http.Error(w, "egressgate: "+rec.Reason, http.StatusBadRequest)
		return
	}

	decision := h.eval.Evaluate(policy.Request{
		Kind:   policy.KindHTTP,
		Host:   host,
		Port:   port,
		Method: r.Method,
		Path:   r.URL.Path,
	})
	rec.Decision = string(decision.Action)
	rec.Rule = decision.Rule
	rec.Reason = decision.Reason

	if decision.Action != policy.Allow {
		h.finish(&rec, start, http.StatusForbidden)
		http.Error(w, "egressgate: denied by policy: "+decision.Reason, http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	counted := &countingReader{}
	if outReq.Body != nil {
		counted.r = outReq.Body
		outReq.Body = counted
	}

	// RoundTrip rather than a Client, because a proxy must not follow
	// redirects. Following one would reach a host the policy never saw.
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		rec.BytesUp = counted.count()
		h.finish(&rec, start, http.StatusBadGateway)
		h.log.Warn("upstream request failed", "host", host, "port", port, "error", err)
		http.Error(w, "egressgate: upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	removeHopByHop(resp.Header)
	for name, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	down, copyErr := io.Copy(w, resp.Body)
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		h.log.Warn("copying response body failed", "host", host, "error", copyErr)
	}

	rec.BytesUp = counted.count()
	rec.BytesDown = down
	h.finish(&rec, start, resp.StatusCode)
}

// finish stamps the record with status and duration, writes it, and updates
// the metrics. Every request path ends here exactly once.
func (h *Handler) finish(rec *audit.Record, start time.Time, status int) {
	rec.Status = status
	rec.DurationMS = time.Since(start).Milliseconds()

	if _, err := h.audit.Append(*rec); err != nil {
		// An audit failure is serious: the gate is still enforcing, but it has
		// stopped being able to prove what it enforced.
		h.log.Error("audit append failed", "error", err, "host", rec.Host)
	}

	h.metrics.Requests.WithLabelValues(rec.Decision, rec.Rule, rec.Kind).Inc()
	h.metrics.Duration.WithLabelValues(rec.Kind).Observe(time.Since(start).Seconds())
	if rec.BytesUp > 0 {
		h.metrics.Bytes.WithLabelValues("up").Add(float64(rec.BytesUp))
	}
	if rec.BytesDown > 0 {
		h.metrics.Bytes.WithLabelValues("down").Add(float64(rec.BytesDown))
	}
}

// NormalisedPath is normalisedPath, exported so that anything modelling the
// gate's answer uses the gate's own code rather than a copy of it.
//
// `egressgate check` is the caller that needs it. A copy would drift, and the
// drift already happened once: check reported allow for a path the running
// proxy refuses with 400, contradicting its documented promise never to
// promise an allow the gate would refuse.
func NormalisedPath(u *url.URL) (normalised string, ok bool) {
	return normalisedPath(u)
}

// normalisedPath reports the cleaned form of a request path and whether it is
// already normalised.
//
// Both the decoded path and the raw, still-encoded form are checked: an
// encoded separator such as "%2f" survives path.Clean untouched but is decoded
// by many origin servers, so a rule matching the encoded string would not
// match what the upstream actually routes on.
func normalisedPath(u *url.URL) (string, bool) {
	raw := u.EscapedPath()
	if strings.Contains(strings.ToLower(raw), "%2f") || strings.Contains(strings.ToLower(raw), "%5c") {
		return raw, false
	}

	p := u.Path
	if p == "" {
		p = "/"
	}
	cleaned := path.Clean(p)
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	return cleaned, cleaned == p
}

func defaultPortFor(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// countingReader counts bytes read from a request body so the audit record
// can report how much left the network.
//
// The count is atomic because the transport reads the body on its own write
// goroutine, and RoundTrip returns as soon as response headers arrive. Any
// upstream that answers before consuming the body, which is every 401, 413 or
// 429, has the handler reading this counter while the transport is still
// writing it.
type countingReader struct {
	r io.ReadCloser
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReader) count() int64 { return c.n.Load() }

func (c *countingReader) Close() error {
	if c.r == nil {
		return nil
	}
	return c.r.Close()
}
