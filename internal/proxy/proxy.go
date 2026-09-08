// Package proxy is the data plane: an HTTP forward proxy that consults a
// policy before it opens any connection to an upstream.
//
// The ordering is the whole point. Every path evaluates the policy first and
// dials second, so a denied request never becomes a packet. A proxy that
// forwards and then reports 403 would satisfy every status-code assertion in
// a test suite while providing no containment at all.
package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	// IdleTimeout closes a CONNECT tunnel that has moved no bytes for this
	// long. It is an idle timeout, not a lifetime cap, so a long-running but
	// active download is not killed.
	IdleTimeout time.Duration
	// MaxTunnelBytes caps each direction of a CONNECT tunnel independently.
	// Zero means no cap. The client-to-upstream direction is the one that
	// bounds how much a compromised agent can send out in a single tunnel.
	MaxTunnelBytes int64
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
	}
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
}

// New builds a Handler. A nil logger falls back to the default slog logger.
func New(e Evaluator, a Auditor, m *metrics.Metrics, cfg Config, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
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
		},
	}
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
		rec.BytesUp = counted.n
		h.finish(&rec, start, http.StatusBadGateway)
		h.log.Warn("upstream request failed", "host", host, "port", port, "error", err)
		http.Error(w, "egressgate: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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

	rec.BytesUp = counted.n
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
type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error {
	if c.r == nil {
		return nil
	}
	return c.r.Close()
}
