package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrd5591/agent-egress-gate/internal/audit"
	"github.com/mrd5591/agent-egress-gate/internal/policy"
)

// handleConnect opens a TCP tunnel after the policy allows it.
//
// The order of operations is deliberate and each step depends on the one
// before it:
//
//  1. Parse the authority. A malformed one is a 400, not a guess.
//  2. Evaluate the policy. A denial is answered with a real HTTP response,
//     because a dropped socket tells an agent nothing about why it failed.
//  3. Dial the upstream. Doing this before hijacking means a refused
//     connection can still be reported as 502 over normal HTTP.
//  4. Only then hijack and write the 200, after which no HTTP response is
//     possible any more.
//
// The audit record for a tunnel is written when the tunnel closes, not when
// it opens, because the byte counts are not known until then. A long-lived
// tunnel is therefore absent from the log while it is running. The
// egressgate_active_tunnels gauge is what covers that window; anyone watching
// for live activity should watch the gauge, not tail the log.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := audit.Record{
		Kind:   string(policy.KindConnect),
		Client: clientIP(r),
	}

	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}

	host, port, err := splitAuthority(authority)
	if err != nil {
		rec.Host = authority
		rec.Decision = string(policy.Deny)
		rec.Reason = err.Error()
		h.finish(&rec, start, http.StatusBadRequest)
		http.Error(w, "egressgate: "+err.Error(), http.StatusBadRequest)
		return
	}
	rec.Host = host
	rec.Port = port

	// Method and Path stay empty. They are not knowable for a tunnel, and
	// filling them with anything would let a constrained rule appear to match.
	decision := h.eval.Evaluate(policy.Request{
		Kind: policy.KindConnect,
		Host: host,
		Port: port,
	})
	rec.Decision = string(decision.Action)
	rec.Rule = decision.Rule
	rec.Reason = decision.Reason

	if decision.Action != policy.Allow {
		h.finish(&rec, start, http.StatusForbidden)
		http.Error(w, "egressgate: denied by policy: "+decision.Reason, http.StatusForbidden)
		return
	}

	upstream, err := h.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		h.finish(&rec, start, http.StatusBadGateway)
		h.log.Warn("tunnel dial failed", "host", host, "port", port, "error", err)
		http.Error(w, "egressgate: could not reach upstream", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		rec.Reason = "the server does not support connection hijacking"
		h.finish(&rec, start, http.StatusInternalServerError)
		http.Error(w, "egressgate: tunnelling unsupported on this server", http.StatusInternalServerError)
		return
	}

	// buffered may already hold bytes the client sent in the same packet as
	// the CONNECT request. Reading from clientConn directly would discard
	// them, which breaks any client that pipelines its TLS ClientHello.
	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		h.finish(&rec, start, http.StatusInternalServerError)
		h.log.Error("hijack failed", "error", err)
		http.Error(w, "egressgate: could not take over the connection", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		rec.Reason = "client went away before the tunnel opened"
		h.finish(&rec, start, http.StatusBadGateway)
		return
	}

	h.metrics.Tunnels.Inc()
	defer h.metrics.Tunnels.Dec()

	up, down, capped := h.pump(clientConn, buffered, upstream)

	rec.BytesUp = up
	rec.BytesDown = down
	if capped {
		rec.Reason = fmt.Sprintf("tunnel closed after reaching the %d byte cap", h.cfg.MaxTunnelBytes)
	}
	h.finish(&rec, start, http.StatusOK)
}

// pump copies bytes in both directions until either side finishes, then
// closes both so the other copy cannot block forever. It returns the bytes
// moved each way and whether a byte cap ended the tunnel.
func (h *Handler) pump(clientConn net.Conn, buffered io.Reader, upstream net.Conn) (up, down int64, capped bool) {
	var upBytes, downBytes int64
	var cappedFlag atomic.Bool

	// One shared activity clock for both directions. Giving each direction its
	// own deadline would kill the tunnel whenever one side went quiet, which
	// is exactly what a large download looks like: the client says nothing for
	// minutes while megabytes arrive. The tunnel is idle only when neither
	// direction has moved.
	activity := newIdleClock(h.cfg.IdleTimeout)

	// The client's read side is the buffered reader, so bytes that arrived
	// with the CONNECT request are not lost. Deadlines are still set on the
	// underlying connection, which is what the reader ultimately draws from.
	clientSrc := &idleReader{r: buffered, conn: clientConn, clock: activity}
	upstreamSrc := &idleReader{r: upstream, conn: upstream, clock: activity}

	// The cap is applied on the write side, not the read side. A LimitReader
	// would forward the cap and then report EOF, which is indistinguishable
	// from a stream that simply ended on the boundary; capping the writer
	// forwards exactly the cap and knows whether more was on its way.
	upWriter := newCappedWriter(upstream, h.cfg.MaxTunnelBytes)
	downWriter := newCappedWriter(clientConn, h.cfg.MaxTunnelBytes)

	done := make(chan struct{}, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = clientConn.Close()
			_ = upstream.Close()
		})
	}

	go func() {
		n, _ := io.Copy(upWriter, clientSrc)
		atomic.StoreInt64(&upBytes, n)
		if upWriter.exceeded() {
			cappedFlag.Store(true)
		}
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(downWriter, upstreamSrc)
		atomic.StoreInt64(&downBytes, n)
		if downWriter.exceeded() {
			cappedFlag.Store(true)
		}
		done <- struct{}{}
	}()

	// One direction finishing means the tunnel is over. Closing both ends
	// unblocks the other copy, which would otherwise wait for its idle
	// timeout on a connection nobody is using.
	<-done
	closeBoth()
	<-done

	return atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes), cappedFlag.Load()
}

// splitAuthority parses the authority form used by CONNECT, defaulting to the
// HTTPS port when none is given.
func splitAuthority(authority string) (host string, port int, err error) {
	if authority == "" {
		return "", 0, fmt.Errorf("CONNECT requires an authority such as host:443")
	}

	h, p, splitErr := net.SplitHostPort(authority)
	if splitErr != nil {
		// No colon at all means no port, which is legal and means 443.
		// Anything else is malformed. errors.As rather than a type assertion,
		// so a future wrapped error still matches.
		var addrErr *net.AddrError
		if errors.As(splitErr, &addrErr) && addrErr.Err == "missing port in address" {
			return authority, 443, nil
		}
		return "", 0, fmt.Errorf("malformed CONNECT authority %q", authority)
	}

	n, convErr := strconv.Atoi(p)
	if convErr != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("malformed port in CONNECT authority %q", authority)
	}
	// An empty host would rejoin as ":443", which under a default-allow policy
	// dials the gate itself.
	if h == "" {
		return "", 0, fmt.Errorf("CONNECT authority %q has no host", authority)
	}
	return h, n, nil
}

// errTunnelCapExceeded stops a copy once the configured cap is reached.
var errTunnelCapExceeded = errors.New("tunnel byte cap reached")

// cappedWriter forwards at most limit bytes and records whether more was
// offered. A limit of zero means no cap.
type cappedWriter struct {
	w         io.Writer
	remaining int64
	capped    bool
	unlimited bool
}

func newCappedWriter(w io.Writer, limit int64) *cappedWriter {
	return &cappedWriter{w: w, remaining: limit, unlimited: limit <= 0}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.unlimited {
		return c.w.Write(p)
	}
	if c.remaining <= 0 {
		c.capped = true
		return 0, errTunnelCapExceeded
	}

	// A write larger than what remains is the moment the cap bites: forward
	// the part that fits and stop. A write that exactly fills the remainder is
	// not capped, because nothing was turned away.
	over := int64(len(p)) > c.remaining
	if over {
		p = p[:c.remaining]
	}

	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	if over {
		c.capped = true
		return n, errTunnelCapExceeded
	}
	return n, nil
}

func (c *cappedWriter) exceeded() bool { return c.capped }

// idleClock is the shared activity timestamp for one tunnel. Both directions
// stamp it on every successful read, and both compute their deadline from it,
// so the tunnel expires only when nothing has moved either way.
type idleClock struct {
	idle time.Duration
	last atomic.Int64 // UnixNano of the last byte moved in either direction
}

func newIdleClock(idle time.Duration) *idleClock {
	c := &idleClock{idle: idle}
	c.last.Store(time.Now().UnixNano())
	return c
}

func (c *idleClock) touch() { c.last.Store(time.Now().UnixNano()) }

// deadline is when the tunnel should expire given the last activity on either
// side. It is always at least a moment in the future, so a direction that
// wakes just after the other one moved does not immediately time itself out.
func (c *idleClock) deadline() time.Time {
	return time.Unix(0, c.last.Load()).Add(c.idle)
}

// idleReader resets the connection's read deadline before every read, giving a
// true idle timeout on the tunnel as a whole. An absolute deadline would kill
// a long but healthy transfer, and a per-direction deadline would kill a
// download whose client has nothing to say.
type idleReader struct {
	r     io.Reader
	conn  net.Conn
	clock *idleClock
}

func (i *idleReader) Read(p []byte) (int, error) {
	for {
		if i.clock.idle > 0 {
			// A failure here means the connection is already gone, in which
			// case the Read below reports the real error.
			_ = i.conn.SetReadDeadline(i.clock.deadline())
		}

		n, err := i.r.Read(p)
		if n > 0 {
			i.clock.touch()
		}

		// A deadline set before a blocking read does not move when the other
		// direction becomes active, so a quiet side will wake up spuriously
		// during a busy transfer. If the shared clock has advanced past the
		// deadline we were waiting on, the tunnel is not idle: extend and keep
		// waiting rather than tearing it down.
		if n == 0 && i.clock.idle > 0 && isTimeout(err) && time.Now().Before(i.clock.deadline()) {
			continue
		}
		return n, err
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
