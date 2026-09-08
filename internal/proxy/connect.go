package proxy

import (
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
	defer upstream.Close()

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
	defer clientConn.Close()

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

	// The client's read side is the buffered reader, so bytes that arrived
	// with the CONNECT request are not lost. Deadlines are still set on the
	// underlying connection, which is what the reader ultimately draws from.
	clientSrc := &idleReader{r: buffered, conn: clientConn, idle: h.cfg.IdleTimeout}
	upstreamSrc := &idleReader{r: upstream, conn: upstream, idle: h.cfg.IdleTimeout}

	var limitUp, limitDown io.Reader = clientSrc, upstreamSrc
	if h.cfg.MaxTunnelBytes > 0 {
		limitUp = io.LimitReader(clientSrc, h.cfg.MaxTunnelBytes)
		limitDown = io.LimitReader(upstreamSrc, h.cfg.MaxTunnelBytes)
	}

	done := make(chan struct{}, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			clientConn.Close()
			upstream.Close()
		})
	}

	go func() {
		n, _ := io.Copy(upstream, limitUp)
		atomic.StoreInt64(&upBytes, n)
		if h.cfg.MaxTunnelBytes > 0 && n >= h.cfg.MaxTunnelBytes {
			cappedFlag.Store(true)
		}
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(clientConn, limitDown)
		atomic.StoreInt64(&downBytes, n)
		if h.cfg.MaxTunnelBytes > 0 && n >= h.cfg.MaxTunnelBytes {
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
		// Anything else is malformed.
		if addrErr, ok := splitErr.(*net.AddrError); ok && addrErr.Err == "missing port in address" {
			return authority, 443, nil
		}
		return "", 0, fmt.Errorf("malformed CONNECT authority %q", authority)
	}

	n, convErr := strconv.Atoi(p)
	if convErr != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("malformed port in CONNECT authority %q", authority)
	}
	return h, n, nil
}

// idleReader resets the connection's read deadline before every read, giving
// a true idle timeout. An absolute deadline would kill a long but healthy
// transfer; this only kills a silent one.
type idleReader struct {
	r    io.Reader
	conn net.Conn
	idle time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	if i.idle > 0 {
		// A failure here means the connection is already gone, in which case
		// the Read below reports the real error.
		_ = i.conn.SetReadDeadline(time.Now().Add(i.idle))
	}
	return i.r.Read(p)
}
