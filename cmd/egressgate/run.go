package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mrd5591/agent-egress-gate/internal/adminsrv"
	"github.com/mrd5591/agent-egress-gate/internal/audit"
	"github.com/mrd5591/agent-egress-gate/internal/metrics"
	"github.com/mrd5591/agent-egress-gate/internal/policy"
	"github.com/mrd5591/agent-egress-gate/internal/proxy"
)

// Exit codes. Two is reserved for usage errors so a shell script can tell
// "you called me wrong" from "the thing you asked about failed".
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
	// exitTruncated says a chain verifies but the file does not end where a
	// record ends: either the last line is torn, or it holds a record that
	// verifies and is missing only its newline.
	//
	// It is deliberately neither 0 nor 1. Not 0, because a gate wired to the
	// exit status would otherwise walk past a torn log without anyone reading
	// the message, and a tail removed on purpose is the one alteration this
	// chain cannot detect on its own. Not 1, because a crash-truncated log is
	// not a broken chain and a caller that tolerates one should not have to
	// tolerate the other. A CI job that accepts crash truncation can test for
	// this code specifically.
	exitTruncated = 3
)

const usage = `egressgate - deny-by-default egress control for headless coding agents

Usage:
  egressgate serve  --policy FILE [--listen ADDR] [--admin ADDR] [--audit FILE]
  egressgate verify --audit FILE [--min-records N] [--from-head HASH --from-seq N]
  egressgate check  --policy FILE METHOD URL

Commands:
  serve    Run the proxy. The data listener proxies agent traffic; the admin
           listener serves /metrics, /healthz, /readyz and POST /reload and
           must never be reachable by the agent.
  verify   Recompute an audit log's hash chain and report the first break.
           Exits 0 when the chain is intact and complete, 1 when it is broken,
           and 3 when it verifies but the file does not end at a record
           boundary, which a crash can cause and a deliberate truncation
           looks identical to.
           --min-records N fails a log that verifies but holds fewer than N
           records, so a caller reading the exit status can tell "nothing was
           recorded" from "everything verified".
           --from-head HASH and --from-seq N verify a rotated segment, whose
           chain continues an earlier file rather than starting at genesis.
  check    Ask what the policy would decide, without running anything.
           Exits 0 on allow and 1 on deny, so it works in a CI gate.
`

// run is the whole CLI. main is a thin wrapper so that every path here is
// reachable from a test without spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	return runWithStop(args, stdout, stderr, nil)
}

// runWithStop is run with an injectable shutdown signal. A nil stop channel
// means serve listens for SIGINT and SIGTERM instead.
func runWithStop(args []string, stdout, stderr io.Writer, stop <-chan struct{}) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stdout, stderr, stop)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "egressgate: unknown subcommand %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

// newFlagSet builds a flag set that reports errors to stderr rather than
// exiting the process, which would take the test binary with it.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func cmdServe(args []string, stdout, stderr io.Writer, stop <-chan struct{}) int {
	fs := newFlagSet("serve", stderr)
	policyPath := fs.String("policy", "", "path to the policy file")
	policyEnv := fs.String("policy-env", "",
		"name of an environment variable holding the policy YAML, instead of --policy")
	listenAddr := fs.String("listen", "127.0.0.1:8080", "data listener address for agent traffic")
	adminAddr := fs.String("admin", "127.0.0.1:9090", "admin listener address; never expose this to agents")
	auditPath := fs.String("audit", "", "path to append the audit log to; empty writes to stdout")
	dialTimeout := fs.Duration("dial-timeout", 10*time.Second, "upstream connect timeout")
	headerTimeout := fs.Duration("response-header-timeout", 30*time.Second, "upstream response header timeout")
	idleTimeout := fs.Duration("idle-timeout", 5*time.Minute, "close a tunnel after this long with no traffic")
	maxTunnelBytes := fs.Int64("max-tunnel-bytes", 0, "cap each direction of a tunnel; 0 means no cap")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	switch {
	case *policyPath == "" && *policyEnv == "":
		fmt.Fprintln(stderr, "egressgate: one of --policy or --policy-env is required")
		fs.Usage()
		return exitUsage
	case *policyPath != "" && *policyEnv != "":
		fmt.Fprintln(stderr, "egressgate: --policy and --policy-env are mutually exclusive")
		return exitUsage
	}

	// Reading the policy from the environment is what lets a container run the
	// binary directly, with no shell to materialise a file and no writable
	// root filesystem. A policy loaded this way has no source path, so
	// POST /reload correctly reports that there is nothing to reload from.
	var store *policy.Store
	var policySource string
	if *policyEnv != "" {
		raw, ok := os.LookupEnv(*policyEnv)
		if !ok || raw == "" {
			fmt.Fprintf(stderr, "egressgate: environment variable %s is unset or empty\n", *policyEnv)
			return exitFail
		}
		p, err := policy.Parse([]byte(raw))
		if err != nil {
			fmt.Fprintf(stderr, "egressgate: %v\n", err)
			return exitFail
		}
		store = policy.NewStore(p)
		policySource = "$" + *policyEnv
	} else {
		s, err := policy.LoadStore(*policyPath)
		if err != nil {
			fmt.Fprintf(stderr, "egressgate: %v\n", err)
			return exitFail
		}
		store = s
		policySource = *policyPath
	}

	// The audit sink defaults to stdout, so stdout must carry audit records
	// and nothing else. Every diagnostic below goes to stderr, or the verifier
	// this project exists to provide cannot read its own output.
	auditWriter := io.Writer(stdout)
	resumeHead, resumeSeq := audit.GenesisHash, uint64(0)

	if *auditPath != "" {
		head, seq, err := existingChainHead(*auditPath, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "egressgate: %v\n", err)
			return exitFail
		}
		resumeHead, resumeSeq = head, seq

		// #nosec G304 -- the audit path is an operator-supplied flag, not
		// anything a proxied request can influence.
		f, err := os.OpenFile(*auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "egressgate: opening audit log: %v\n", err)
			return exitFail
		}
		// A failed close on the audit log can mean records never reached the
		// disk, so it is reported rather than discarded.
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(stderr, "egressgate: closing audit log: %v\n", cerr)
			}
		}()
		auditWriter = f
	}

	// Resume rather than New, so a restart continues the existing chain. A new
	// chain in the same file would make every deploy look like tampering.
	auditLog := audit.Resume(auditWriter, resumeHead, resumeSeq)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := proxy.New(store, auditLog, m, proxy.Config{
		DialTimeout:           *dialTimeout,
		ResponseHeaderTimeout: *headerTimeout,
		IdleTimeout:           *idleTimeout,
		MaxTunnelBytes:        *maxTunnelBytes,
	}, logger)

	// Atomic because the admin server's goroutines read it while this one
	// writes it around startup and shutdown.
	var serving atomic.Bool
	admin := adminsrv.Handler(reg, m, store, serving.Load)

	// Listeners are opened before either server starts so that a port
	// conflict is reported as a startup failure, and so that binding to port
	// 0 can be announced with the port actually chosen.
	lc := &net.ListenConfig{}
	listenCtx := context.Background()

	dataLn, err := lc.Listen(listenCtx, "tcp", *listenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: listening on %s: %v\n", *listenAddr, err)
		return exitFail
	}
	adminLn, err := lc.Listen(listenCtx, "tcp", *adminAddr)
	if err != nil {
		_ = dataLn.Close()
		fmt.Fprintf(stderr, "egressgate: listening on %s: %v\n", *adminAddr, err)
		return exitFail
	}

	// ReadHeaderTimeout is set on both servers. Without it a client can hold
	// a connection open by dribbling headers, which is the slowloris attack
	// and also gosec G112.
	dataSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 20 * time.Second}
	adminSrv := &http.Server{Handler: admin, ReadHeaderTimeout: 20 * time.Second}

	errCh := make(chan error, 2)
	go func() { errCh <- dataSrv.Serve(dataLn) }()
	go func() { errCh <- adminSrv.Serve(adminLn) }()

	serving.Store(true)
	fmt.Fprintf(stderr, "listening: proxy=%s admin=%s policy=%s\n",
		dataLn.Addr(), adminLn.Addr(), policySource)

	stopCh, stopCancel := waitForStop(stop)
	defer stopCancel()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "egressgate: server failed: %v\n", err)
			shutdown(dataSrv, adminSrv)
			return exitFail
		}
	case <-stopCh:
	}

	serving.Store(false)
	shutdown(dataSrv, adminSrv)

	// Then the tunnels. http.Server.Shutdown deliberately does not wait on
	// hijacked connections, so at this point every CONNECT tunnel is still
	// running and none of them has written its record — a tunnel's record is
	// written when it closes. Reading the head before this would print a head
	// that the tunnels' own records then invalidate, and the tunnels open at
	// SIGTERM, which at the end of a CI job is all of them, would never appear
	// in the evidence at all.
	tunnelCtx, tunnelCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := handler.Shutdown(tunnelCtx); err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
	}
	tunnelCancel()

	head, seq := auditLog.Head()
	fmt.Fprintf(stderr, "audit chain head: %s after %d records\n", head, seq)
	fmt.Fprintln(stderr, "record that hash somewhere the gate cannot write, or truncation of the log is undetectable")
	return exitOK
}

// existingChainHead returns the head hash and last sequence number of an audit
// log that is already on disk, so a restart can continue its chain.
//
// It refuses to continue a chain that does not verify. Appending to a broken
// log would produce a file that can never verify again, and silently doing so
// is how a tamper-evident log becomes decoration.
//
// A torn final line is treated differently, and the difference matters. A
// process killed mid-write leaves an incomplete record; that is an interrupted
// write, not tampering. Refusing to start on it would turn one OOM kill into a
// permanent crash loop whose only remedy is editing the audit log, which is
// the very act the chain exists to make suspicious. So the gate resumes from
// the last complete record, says loudly that it discarded a partial one, and
// keeps running.
//
// A file missing only the newline after a record that verifies is a third
// thing again, and the one worth being careful about: it is what deleting one
// byte from a tampered log produces. Verify judges that record rather than
// assuming it, so tampering arrives here as a broken chain and is refused
// above, and the genuine case is repaired by adding the byte back. Discarding
// it as debris would have the gate destroy a verified record, and leave a log
// that verifies clean afterwards.
func existingChainHead(path string, stderr io.Writer) (string, uint64, error) {
	// #nosec G304 -- operator-supplied flag.
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return audit.GenesisHash, 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("reading existing audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	res, err := audit.Verify(f)
	if err != nil {
		return "", 0, fmt.Errorf("reading existing audit log: %w", err)
	}
	if !res.OK {
		return "", 0, fmt.Errorf(
			"refusing to append to %s: its chain is already broken at record %d (%s).\n"+
				"  This log cannot be made verifiable again by appending to it. Investigate the\n"+
				"  break, then point --audit at a new file to start a fresh chain; keep this one\n"+
				"  as the evidence it is",
			path, res.BreakAt, res.Problem)
	}
	if res.TruncatedTail {
		// The partial bytes must go before anything is appended, or the next
		// record lands on the end of the torn line and the log can never
		// verify again.
		dropped, terr := truncatePartialLine(path)
		if terr != nil {
			return "", 0, fmt.Errorf("discarding the partial final record of %s: %w", path, terr)
		}
		fmt.Fprintf(stderr,
			"egressgate: %s ended mid-record, so a previous run was killed while writing.\n"+
				"  Discarded %d bytes of a partial record and resumed from record %d; "+
				"the %d complete records verify.\n",
			path, dropped, res.LastSeq, res.Records)
	}
	if res.UnterminatedFinalRecord {
		// The opposite response to a file that looks the same from the outside,
		// which is why the two arrive as separate fields. Here the final record
		// decoded and verified and only its newline is missing, so truncating
		// back to the previous line would delete a complete record: the gate
		// erasing its own evidence to tidy up. The byte is added instead and
		// the record keeps its place in the chain.
		if aerr := appendMissingNewline(path); aerr != nil {
			return "", 0, fmt.Errorf("terminating the final record of %s: %w", path, aerr)
		}
		fmt.Fprintf(stderr,
			"egressgate: %s ended without the newline after record %d, so a previous run stopped\n"+
				"  between writing that record and terminating its line. The record itself verifies,\n"+
				"  so it was kept: appended the missing newline and resumed from it, with all %d\n"+
				"  records intact.\n",
			path, res.LastSeq, res.Records)
	}
	return res.Head, res.LastSeq, nil
}

// appendMissingNewline terminates a final line holding a complete, verified
// record. Appending the next record without it would put two records on one
// line, which the verifier reads as trailing bytes and refuses.
func appendMissingNewline(path string) error {
	// #nosec G304 -- operator-supplied flag, the same path already verified.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// truncatePartialLine cuts a file back to the end of its last complete line
// and reports how many bytes went. A file with no newline at all is emptied,
// which is correct: it holds one partial record and nothing else.
//
// It searches backwards in chunks rather than reading the file, because an
// audit log is append-only and can be large, and only its tail is in question.
func truncatePartialLine(path string) (int64, error) {
	// #nosec G304 -- operator-supplied flag, the same path already verified.
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	const chunk = 64 * 1024
	buf := make([]byte, chunk)

	for end := size; end > 0; {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		n := int(end - start)
		if _, err := f.ReadAt(buf[:n], start); err != nil && err != io.EOF {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			keep := start + int64(i) + 1
			if err := f.Truncate(keep); err != nil {
				return 0, err
			}
			return size - keep, nil
		}
		end = start
	}

	if err := f.Truncate(0); err != nil {
		return 0, err
	}
	return size, nil
}

// waitForStop returns a channel that closes on the injected stop signal, or on
// SIGINT/SIGTERM when none was injected, plus a cancel the caller must run.
//
// The cancel matters on the error path: if a server fails first, nothing else
// would ever unregister the signal handler or release its goroutine.
func waitForStop(stop <-chan struct{}) (<-chan struct{}, func()) {
	if stop != nil {
		return stop, func() {}
	}
	ctx, cancel := signalContext()
	return ctx.Done(), cancel
}

func shutdown(servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	auditPath := fs.String("audit", "", "path to the audit log (required)")
	minRecords := fs.Int("min-records", 0,
		"fail unless the log holds at least this many records; 0 accepts an empty log")
	fromHead := fs.String("from-head", "",
		"chain head this log continues from, for a rotated segment; empty means the log starts at genesis")
	fromSeq := fs.Uint64("from-seq", 0,
		"sequence number the previous segment ended on; used with --from-head")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *auditPath == "" {
		fmt.Fprintln(stderr, "egressgate: --audit is required")
		fs.Usage()
		return exitUsage
	}
	if *minRecords < 0 {
		fmt.Fprintln(stderr, "egressgate: --min-records cannot be negative")
		return exitUsage
	}
	// A sequence number without a head cannot be checked against anything: the
	// chain would be verified from genesis while the sequence started
	// elsewhere, which is a shape no writer produces. Saying so beats
	// verifying something the caller did not mean.
	if *fromHead == "" && *fromSeq != 0 {
		fmt.Fprintln(stderr, "egressgate: --from-seq needs --from-head; a sequence offset without a head verifies nothing")
		return exitUsage
	}

	// #nosec G304 -- the audit path is an operator-supplied flag.
	f, err := os.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
		return exitFail
	}
	defer func() { _ = f.Close() }()

	res, err := audit.VerifyFrom(f, *fromHead, *fromSeq)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
		return exitFail
	}

	if !res.OK {
		fmt.Fprintf(stdout, "chain BROKEN at record %d: %s\n", res.BreakAt, res.Problem)
		fmt.Fprintf(stdout, "%d records verified before the break\n", res.Records)
		return exitFail
	}

	fmt.Fprintf(stdout, "chain intact: %d records\n", res.Records)
	fmt.Fprintf(stdout, "head: %s\n", res.Head)

	// A log that verifies and holds nothing is the vacuous green: "chain
	// intact: 0 records" exits 0, so a caller wired to the exit status cannot
	// tell "nothing was recorded" from "everything verified". Where the caller
	// knows traffic should have happened, --min-records is how it says so.
	// This is checked before the truncation notes because a log too short to
	// be evidence is a failure whatever shape its tail has.
	if res.Records < *minRecords {
		fmt.Fprintf(stdout,
			"FAIL: %d records, but --min-records %d was required.\n"+
				"  The chain verifies; there is just not enough of it. Either the gate saw no\n"+
				"  traffic, or it was never in the path of the traffic it was supposed to gate.\n",
			res.Records, *minRecords)
		return exitFail
	}
	if res.TruncatedTail {
		// The chain holds, but it stops mid-record, and a chain cannot tell a
		// crash-truncated tail from one someone removed. That is the gap the
		// recorded head exists to close, so this is exactly the moment to
		// point at it.
		fmt.Fprintln(stdout,
			"note: the log ends mid-record, so the last write was interrupted.\n"+
				"  Every complete record verifies and the partial one is not counted. A chain\n"+
				"  cannot distinguish this from a tail someone removed, so compare the head above\n"+
				"  against the one the gate printed when it shut down.")
		return exitTruncated
	}
	if res.UnterminatedFinalRecord {
		// Not exit 0, which claims a log that is intact and complete: this one
		// does not end at a record boundary. Every record is counted, because
		// the last one decoded and verified rather than being assumed to be
		// debris, but a file the writer never finished terminating is still a
		// file whose end nobody can vouch for, and it shares its exit code
		// with the torn case for that reason. What it does not share is the
		// remedy, so the note says which one this is.
		fmt.Fprintln(stdout,
			"note: the final record is complete and verifies, but its newline is missing,\n"+
				"  so the last write stopped one byte short. Every record above is counted. A\n"+
				"  chain cannot distinguish this from a file someone truncated at that exact\n"+
				"  offset, so compare the head above against the one the gate printed when it\n"+
				"  shut down; the gate itself appends the newline and keeps the record.")
		return exitTruncated
	}
	return exitOK
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("check", stderr)
	policyPath := fs.String("policy", "", "path to the policy file (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "egressgate: --policy is required")
		fs.Usage()
		return exitUsage
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "egressgate: check needs a METHOD and a URL, for example: check --policy p.yaml GET https://pypi.org/simple/")
		return exitUsage
	}

	method := strings.ToUpper(fs.Arg(0))
	raw := fs.Arg(1)

	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		fmt.Fprintf(stderr, "egressgate: %q is not an absolute URL\n", raw)
		return exitUsage
	}

	store, err := policy.LoadStore(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
		return exitFail
	}

	req := requestFor(u, method)

	// The proxy refuses a non-normalising path with 400 before it consults the
	// policy at all, so check has to do the same, in the same order, using the
	// same code. It used to skip this and report the policy's answer, which
	// meant `check GET http://h/allowed/../secret` said allow for a request
	// the running gate rejects outright - the one direction check promises
	// never to be wrong in.
	//
	// Only the plain-HTTP path has a path to normalise. A CONNECT tunnel
	// carries no path, and requestFor has already modelled an https URL as
	// one, so there is nothing to check there.
	if req.Kind == policy.KindHTTP {
		if norm, ok := proxy.NormalisedPath(u); !ok {
			fmt.Fprintf(stdout, "%s %s\n", method, raw)
			fmt.Fprintf(stdout, "  evaluated as: plain HTTP request to %s:%d\n", req.Host, req.Port)
			fmt.Fprintf(stdout, "  decision:     refused\n")
			fmt.Fprintf(stdout,
				"  reason:       path %q contains dot-segments or encoded separators; it\n"+
					"                normalises to %q, so a path rule could not be enforced on\n"+
					"                what the upstream would route. The gate answers 400 without\n"+
					"                consulting the policy.\n",
				u.Path, norm)
			return exitFail
		}
	}

	decision := store.Evaluate(req)

	kind := "plain HTTP request"
	if req.Kind == policy.KindConnect {
		kind = "CONNECT tunnel"
	}
	fmt.Fprintf(stdout, "%s %s\n", method, raw)
	fmt.Fprintf(stdout, "  evaluated as: %s to %s:%d\n", kind, req.Host, req.Port)
	fmt.Fprintf(stdout, "  decision:     %s\n", decision.Action)
	if decision.Rule != "" {
		fmt.Fprintf(stdout, "  rule:         %s\n", decision.Rule)
	}
	fmt.Fprintf(stdout, "  reason:       %s\n", decision.Reason)

	if decision.Action == policy.Allow {
		return exitOK
	}
	return exitFail
}

// requestFor turns a URL into the question the proxy would ask. An https URL
// becomes a CONNECT with no method or path, because that is what the gate sees
// from any ordinary client. Modelling it another way would let check report an
// allow the running gate then refuses.
//
// The approximation errs on the conservative side, and that is not free. A
// client sending an https URL in absolute form straight to the data port takes
// the plain-HTTP path, where method and path are visible and therefore
// enforceable, and can be allowed where check said deny. No proxy-configured
// client does that. The guarantee check offers is one-directional: it never
// promises an allow the gate would refuse, but it may refuse one the gate
// would allow.
func requestFor(u *url.URL, method string) policy.Request {
	host := u.Hostname()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	if u.Scheme == "https" {
		return policy.Request{Kind: policy.KindConnect, Host: host, Port: port}
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	return policy.Request{
		Kind:   policy.KindHTTP,
		Host:   host,
		Port:   port,
		Method: method,
		Path:   path,
	}
}
