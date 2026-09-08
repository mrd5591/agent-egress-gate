package main

import (
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
)

const usage = `egressgate - deny-by-default egress control for headless coding agents

Usage:
  egressgate serve  --policy FILE [--listen ADDR] [--admin ADDR] [--audit FILE]
  egressgate verify --audit FILE
  egressgate check  --policy FILE METHOD URL

Commands:
  serve    Run the proxy. The data listener proxies agent traffic; the admin
           listener serves /metrics, /healthz, /readyz and POST /reload and
           must never be reachable by the agent.
  verify   Recompute an audit log's hash chain and report the first break.
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
	policyPath := fs.String("policy", "", "path to the policy file (required)")
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
	if *policyPath == "" {
		fmt.Fprintln(stderr, "egressgate: --policy is required")
		fs.Usage()
		return exitUsage
	}

	store, err := policy.LoadStore(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
		return exitFail
	}

	auditWriter := io.Writer(stdout)
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "egressgate: opening audit log: %v\n", err)
			return exitFail
		}
		defer f.Close()
		auditWriter = f
	}
	auditLog := audit.New(auditWriter)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := proxy.New(store, auditLog, m, proxy.Config{
		DialTimeout:           *dialTimeout,
		ResponseHeaderTimeout: *headerTimeout,
		IdleTimeout:           *idleTimeout,
		MaxTunnelBytes:        *maxTunnelBytes,
	}, logger)

	var serving bool
	admin := adminsrv.Handler(reg, m, store, func() bool { return serving })

	// Listeners are opened before either server starts so that a port
	// conflict is reported as a startup failure, and so that binding to port
	// 0 can be announced with the port actually chosen.
	dataLn, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: listening on %s: %v\n", *listenAddr, err)
		return exitFail
	}
	adminLn, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		dataLn.Close()
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

	serving = true
	fmt.Fprintf(stdout, "listening: proxy=%s admin=%s policy=%s\n",
		dataLn.Addr(), adminLn.Addr(), *policyPath)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "egressgate: server failed: %v\n", err)
			shutdown(dataSrv, adminSrv)
			return exitFail
		}
	case <-waitForStop(stop):
	}

	serving = false
	shutdown(dataSrv, adminSrv)

	head, seq := auditLog.Head()
	fmt.Fprintf(stdout, "audit chain head: %s after %d records\n", head, seq)
	fmt.Fprintln(stdout, "record that hash somewhere the gate cannot write, or truncation of the log is undetectable")
	return exitOK
}

// waitForStop returns a channel that closes on the injected stop signal, or
// on SIGINT/SIGTERM when none was injected.
func waitForStop(stop <-chan struct{}) <-chan struct{} {
	if stop != nil {
		return stop
	}
	ctx, cancel := signalContext()
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx.Done()
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
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *auditPath == "" {
		fmt.Fprintln(stderr, "egressgate: --audit is required")
		fs.Usage()
		return exitUsage
	}

	f, err := os.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "egressgate: %v\n", err)
		return exitFail
	}
	defer f.Close()

	res, err := audit.Verify(f)
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
// becomes a CONNECT with no method or path, because that is exactly what the
// gate will see. Modelling it any other way would let check report an allow
// the running gate then refuses.
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
