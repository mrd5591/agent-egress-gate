// Package adminsrv serves the gate's control plane: metrics, health,
// readiness and policy reload.
//
// It is a separate handler from the proxy because it must be bound to a
// separate listener. Exposing a reload endpoint on the same port an agent
// talks to would let the agent reload, or at minimum probe, the policy that
// constrains it. Keeping the two planes apart is the reason this package
// exists at all.
package adminsrv

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mrd5591/agent-egress-gate/internal/metrics"
)

// Reloader is the part of the policy store the admin plane needs.
type Reloader interface {
	// Reload replaces the policy from the given path, leaving the previous
	// one in force on failure.
	Reload(path string) error
	// Source is the path the policy was loaded from, empty if it was not
	// loaded from a file.
	Source() string
}

// Handler builds the admin mux. It returns a handler rather than a running
// server so that tests exercise the routes without binding a port.
//
// ready reports whether the gate is serving; it is separate from health so an
// orchestrator can tell "starting up" from "broken".
func Handler(reg *prometheus.Registry, m *metrics.Metrics, r Reloader, ready func() bool) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})

	mux.HandleFunc("/reload", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "reload requires POST", http.StatusMethodNotAllowed)
			return
		}
		source := r.Source()
		if source == "" {
			http.Error(w, "no policy file to reload from", http.StatusBadRequest)
			return
		}
		if err := r.Reload(source); err != nil {
			m.Reloads.WithLabelValues("error").Inc()
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		m.Reloads.WithLabelValues("ok").Inc()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "reloaded %s\n", source)
	})

	return mux
}
