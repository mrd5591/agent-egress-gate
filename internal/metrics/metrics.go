// Package metrics holds the Prometheus collectors the gate exports.
//
// New takes the registry to register into rather than using the default
// registerer. Package-level collectors are convenient right up to the point
// where two tests run in the same binary, and then they are a permanent
// source of flakes.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics is the gate's instrument panel.
type Metrics struct {
	// Requests counts every decision, allowed or denied. The rule label is
	// empty on a denial, which is what makes deny-by-rule and deny-by-default
	// distinguishable on a dashboard.
	Requests *prometheus.CounterVec
	// Duration measures wall time per request, split by kind. A tunnel's
	// duration is its whole lifetime, so treat the two kinds separately.
	Duration *prometheus.HistogramVec
	// Bytes counts payload moved, labelled "up" (client to upstream) and
	// "down".
	Bytes *prometheus.CounterVec
	// Tunnels is the number of CONNECT tunnels currently open.
	Tunnels prometheus.Gauge
	// Reloads counts policy reload attempts by outcome. A rising error count
	// means the running policy is older than the file on disk.
	Reloads *prometheus.CounterVec
}

// New builds and registers the collectors on the given registry.
func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		Requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "egressgate_requests_total",
			Help: "Proxy requests by decision, matched rule and request kind.",
		}, []string{"decision", "rule", "kind"}),

		Duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "egressgate_request_duration_seconds",
			Help:    "Time from request received to response or tunnel close, by kind.",
			Buckets: prometheus.DefBuckets,
		}, []string{"kind"}),

		Bytes: f.NewCounterVec(prometheus.CounterOpts{
			Name: "egressgate_bytes_total",
			Help: "Payload bytes proxied, by direction.",
		}, []string{"direction"}),

		Tunnels: f.NewGauge(prometheus.GaugeOpts{
			Name: "egressgate_active_tunnels",
			Help: "CONNECT tunnels currently open.",
		}),

		Reloads: f.NewCounterVec(prometheus.CounterOpts{
			Name: "egressgate_policy_reloads_total",
			Help: "Policy reload attempts by outcome.",
		}, []string{"result"}),
	}
}
