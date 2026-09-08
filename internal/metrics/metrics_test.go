package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRequestsCounterIsLabelledAndExported(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.Requests.WithLabelValues("allow", "gh", "http").Inc()
	m.Requests.WithLabelValues("deny", "", "connect").Inc()

	const want = `
# HELP egressgate_requests_total Proxy requests by decision, matched rule and request kind.
# TYPE egressgate_requests_total counter
egressgate_requests_total{decision="allow",kind="http",rule="gh"} 1
egressgate_requests_total{decision="deny",kind="connect",rule=""} 1
`
	if err := testutil.CollectAndCompare(reg, strings.NewReader(want), "egressgate_requests_total"); err != nil {
		t.Error(err)
	}
}

func TestBytesCounterTracksBothDirections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.Bytes.WithLabelValues("up").Add(100)
	m.Bytes.WithLabelValues("down").Add(250)

	if got := testutil.ToFloat64(m.Bytes.WithLabelValues("up")); got != 100 {
		t.Errorf("up = %v, want 100", got)
	}
	if got := testutil.ToFloat64(m.Bytes.WithLabelValues("down")); got != 250 {
		t.Errorf("down = %v, want 250", got)
	}
}

func TestTunnelsGaugeRisesAndFalls(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.Tunnels.Inc()
	m.Tunnels.Inc()
	m.Tunnels.Dec()

	if got := testutil.ToFloat64(m.Tunnels); got != 1 {
		t.Errorf("Tunnels = %v, want 1", got)
	}
}

func TestReloadsCounterSeparatesOutcomes(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.Reloads.WithLabelValues("ok").Inc()
	m.Reloads.WithLabelValues("error").Inc()
	m.Reloads.WithLabelValues("error").Inc()

	if got := testutil.ToFloat64(m.Reloads.WithLabelValues("error")); got != 2 {
		t.Errorf("error reloads = %v, want 2", got)
	}
}

func TestDurationHistogramObserves(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.Duration.WithLabelValues("http").Observe(0.25)

	if got := testutil.CollectAndCount(reg, "egressgate_request_duration_seconds"); got != 1 {
		t.Errorf("collected %d duration metrics, want 1", got)
	}
}

// Collectors must belong to the registry they are given, not to a package
// global. Two independent registries proves there is no shared state, which
// is what makes the whole thing testable in parallel.
func TestTwoRegistriesAreIndependent(t *testing.T) {
	regA, regB := prometheus.NewRegistry(), prometheus.NewRegistry()
	a, b := New(regA), New(regB)

	a.Requests.WithLabelValues("allow", "r", "http").Inc()

	if got := testutil.ToFloat64(a.Requests.WithLabelValues("allow", "r", "http")); got != 1 {
		t.Errorf("registry A count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(b.Requests.WithLabelValues("allow", "r", "http")); got != 0 {
		t.Errorf("registry B count = %v, want 0; the registries share state", got)
	}
}
