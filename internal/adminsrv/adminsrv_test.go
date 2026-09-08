package adminsrv

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mrd5591/agent-egress-gate/internal/metrics"
)

type fakeReloader struct {
	source string
	err    error
	calls  int
}

func (f *fakeReloader) Reload(string) error {
	f.calls++
	return f.err
}

func (f *fakeReloader) Source() string { return f.source }

func newTestHandler(t *testing.T, r Reloader, ready func() bool) (http.Handler, *prometheus.Registry, *metrics.Metrics) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	return Handler(reg, m, r, ready), reg, m
}

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealthzIsAlwaysOK(t *testing.T) {
	h, _, _ := newTestHandler(t, &fakeReloader{}, func() bool { return false })
	rec := do(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 even when not ready", rec.Code)
	}
}

func TestReadyzReflectsTheReadyFunc(t *testing.T) {
	ready := false
	h, _, _ := newTestHandler(t, &fakeReloader{}, func() bool { return ready })

	if rec := do(t, h, http.MethodGet, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 before ready", rec.Code)
	}
	ready = true
	if rec := do(t, h, http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 once ready", rec.Code)
	}
}

func TestMetricsExposesTheRegistry(t *testing.T) {
	h, _, m := newTestHandler(t, &fakeReloader{}, func() bool { return true })
	m.Requests.WithLabelValues("allow", "r", "http").Inc()

	rec := do(t, h, http.MethodGet, "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "egressgate_requests_total") {
		t.Errorf("body does not contain the gate's metrics:\n%s", body)
	}
}

func TestReloadRequiresPOST(t *testing.T) {
	r := &fakeReloader{source: "/etc/policy.yaml"}
	h, _, _ := newTestHandler(t, r, func() bool { return true })

	rec := do(t, h, http.MethodGet, "/reload")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 for GET", rec.Code)
	}
	if r.calls != 0 {
		t.Errorf("Reload called %d times on a GET, want 0", r.calls)
	}
}

func TestReloadOnSuccess(t *testing.T) {
	r := &fakeReloader{source: "/etc/policy.yaml"}
	h, reg, _ := newTestHandler(t, r, func() bool { return true })

	rec := do(t, h, http.MethodPost, "/reload")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if r.calls != 1 {
		t.Errorf("Reload called %d times, want 1", r.calls)
	}
	if got := testutil.CollectAndCount(reg, "egressgate_policy_reloads_total"); got != 1 {
		t.Errorf("reload counter series = %d, want 1", got)
	}
}

func TestReloadReportsAFailureAndCountsIt(t *testing.T) {
	r := &fakeReloader{source: "/etc/policy.yaml", err: errors.New("bad yaml at line 3")}
	h, _, m := newTestHandler(t, r, func() bool { return true })

	rec := do(t, h, http.MethodPost, "/reload")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "bad yaml at line 3") {
		t.Errorf("body = %q, want the underlying error", body)
	}
	if got := testutil.ToFloat64(m.Reloads.WithLabelValues("error")); got != 1 {
		t.Errorf("error reload count = %v, want 1", got)
	}
}

// Reload with nothing to reload from is a configuration error, not a crash.
func TestReloadWithNoSourceIsRejected(t *testing.T) {
	r := &fakeReloader{source: ""}
	h, _, _ := newTestHandler(t, r, func() bool { return true })

	rec := do(t, h, http.MethodPost, "/reload")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when no policy file backs the store", rec.Code)
	}
	if r.calls != 0 {
		t.Errorf("Reload called %d times, want 0", r.calls)
	}
}

func TestUnknownAdminPathIs404(t *testing.T) {
	h, _, _ := newTestHandler(t, &fakeReloader{}, func() bool { return true })
	if rec := do(t, h, http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
