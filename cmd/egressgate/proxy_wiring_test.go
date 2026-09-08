package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fieldFrom pulls a key=value field out of the startup line.
func fieldFrom(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, prefix); ok {
				return v
			}
		}
	}
	t.Fatalf("no %s field in:\n%s", prefix, out)
	return ""
}

// policyForUpstream writes a policy allowing exactly the host and port of an
// httptest server, which binds an ephemeral port outside the default pair.
func policyForUpstream(t *testing.T, dir, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	body := "version: 1\ndefault: deny\nrules:\n" +
		"  - name: up\n" +
		"    hosts: [\"" + u.Hostname() + "\"]\n" +
		"    ports: [" + u.Port() + "]\n"
	return writeFile(t, dir, "policy.yaml", body)
}

// The CLI's own wiring between run.go and the proxy package was otherwise
// only covered by the admin endpoints, which do not touch the data path.
func TestServeActuallyProxiesTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream reached")
	}))
	defer upstream.Close()

	dir := t.TempDir()
	policyPath := policyForUpstream(t, dir, upstream.URL)
	auditPath := filepath.Join(dir, "audit.log")

	_, stderr, _, stop := startServe(t,
		"serve", "--policy", policyPath, "--listen", "127.0.0.1:0",
		"--admin", "127.0.0.1:0", "--audit", auditPath)

	proxyAddr := fieldFrom(t, stderr.String(), "proxy=")
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "upstream reached" {
		t.Errorf("proxied body = %q, want %q", body, "upstream reached")
	}

	if code := stop(); code != 0 {
		t.Errorf("exit = %d; stderr = %s", code, stderr.String())
	}

	logged, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), `"decision":"allow"`) {
		t.Errorf("audit log has no record of the proxied request:\n%s", logged)
	}
}

// A policy supplied through the environment is what lets the container run
// the binary directly, with no shell and no writable filesystem.
func TestServeAcceptsAPolicyFromTheEnvironment(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "env policy works")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EGRESSGATE_TEST_POLICY",
		"version: 1\ndefault: deny\nrules:\n  - name: up\n    hosts: [\""+u.Hostname()+"\"]\n    ports: ["+u.Port()+"]\n")

	_, stderr, adminAddr, stop := startServe(t,
		"serve", "--policy-env", "EGRESSGATE_TEST_POLICY",
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")

	proxyAddr := fieldFrom(t, stderr.String(), "proxy=")
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "env policy works" {
		t.Errorf("proxied body = %q", body)
	}

	// A policy with no file behind it cannot be reloaded, and the admin plane
	// should say so rather than pretend.
	reload, err := http.Post("http://"+adminAddr+"/reload", "", nil)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	io.Copy(io.Discard, reload.Body)
	reload.Body.Close()
	if reload.StatusCode != http.StatusBadRequest {
		t.Errorf("reload status = %d, want 400 for an environment-supplied policy", reload.StatusCode)
	}

	if code := stop(); code != 0 {
		t.Errorf("exit = %d", code)
	}
}

func TestServeRejectsBothPolicySources(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "policy.yaml", testPolicy)
	t.Setenv("EGRESSGATE_TEST_POLICY", testPolicy)

	code, _, errOut := runCLI(t, "serve", "--policy", p, "--policy-env", "EGRESSGATE_TEST_POLICY",
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "mutually exclusive") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestServeRejectsAnUnsetPolicyEnvironmentVariable(t *testing.T) {
	code, _, errOut := runCLI(t, "serve", "--policy-env", "EGRESSGATE_DEFINITELY_UNSET",
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "unset or empty") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestServeRejectsAnInvalidPolicyFromTheEnvironment(t *testing.T) {
	t.Setenv("EGRESSGATE_TEST_POLICY", "version: 99\ndefault: deny\nrules: []\n")
	code, _, errOut := runCLI(t, "serve", "--policy-env", "EGRESSGATE_TEST_POLICY",
		"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "version") {
		t.Errorf("stderr = %q", errOut)
	}
}
