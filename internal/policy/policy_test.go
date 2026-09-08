package policy

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return p
}

const sample = `
version: 1
default: deny
rules:
  - name: gh
    hosts: ["api.github.com"]
    methods: ["GET"]
    paths: ["/repos/"]
  - name: registries
    hosts: ["pypi.org", "*.pypi.org"]
  - name: internal
    hosts: ["metrics.internal"]
    ports: [9090]
`

func TestEvaluate(t *testing.T) {
	p := mustParse(t, sample)

	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{
			name: "http allowed on exact host, method and path prefix",
			req:  Request{Kind: KindHTTP, Host: "api.github.com", Port: 443, Method: "GET", Path: "/repos/x"},
			want: Decision{Action: Allow, Rule: "gh", Reason: "matched rule gh"},
		},
		{
			name: "http denied when method not listed",
			req:  Request{Kind: KindHTTP, Host: "api.github.com", Port: 443, Method: "DELETE", Path: "/repos/x"},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
		{
			name: "http denied when path prefix does not match",
			req:  Request{Kind: KindHTTP, Host: "api.github.com", Port: 443, Method: "GET", Path: "/orgs/x"},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
		{
			name: "http host match is case insensitive",
			req:  Request{Kind: KindHTTP, Host: "API.GitHub.COM", Port: 443, Method: "GET", Path: "/repos/x"},
			want: Decision{Action: Allow, Rule: "gh", Reason: "matched rule gh"},
		},
		{
			name: "connect refused for a rule that constrains method or path",
			req:  Request{Kind: KindConnect, Host: "api.github.com", Port: 443},
			want: Decision{
				Action: Deny,
				Reason: "rule gh matched host but constrains method or path, which cannot be enforced inside a tunnel",
			},
		},
		{
			name: "connect allowed for a host-only rule",
			req:  Request{Kind: KindConnect, Host: "pypi.org", Port: 443},
			want: Decision{Action: Allow, Rule: "registries", Reason: "matched rule registries"},
		},
		{
			name: "wildcard matches a subdomain",
			req:  Request{Kind: KindConnect, Host: "files.pypi.org", Port: 443},
			want: Decision{Action: Allow, Rule: "registries", Reason: "matched rule registries"},
		},
		{
			name: "wildcard matches a multi-label subdomain",
			req:  Request{Kind: KindConnect, Host: "a.b.pypi.org", Port: 443},
			want: Decision{Action: Allow, Rule: "registries", Reason: "matched rule registries"},
		},
		{
			name: "wildcard does not match a host that merely ends with the string",
			req:  Request{Kind: KindConnect, Host: "evilpypi.org", Port: 443},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
		{
			name: "unlisted host is denied",
			req:  Request{Kind: KindConnect, Host: "evil.com", Port: 443},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
		{
			name: "non-default port denied when the rule lists no ports",
			req:  Request{Kind: KindConnect, Host: "pypi.org", Port: 8443},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
		{
			name: "port 80 is allowed by default alongside 443",
			req:  Request{Kind: KindHTTP, Host: "pypi.org", Port: 80, Method: "GET", Path: "/simple/"},
			want: Decision{Action: Allow, Rule: "registries", Reason: "matched rule registries"},
		},
		{
			name: "explicit port list replaces the default pair",
			req:  Request{Kind: KindConnect, Host: "metrics.internal", Port: 9090},
			want: Decision{Action: Allow, Rule: "internal", Reason: "matched rule internal"},
		},
		{
			name: "explicit port list excludes 443",
			req:  Request{Kind: KindConnect, Host: "metrics.internal", Port: 443},
			want: Decision{Action: Deny, Reason: "no rule matched"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Evaluate(tc.req)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// A tunnel-ineligible rule must not shadow a later rule that does allow the
// host. Reporting the near miss is useful; letting it end evaluation is a bug.
func TestEvaluateContinuesPastATunnelIneligibleRule(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - name: constrained
    hosts: ["shared.example.com"]
    methods: ["GET"]
  - name: open
    hosts: ["shared.example.com"]
`)
	got := p.Evaluate(Request{Kind: KindConnect, Host: "shared.example.com", Port: 443})
	want := Decision{Action: Allow, Rule: "open", Reason: "matched rule open"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluateWithDefaultAllow(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault: allow\nrules: []\n")
	got := p.Evaluate(Request{Kind: KindConnect, Host: "anything.example.com", Port: 443})
	want := Decision{Action: Allow, Reason: "default action is allow"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseNormalisesCase(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - name: mixed
    hosts: ["API.Example.COM"]
    methods: ["get"]
`)
	if got := p.Rules[0].Hosts[0]; got != "api.example.com" {
		t.Errorf("host = %q, want lower-cased", got)
	}
	if got := p.Rules[0].Methods[0]; got != "GET" {
		t.Errorf("method = %q, want upper-cased", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{"not yaml", "\tthis: [is: not", "parse policy"},
		{"missing version", "default: deny\nrules: []\n", "version must be 1"},
		{"wrong version", "version: 2\ndefault: deny\nrules: []\n", "version must be 1"},
		{"missing default", "version: 1\nrules: []\n", `default must be "allow" or "deny"`},
		{"unknown default", "version: 1\ndefault: maybe\nrules: []\n", `default must be "allow" or "deny"`},
		{"rule without name", "version: 1\ndefault: deny\nrules:\n  - hosts: [\"a.com\"]\n", "rule 0: name is required"},
		{
			"duplicate rule name",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n  - name: a\n    hosts: [\"b.com\"]\n",
			`duplicate rule name "a"`,
		},
		{"rule without hosts", "version: 1\ndefault: deny\nrules:\n  - name: a\n", `rule "a": at least one host is required`},
		{"empty host", "version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"\"]\n", `rule "a": empty host`},
		{
			"wildcard not leading",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.*.com\"]\n",
			`rule "a": host "a.*.com": wildcard is only supported as a leading "*." label`,
		},
		{
			"bare wildcard",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"*\"]\n",
			`rule "a": host "*": wildcard is only supported as a leading "*." label`,
		},
		{
			"wildcard with no suffix",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"*.\"]\n",
			`rule "a": host "*.": wildcard needs a domain after it`,
		},
		{
			"path without leading slash",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    paths: [\"repos\"]\n",
			`rule "a": path "repos" must start with "/"`,
		},
		{
			"port too low",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    ports: [0]\n",
			`rule "a": port 0 out of range`,
		},
		{
			"port too high",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    ports: [70000]\n",
			`rule "a": port 70000 out of range`,
		},
		{
			"unknown method",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    methods: [\"FETCH\"]\n",
			`rule "a": unknown method "FETCH"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("Parse() error = nil, want one containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Parse() error = %q, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseAcceptsAKnownGoodPolicy(t *testing.T) {
	p := mustParse(t, sample)
	if p.Version != 1 {
		t.Errorf("Version = %d, want 1", p.Version)
	}
	if p.Default != Deny {
		t.Errorf("Default = %q, want deny", p.Default)
	}
	if len(p.Rules) != 3 {
		t.Fatalf("len(Rules) = %d, want 3", len(p.Rules))
	}
}
