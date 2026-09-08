package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
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
		{
			"mistyped rule field",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    path: [\"/x\"]\n",
			"field path not found",
		},
		{
			"mistyped top-level field",
			"version: 1\ndefalt: deny\nrules: []\n",
			"field defalt not found",
		},
		{
			"explicitly empty paths",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    paths: []\n",
			`rule "a": paths is written but empty`,
		},
		{
			"explicitly empty methods",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    methods: []\n",
			`rule "a": methods is written but empty`,
		},
		{
			"explicitly empty ports",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    ports: []\n",
			`rule "a": ports is written but empty`,
		},
		{
			"explicitly empty hosts",
			"version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: []\n",
			`rule "a": at least one host is required`,
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

// A mistyped constraint key must not promote a rule to tunnel-eligible.
//
// Before strict parsing, this policy loaded clean and
// Evaluate(CONNECT m.internal:443) returned
//
//	{Action:allow Rule:m Reason:matched rule m}
//
// The operator wrote a rule they believed was pinned to GET /v1/status and got
// a full HTTPS tunnel to the host, which is the exact failure the CONNECT rule
// exists to prevent. The keys are dropped by the YAML decoder, so nothing
// downstream can notice: validate only sees a host-only rule.
func TestAMistypedConstraintKeyIsRejectedRatherThanOpeningATunnel(t *testing.T) {
	src := `
version: 1
default: deny
rules:
  - name: m
    hosts: ["m.internal"]
    method: ["GET"]
    path: ["/v1/status"]
`
	p, err := Parse([]byte(src))
	if err == nil {
		got := p.Evaluate(Request{Kind: KindConnect, Host: "m.internal", Port: 443})
		t.Fatalf("Parse() error = nil; CONNECT evaluates to %+v, so a typo opened a tunnel", got)
	}
	for _, want := range []string{"method", "path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Parse() error = %q, want it to name the unknown field %q", err, want)
		}
	}
}

// The policy is one document. yaml.Unmarshal parses only the first and drops
// the rest without a word, so a file whose rules live after a "---" loads as a
// policy the operator never wrote.
func TestParseRejectsASecondDocument(t *testing.T) {
	src := "version: 1\ndefault: deny\nrules: []\n---\nversion: 1\ndefault: allow\nrules: []\n"
	if _, err := Parse([]byte(src)); err == nil {
		t.Fatal("Parse() error = nil, want a rejection of the trailing document")
	} else if !strings.Contains(err.Error(), "single YAML document") {
		t.Errorf("Parse() error = %q, want one mentioning a single YAML document", err)
	}
}

// An empty document must keep failing on the missing version rather than on
// the decoder's EOF: "version must be 1, got 0" tells an operator what to
// write, and "EOF" does not.
func TestParseReportsAnEmptyDocumentAsAMissingVersion(t *testing.T) {
	for _, src := range []string{"", "\n", "# only a comment\n"} {
		_, err := Parse([]byte(src))
		if err == nil {
			t.Fatalf("Parse(%q) error = nil, want one", src)
		}
		if !strings.Contains(err.Error(), "version must be 1") {
			t.Errorf("Parse(%q) error = %q, want one containing %q", src, err, "version must be 1")
		}
	}
}

// A path prefix matches on segment boundaries. An unanchored prefix hands the
// rule endpoints the operator never listed: "/v1/status" would also cover
// "/v1/status-admin" and "/v1/statuses/all", which are different endpoints
// that merely start with the same characters.
func TestPathPrefixMatchesOnSegmentBoundaries(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - name: status
    hosts: ["a.internal"]
    methods: ["GET"]
    paths: ["/v1/status", "/repos/"]
`)
	cases := []struct {
		path string
		want Action
	}{
		{"/v1/status", Allow},
		{"/v1/status/", Allow},
		{"/v1/status/detail", Allow},
		{"/v1/status-admin", Deny},
		{"/v1/statuses/all", Deny},
		{"/v1/statusadmin", Deny},
		// A prefix written with a trailing slash already names the boundary,
		// so it keeps behaving exactly as before.
		{"/repos/x", Allow},
		{"/repos", Deny},
		{"/reposx", Deny},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := p.Evaluate(Request{Kind: KindHTTP, Host: "a.internal", Port: 80, Method: "GET", Path: tc.path})
			if got.Action != tc.want {
				t.Errorf("Evaluate(%q).Action = %q, want %q (reason %q)", tc.path, got.Action, tc.want, got.Reason)
			}
		})
	}
}

// The wildcard stands for one or more real labels. An empty label is not a
// name any resolver will answer, and accepting it means "*.example.com"
// matches "..example.com".
func TestWildcardRequiresANonEmptyLabel(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault: deny\nrules:\n  - name: w\n    hosts: [\"*.example.com\"]\n")
	for _, host := range []string{"..example.com", "a..example.com", ".example.com"} {
		got := p.Evaluate(Request{Kind: KindConnect, Host: host, Port: 443})
		if got.Action != Deny {
			t.Errorf("Evaluate(host=%q).Action = %q, want deny", host, got.Action)
		}
	}
	// The documented contract is unchanged.
	for _, host := range []string{"a.example.com", "a.b.example.com"} {
		if got := p.Evaluate(Request{Kind: KindConnect, Host: host, Port: 443}); got.Action != Allow {
			t.Errorf("Evaluate(host=%q).Action = %q, want allow", host, got.Action)
		}
	}
}

// The distinction between an absent key and an explicit empty list is the
// whole basis for rejecting the latter, and it is a property of the YAML
// decoder rather than of this package. Pin it, so an upgrade that changes it
// fails here instead of quietly re-opening the hole.
func TestTheDecoderDistinguishesAnAbsentKeyFromAnEmptyList(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n")
	if p.Rules[0].Paths != nil {
		t.Errorf("absent paths = %#v, want nil", p.Rules[0].Paths)
	}

	var raw Policy
	src := "version: 1\ndefault: deny\nrules:\n  - name: a\n    hosts: [\"a.com\"]\n    paths: []\n"
	if err := yaml.Unmarshal([]byte(src), &raw); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if raw.Rules[0].Paths == nil {
		t.Error("explicit empty paths decoded to nil, so it cannot be told from an absent key")
	}
}

// Both shipped policies must survive strict parsing. They are what an operator
// starts from, and the deployed Terraform ships one of them verbatim.
func TestShippedExamplePoliciesParse(t *testing.T) {
	for _, path := range []string{"../../policy.example.yaml", "../../terraform/example/policy.yaml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			if _, err := Parse(data); err != nil {
				t.Fatalf("Parse(%s) error = %v", path, err)
			}
		})
	}
}

// A leading "---" opens the first document rather than adding a second, and
// a trailing "..." closes one rather than opening one. Hand-written YAML
// carries both, and the single-document check must not mistake either for a
// policy split in two.
func TestParseAcceptsDocumentMarkers(t *testing.T) {
	for _, src := range []string{
		"---\nversion: 1\ndefault: deny\nrules: []\n",
		"version: 1\ndefault: deny\nrules: []\n...\n",
		"---\nversion: 1\ndefault: deny\nrules: []\n...\n",
	} {
		if p := mustParse(t, src); p.Default != Deny {
			t.Errorf("Parse(%q).Default = %q, want deny", src, p.Default)
		}
	}
}

// A documented limit, pinned so it stays deliberate. A key written with no
// value at all ("paths:") decodes to null, and yaml.v3 handles a null node
// before it consults the destination type, so it is indistinguishable from an
// absent key without walking the document as a node tree. It therefore reads
// as "unconstrained", which for a rule the operator was mid-edit on means
// tunnel-eligible. An explicit "[]" is the case that looks like enforcement,
// and that one is refused.
func TestAKeyWrittenWithNoValueReadsAsAbsent(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - name: a
    hosts: ["a.com"]
    paths:
`)
	if p.Rules[0].Paths != nil {
		t.Errorf("Paths = %#v, want nil", p.Rules[0].Paths)
	}
}
