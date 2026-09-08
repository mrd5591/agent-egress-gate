// Package policy parses and evaluates the egress allowlist.
//
// Evaluation is pure: it performs no I/O, holds no state, and depends on
// nothing outside the standard library and the YAML parser. That is
// deliberate, because this is where the security decision is actually made
// and it should be possible to test every branch of it without a socket.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is the outcome of a policy decision.
type Action string

// The two possible actions.
const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Kind distinguishes a proxied HTTP request from a CONNECT tunnel. The
// distinction matters: inside a tunnel the gate sees opaque bytes, so method
// and path constraints cannot be enforced.
type Kind string

// The two request kinds.
const (
	KindHTTP    Kind = "http"
	KindConnect Kind = "connect"
)

// defaultPorts are the ports a rule covers when it does not list any. A rule
// with no ports is deliberately not "any port": widening to every port by
// omission is the kind of default that turns into an incident.
var defaultPorts = []int{80, 443}

// knownMethods is the set of HTTP methods a rule may name. CONNECT is absent
// on purpose; a tunnel is authorised by host, never by method.
var knownMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// Rule is one allowlist entry. A rule matches when the host matches one of
// its patterns, the port is covered, and, for plain HTTP, the method and path
// satisfy any constraints the rule sets.
type Rule struct {
	Name    string   `yaml:"name"`
	Hosts   []string `yaml:"hosts"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
	Ports   []int    `yaml:"ports"`
}

// constrained reports whether the rule limits method or path. A constrained
// rule cannot authorise a CONNECT tunnel, because neither field is visible
// once the tunnel is open.
func (r Rule) constrained() bool {
	return len(r.Methods) > 0 || len(r.Paths) > 0
}

// Policy is a parsed and validated ruleset.
type Policy struct {
	Version int    `yaml:"version"`
	Default Action `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}

// Request is the question the proxy asks. Method and Path are empty for a
// CONNECT tunnel.
type Request struct {
	Kind   Kind
	Host   string
	Port   int
	Method string
	Path   string
}

// Decision is the answer, carrying the reason so it can be written straight
// into the audit log.
type Decision struct {
	Action Action
	Rule   string
	Reason string
}

// Parse reads a policy document and validates it. It returns an error rather
// than a partially usable policy: a policy file that half-loads is worse than
// none, because the operator believes rules are in force that are not.
func Parse(data []byte) (*Policy, error) {
	var p Policy

	// Strictly, because yaml.Unmarshal drops an unrecognised key without a
	// word. Most typos are caught downstream by validate, which finds no
	// version or no hosts and says so. Two are not: `methods` and `paths`
	// mistyped as `method` and `path` simply vanish, constrained() then
	// reports false, and a rule the operator wrote to permit one method on one
	// path becomes a host-only rule that authorises a full HTTPS tunnel to
	// that host. The policy file reads as though it enforces something it does
	// not, which is the failure the CONNECT rule exists to prevent, and it
	// fails in the permissive direction. An unknown key is therefore a parse
	// error naming the field and its line.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	// A Decoder reports an empty or comment-only document as io.EOF, where
	// yaml.Unmarshal reports nothing and leaves the zero value. Keep the
	// second behaviour: falling through to validate answers with "version must
	// be 1, got 0", which tells an operator what to write. "EOF" does not.
	switch err := dec.Decode(&p); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, fmt.Errorf("parse policy: %w", err)
	default:
		// A policy is one document. yaml.Unmarshal parses the first and
		// discards everything after a "---" silently, so rules an operator
		// appended below one would never be in force. That is the same
		// half-loaded policy this function refuses everywhere else.
		var next yaml.Node
		if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
			return nil, errors.New("parse policy: a policy must be a single YAML document")
		}
	}

	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// writtenButEmpty reports a list the operator wrote as empty, as opposed to
// one they left out. The YAML decoder leaves an absent key nil and decodes an
// explicit "[]" into a non-nil zero-length slice, and that is the only trace
// of the difference between them. It is a property of the decoder rather than
// of this package, so a test pins it: an upgrade that changed it would
// otherwise re-open the hole in silence.
func writtenButEmpty[T any](list []T) bool {
	return list != nil && len(list) == 0
}

func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", p.Version)
	}
	if p.Default != Allow && p.Default != Deny {
		return fmt.Errorf("default must be %q or %q, got %q", Allow, Deny, p.Default)
	}

	seen := make(map[string]bool, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if len(r.Hosts) == 0 {
			return fmt.Errorf("rule %q: at least one host is required", r.Name)
		}
		for j, h := range r.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				return fmt.Errorf("rule %q: empty host", r.Name)
			}
			if strings.Contains(h, "*") {
				if !strings.HasPrefix(h, "*.") || strings.Contains(h[2:], "*") {
					return fmt.Errorf(
						"rule %q: host %q: wildcard is only supported as a leading %q label",
						r.Name, r.Hosts[j], "*.")
				}
				if h == "*." {
					return fmt.Errorf("rule %q: host %q: wildcard needs a domain after it", r.Name, r.Hosts[j])
				}
			}
			r.Hosts[j] = h
		}

		// An explicitly empty list is refused rather than guessed at. It has
		// two defensible readings and neither is safe to assume. Read as
		// "permit nothing", the rule can never fire: it reads as enforcement
		// and enforces nothing. Read as "constrain nothing", which is what a
		// bare len() check gave it because len() cannot tell "[]" from an
		// absent key, the rule silently gains every method and every path and
		// flips to tunnel-eligible. The second is the dangerous reading and it
		// was the one in force. So name the field and make the operator say
		// which they meant.
		if writtenButEmpty(r.Methods) {
			return fmt.Errorf(
				"rule %q: methods is written but empty; drop the key to constrain no method, or list the methods to permit",
				r.Name)
		}
		if writtenButEmpty(r.Paths) {
			return fmt.Errorf(
				"rule %q: paths is written but empty; drop the key to constrain no path, or list the paths to permit",
				r.Name)
		}
		if writtenButEmpty(r.Ports) {
			return fmt.Errorf(
				"rule %q: ports is written but empty; drop the key to cover 80 and 443, or list the ports to permit",
				r.Name)
		}

		for j, m := range r.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if !knownMethods[m] {
				return fmt.Errorf("rule %q: unknown method %q", r.Name, r.Methods[j])
			}
			r.Methods[j] = m
		}

		for _, path := range r.Paths {
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("rule %q: path %q must start with %q", r.Name, path, "/")
			}
		}

		for _, port := range r.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("rule %q: port %d out of range", r.Name, port)
			}
		}
	}
	return nil
}

// Evaluate applies the policy to one request and returns the first matching
// rule's verdict, or the default action.
//
// For a CONNECT tunnel, rules that constrain method or path are skipped: the
// gate cannot see inside TLS, so honouring such a rule would claim an
// enforcement it cannot perform. Evaluation continues past a skipped rule, so
// a later host-only rule can still authorise the tunnel. If nothing matches
// and at least one rule was skipped this way, the denial names it, because
// "your rule is the wrong shape for HTTPS" is the single most useful thing to
// tell an operator staring at a blocked build.
func (p *Policy) Evaluate(req Request) Decision {
	host := strings.ToLower(req.Host)
	var nearMiss string

	for _, r := range p.Rules {
		if !r.matchesHost(host) || !r.matchesPort(req.Port) {
			continue
		}

		if req.Kind == KindConnect {
			if r.constrained() {
				if nearMiss == "" {
					nearMiss = r.Name
				}
				continue
			}
			return Decision{Action: Allow, Rule: r.Name, Reason: "matched rule " + r.Name}
		}

		if !r.matchesMethod(req.Method) || !r.matchesPath(req.Path) {
			continue
		}
		return Decision{Action: Allow, Rule: r.Name, Reason: "matched rule " + r.Name}
	}

	if p.Default == Allow {
		return Decision{Action: Allow, Reason: "default action is allow"}
	}
	if nearMiss != "" {
		return Decision{
			Action: Deny,
			Reason: fmt.Sprintf(
				"rule %s matched host but constrains method or path, which cannot be enforced inside a tunnel",
				nearMiss),
		}
	}
	return Decision{Action: Deny, Reason: "no rule matched"}
}

func (r Rule) matchesHost(host string) bool {
	for _, pattern := range r.Hosts {
		if hostMatches(pattern, host) {
			return true
		}
	}
	return false
}

// hostMatches implements the one wildcard form the policy supports.
// "*.example.com" matches one or more subdomain labels and does not match the
// apex. An operator who wants both writes both.
func hostMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		// The dot is required so that "*.pypi.org" rejects "evilpypi.org".
		rest, found := strings.CutSuffix(host, "."+suffix)
		if !found {
			return false
		}
		// rest holds the labels the wildcard stands for, and every one of them
		// must be a real label. A length check alone accepts "..example.com"
		// and "a..example.com", whose empty labels are not names a resolver
		// will answer, so matching them only widens the rule.
		for _, label := range strings.Split(rest, ".") {
			if label == "" {
				return false
			}
		}
		return true
	}
	return pattern == host
}

func (r Rule) matchesPort(port int) bool {
	ports := r.Ports
	if len(ports) == 0 {
		ports = defaultPorts
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func (r Rule) matchesMethod(method string) bool {
	if len(r.Methods) == 0 {
		return true
	}
	for _, m := range r.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (r Rule) matchesPath(path string) bool {
	if len(r.Paths) == 0 {
		return true
	}
	for _, prefix := range r.Paths {
		if pathHasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// pathHasPrefix reports whether path is covered by prefix, matching on segment
// boundaries: "/v1/status" covers "/v1/status" and "/v1/status/detail" and not
// "/v1/status-admin" or "/v1/statuses/all". A plain strings.HasPrefix grants
// those last two, and they are different endpoints that happen to share an
// opening string; an operator who listed one has not listed its neighbours.
//
// A prefix written with a trailing slash already names the boundary, so
// "/repos/" behaves exactly as it always has and the shipped example is
// unaffected. Dot-segments and encoded separators are refused before policy is
// consulted, but this holds on its own: it is a comparison, not a sanitiser,
// and it should not depend on who calls it.
func pathHasPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || strings.HasSuffix(prefix, "/") || strings.HasPrefix(rest, "/")
}
