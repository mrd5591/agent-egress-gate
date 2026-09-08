# agent-egress-gate — Design

*2026-09-08. Approved in advance by Matt ("proceed with the Go service with Terraform work
autonomously"). Design decisions below were made by Claude and are flagged where a reasonable
person would have chosen differently.*

## Problem

A headless coding agent in CI runs with network access. Nothing constrains where it reaches.
A prompt-injected agent, or a compromised dependency it installs, can send a repository to any
host that answers. The build log will not show it, because an outbound request is not an event
anyone records.

Two existing repos in this body of work address adjacent halves of the problem, and neither
covers this one.

| Repo | Gate | When |
|---|---|---|
| `agentic-harness-jvm` | Does the code the agent wrote meet the bar? | Build time |
| `agent-eval-mcp` | What did the agent actually do in its session? | After the fact |
| **`agent-egress-gate`** | **Where is the agent allowed to reach?** | **Runtime** |

## What it is

A forward proxy the agent points at, plus the Terraform that makes it the only way out.

Deny by default. An allowlist of hosts expressed in YAML. Every decision appended to a
hash-chained audit log that can be verified offline. Prometheus metrics on an admin listener
separate from the data path.

The network enforces that the agent can only reach the proxy. The proxy enforces which hosts
the agent may reach. The audit log proves what happened. No single layer is trusted alone.

## Scope

In:

- HTTP forward proxying (absolute-URI requests) and HTTPS via `CONNECT` tunnelling.
- Policy evaluation on host, port, method, and path prefix.
- Hash-chained, append-only audit log, with an offline verifier.
- Prometheus metrics, health and readiness endpoints, and policy reload, all on an admin
  listener separate from the data path.
- A Terraform module that runs it on ECS Fargate and writes the security-group rules that
  make it unavoidable.

Out, deliberately:

- **TLS interception.** The gate sees `CONNECT host:443` and nothing more. Method and path
  inside a tunnel are unverifiable, so the gate refuses to pretend otherwise. Interception
  would mean distributing a CA to agents, a larger and more dangerous product than this one.
- **Cedar policy.** An earlier research note proposed Cedar. YAML covers the allowlist case at
  a fraction of the complexity, and evaluation sits behind an interface, so Cedar stays
  addable later.
- **Sigstore signing.** A SHA-256 hash chain gives tamper evidence with no key-management
  story. Signing the chain head is a later addition, not a prerequisite.
- **Agent authentication.** Network placement is the boundary in version one.

## The CONNECT rule

This is the one design decision worth arguing about, so it is stated plainly.

A rule that constrains `methods` or `paths` cannot authorise a CONNECT tunnel. Once the tunnel
opens the gate is copying opaque bytes. It cannot know the method or the path, and a rule that
claims to restrict them would be theatre.

So a rule carrying method or path constraints is skipped during CONNECT evaluation, and the
audit record says why. Allowing HTTPS to a host is a host-level decision, and an operator has
to make it explicitly by writing a host-only rule.

The alternative, silently ignoring the constraints and opening the tunnel, is what a naive
implementation does. It is worse, because the policy file then reads as though it enforces
something it does not.

## Architecture

```
              admin listener :9090            data listener :8080
              /metrics  /healthz              HTTP absolute-URI
              /readyz   /reload               CONNECT host:443
                    |                                |
              +-----+--------------------------------+-----+
              |                   server                   |
              +----+---------------+---------------+-------+
                   |               |               |
             +-----v-----+   +-----v-----+   +-----v-----+
             |  policy   |   |   audit   |   |  metrics  |
             |  (pure)   |   |  (chain)  |   |  (prom)   |
             +-----------+   +-----------+   +-----------+
```

Each package has one job and no knowledge of the others' internals.

| Package | Responsibility | Depends on |
|---|---|---|
| `internal/policy` | Parse and evaluate rules. Pure, no I/O. | nothing |
| `internal/audit` | Append hash-chained records, verify a chain. | nothing |
| `internal/metrics` | Prometheus collectors. | prometheus |
| `internal/proxy` | HTTP and CONNECT handling, timeouts, byte copying. | policy, audit, metrics |
| `cmd/egressgate` | Flag parsing, wiring, signal handling. | all of the above |

Policy and audit are pure, which is where most of the correctness lives. The proxy is tested
against real `httptest` servers including TLS, not mocks. A proxy that passes against a mock
and fails against a socket is worthless.

## Policy format

```yaml
version: 1
default: deny

rules:
  - name: github-api
    hosts: ["api.github.com"]
    methods: ["GET", "POST"]
    paths: ["/repos/", "/user"]

  - name: package-registries      # host-only, so CONNECT is eligible
    hosts: ["pypi.org", "*.pypi.org", "files.pythonhosted.org", "proxy.golang.org"]
```

A pattern of the form `*.example.com` matches one or more subdomain labels, not the apex. An
operator who wants both writes both. Implicit apex matching is the kind of convenience that
turns into an incident.

## Audit record

One JSON object per line.

```json
{"seq":1,"ts":"2026-09-08T14:02:11Z","kind":"connect","host":"api.github.com","port":443,
 "decision":"allow","rule":"package-registries","client":"10.0.1.5","bytes_up":412,
 "bytes_down":9021,"duration_ms":214,"prev":"0000","hash":"9f2c"}
```

The hash is `SHA256(prev_hash || canonical_json(record without hash))`. The genesis `prev` is
64 zeros. The `verify` subcommand recomputes the chain and reports the sequence number of the
first break. Truncation of the tail is detectable only against a recorded head, which the tool
prints on shutdown. That limitation is documented rather than papered over.

## Terraform

Standard module layout: `terraform/modules/egress-gate` is reusable, `terraform/examples/complete`
stands one up.

The module provisions the ECS Fargate service, an ECR repository, a CloudWatch log group, task
and execution roles scoped to exactly that log group and the one parameter holding the policy,
and, the part that matters, two security groups.

- `gate`: ingress on the proxy port from the agent security group only, egress to the internet.
- `agent`: egress only to the gate on the proxy port. No other outbound rule exists.

The second group is the control. Without it the proxy is advice. With it the proxy is the only
route off the subnet.

CI runs `fmt -check`, `init -backend=false`, `validate`, and `tflint`. It does not run `apply`.
There is no AWS account attached to this repo, and a README claiming a deployed service it
cannot show is a lie a reviewer will catch. The README says "validated, not applied", and says
what that means.

## Testing

Test-driven throughout.

- **policy**: table-driven, exhaustive over match and non-match for each field, including the
  CONNECT eligibility rule.
- **audit**: round trip, chain continuity, and detection of a mutated middle record.
- **proxy**: real `httptest` upstreams over HTTP and TLS. An allowed request reaches the
  upstream. A denied request returns 403 and the upstream never sees a connection. A tunnel
  copies bytes both ways. Timeouts fire. All under `-race`.
- Coverage floor enforced in CI, set to the bar the sibling repos hold rather than a number
  that merely passes.

## Success criteria

1. `go test -race ./...` green on Linux and Windows, coverage above the floor.
2. `terraform validate` and `tflint` green.
3. A denied host cannot reach the upstream, proven by a test asserting the upstream received
   nothing.
4. A tampered audit log fails verification at the correct sequence number.
5. A README a hiring engineer can read in three minutes and come away knowing what the thing
   does, what it does not do, and why.
