# agent-egress-gate

A headless coding agent in CI can reach any host that answers. This is the
proxy that says no, and the Terraform that makes it the only way out.

```bash
go build -o egressgate ./cmd/egressgate

# What would the policy do? Exits 0 on allow, 1 on deny, so it works in a gate.
./egressgate check --policy policy.example.yaml GET https://pypi.org/simple/

# Run it.
./egressgate serve --policy policy.example.yaml --audit audit.log

# Later, prove the log was not edited.
./egressgate verify --audit audit.log
```

Third in a set. [agentic-harness-jvm](https://github.com/mrd5591/agentic-harness-jvm)
gates the code an agent writes. [agent-eval-mcp](https://github.com/mrd5591/agent-eval-mcp)
scores what an agent did. This gates where an agent can reach.

---

## Why

You can read an agent's diff. You can read its transcript. You cannot see
that it resolved a package from a host nobody vetted, because an outbound
request leaves no trace in a build log.

That matters more than it used to. A prompt-injected agent, or a compromised
dependency it installs mid-build, has the same network access as the build
itself. The usual answer is a network policy written once, somewhere else, by
someone who no longer works there.

So: deny by default, allow a list of hosts, and write down every decision in a
form that shows if someone edited it afterwards.

## What it enforces

| Layer | Enforces | Failure mode it removes |
|---|---|---|
| Security group | The agent can only reach the gate | An agent that ignores `HTTP_PROXY` |
| Policy | Which hosts the gate will reach | An allowed agent reaching an unvetted host |
| Audit chain | What actually happened | A quiet edit to the record afterwards |

No layer is trusted alone. The proxy is the interesting one, but the security
group is the one that makes it unavoidable.

## The CONNECT rule

This is the design decision worth arguing about, so it is stated plainly
rather than buried.

**A rule that constrains `methods` or `paths` cannot authorise an HTTPS
tunnel.**

Once a `CONNECT` tunnel opens, the gate is copying opaque bytes. It cannot see
the method or the path. A rule claiming to restrict them would be theatre, so
such a rule is skipped during tunnel evaluation, and the denial names the rule
that nearly matched. Given the `github-api` rule in the next section:

```console
$ ./egressgate check --policy policy.yaml GET https://api.github.com/repos/x
GET https://api.github.com/repos/x
  evaluated as: CONNECT tunnel to api.github.com:443
  decision:     deny
  reason:       rule github-api matched host but constrains method or path, which cannot be enforced inside a tunnel
```

The same request over plain HTTP is allowed, because there the method and path
are visible and can actually be checked.

Allowing HTTPS to a host is a host-level decision, and you have to make it
explicitly by writing a host-only rule. The alternative, quietly opening the
tunnel and ignoring the constraints, is what a naive implementation does. It
is worse, because the policy file then reads as though it enforces something
it does not.

`egressgate check` models this the same way the running proxy does, so it
cannot tell you a rule works when the gate will refuse it.

## Policy

```yaml
version: 1
default: deny

rules:
  - name: github-api          # plain HTTP only: it constrains method and path
    hosts: ["api.github.com"]
    methods: ["GET", "POST"]
    paths: ["/repos/", "/user"]

  - name: package-registries  # host-only, so HTTPS tunnels are allowed
    hosts: ["pypi.org", "*.pypi.org", "files.pythonhosted.org"]
```

Two rules that catch people out, both chosen so the surprising direction is
the safe one:

- `*.example.com` matches one or more subdomain labels and **not** the apex.
  Want both? Write both.
- A rule with no `ports` covers **80 and 443 only**, never every port.

## Audit log

One JSON object per line. Each record carries the hash of the one before it,
so altering a record in the middle invalidates every record after it.

```json
{"seq":1,"ts":"2026-09-08T06:23:14Z","kind":"connect","host":"example.com",
 "port":443,"decision":"allow","rule":"example-only","client":"127.0.0.1",
 "status":200,"bytes_up":841,"bytes_down":5324,"duration_ms":180,
 "prev":"0000…","hash":"508625…"}
```

`verify` recomputes the chain and names the first break:

```
chain BROKEN at record 2: record hash eebe75… does not match the recomputed hash 7abd45…
1 records verified before the break
```

Two honest limits:

- This is tamper **evidence**, not tamper resistance. Someone who can rewrite
  the whole file can rebuild a consistent chain. `serve` prints the chain head
  on shutdown so you can record it somewhere the gate cannot write, which is
  what makes truncation of the tail detectable.
- A tunnel's record is written when the tunnel **closes**, because the byte
  counts are not known before then. While a long tunnel is open it is absent
  from the log. Watch `egressgate_active_tunnels` for that window.

## Running it

Two listeners, and keeping them apart is the point. The data listener carries
agent traffic. The admin listener carries `/metrics`, `/healthz`, `/readyz`
and `POST /reload`, and must never be reachable by the agent: an agent that
can reload the policy can replace the policy that constrains it.

```bash
./egressgate serve \
  --policy policy.yaml \
  --listen 0.0.0.0:8080 \
  --admin 127.0.0.1:9090 \
  --audit /var/log/egressgate/audit.log \
  --idle-timeout 5m \
  --max-tunnel-bytes 0        # 0 means no cap; set it to bound one tunnel
```

Point the agent at it:

```bash
export HTTP_PROXY=http://gate:8080
export HTTPS_PROXY=http://gate:8080
```

A policy reload reads and parses before it swaps, so a typo leaves the
previous policy in force rather than briefly opening the gate:

```bash
curl -X POST http://127.0.0.1:9090/reload
```

## Terraform

`terraform/modules/egress-gate` runs the gate on ECS Fargate. The part that
matters is not the service, it is the two security groups:

- **gate**: ingress on the proxy port from the agent group only; egress to the
  internet.
- **agent**: egress **only** to the gate on the proxy port. It has no other
  outbound rule.

Attach `agent_security_group_id` to your agent tasks and the gate stops being
advice. IAM is scoped to the one log group, the one ECR repository and the one
SSM parameter holding the policy, with no resource wildcards except the ECR
authorization token, which has none to scope to.

`terraform/example` stands up a VPC, a NAT gateway, the parameter and the
module, so `validate` runs against a real caller.

**Validated, not applied.** CI runs `fmt -check`, `init -backend=false`,
`validate` and `tflint` on every push. It has never run `apply`, because there
is no AWS account attached to this repository. The configuration is
syntactically valid and type-checked against the AWS provider schema; it has
not been proven to converge against the live API. Treat it as a reviewed
starting point, not as something known to stand up on the first try.

## Building the container

```bash
docker build -t egressgate .
```

Static binary, non-root user, Alpine base. Alpine rather than distroless
because the ECS task definition uses a shell to write the policy file and
`wget` for its health check.

## Development

```bash
go test ./... -race          # every test runs under the race detector
./scripts/coverage.sh        # same coverage floor CI uses
```

Test-driven throughout: 93% statement coverage, and the uncovered remainder is
listed in the code with the reason it cannot be reached. The tests that carry
the most weight are the ones asserting a denied request **never reaches the
upstream**, rather than merely that the client saw a 403. A proxy that
forwards first and reports 403 afterwards passes the weaker test and provides
no containment at all.

## What this does not do

- **No TLS interception.** The gate sees `CONNECT host:443` and nothing more.
  Interception would mean distributing a CA to every agent, which is a larger
  and more dangerous product than this one.
- **No agent authentication.** Network placement is the boundary. If you need
  to distinguish two agents on the same subnet, this is not yet that.
- **No DNS control.** A rule names a host; resolution is the resolver's job.
  A poisoned resolver defeats a hostname allowlist, here as everywhere.

## Licence

MIT.
