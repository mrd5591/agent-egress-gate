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

Three honest limits:

- This is tamper **evidence**, not tamper resistance. Someone who can rewrite
  the whole file can rebuild a consistent chain. `serve` prints the chain head
  on shutdown so you can record it somewhere the gate cannot write, which is
  what makes truncation of the tail detectable.
- `verify` exits 0 for an intact, complete chain, 1 for a broken one, and **3**
  for a chain that verifies but stops mid-record. That third case gets its own
  code on purpose: a crash produces it, and so does a tail someone removed, and
  those are indistinguishable without the head you recorded. Exiting 0 would
  let a gate wired to the exit status walk straight past it.
- A tunnel's record is written when the tunnel **closes**, because the byte
  counts are not known before then. While a long tunnel is open it is absent
  from the log. `egressgate_active_tunnels` covers that window, but note that
  the Terraform module opens the admin port to nothing by default: until you
  pass `admin_ingress_security_group_ids`, no collector can scrape it and the
  window is genuinely unobserved.
- A restart continues the existing chain rather than starting a new one, so a
  deploy does not look like tampering. If a previous run was killed mid-write,
  the gate discards the partial final record, says so on stderr, and resumes
  from the last complete one. That case is deliberately distinguished from a
  real break: refusing to start on a torn write would turn one crash into a
  crash loop whose only remedy is editing the audit log. A record that was
  actually altered still stops the gate, and the error names a new file to
  start a fresh chain in, so the log stays as evidence.
- The hashed bytes are Go's `encoding/json` output, which escapes `<`, `>` and
  `&` as `\u003c`, `\u003e` and `\u0026`. Writer and verifier agree, so this is
  invisible in normal use, but a verifier reimplemented in another language
  has to reproduce that escaping. Python's `json.dumps` does not, by default.

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

`--max-tunnel-bytes` is a resource guard, not an exfiltration control. It caps
each direction of a CONNECT tunnel, and nothing else: the plain-HTTP path has
no cap, so an agent allowed a host over HTTP can still POST without bound. Read
it as "one tunnel cannot consume the gate", and rely on the host allowlist for
the rest.

Point the agent at it:

```bash
export HTTP_PROXY=http://egress-gate:8080
export HTTPS_PROXY=http://egress-gate:8080
```

That hostname comes from ECS Service Connect, which the module enables when
you give it a namespace. Without it the gate has no stable address, because
tasks get ephemeral private IPs and there is more than one of them; the
module's `proxy_endpoint` output is null in that case rather than guessing.

A policy reload reads and parses before it swaps, so a typo leaves the
previous policy in force rather than briefly opening the gate:

```bash
curl -X POST http://127.0.0.1:9090/reload
```

Reload re-reads a policy **file**. The ECS task definition runs the gate with
`--policy-env`, so the deployed configuration has no file behind its policy:
`/reload` answers 400 there, and changing the SSM parameter means a new
deployment. `--policy` with `POST /reload` is for the case where the policy is
a file the gate can read again.

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

One consequence worth stating before you hit it. Since Fargate platform 1.4.0
a task's image pull goes through the task's own ENI and is therefore subject
to its security group, so a task whose only egress rule is "reach the gate"
cannot pull its image and never starts. The module takes
`vpc_endpoint_security_group_ids` and `s3_gateway_prefix_list_id` and opens
443 to those, which keeps that traffic inside the VPC. Leave them empty and
you get the strictest rules and a task that will not launch. The example wires
up the endpoints so it is a configuration that would actually run.

`terraform/example` stands up a VPC, a NAT gateway, the parameter and the
module, so `validate` runs against a real caller.

**Validated, not applied.** CI runs `fmt -check`, `init -backend=false`,
`validate` and `tflint` on every push. It has never run `apply`, because there
is no AWS account attached to this repository.

Be precise about what that buys. `validate` checks the resource arguments and
their types against the provider schema. It does **not** check
`container_definitions`, which Terraform sees as an opaque JSON string, and
that block is the most important one in the module: the command, the user, the
read-only root filesystem and the health check all live inside it and get zero
checking. That gap is exactly how an earlier version shipped a task definition
passing a shell invocation to an image with an `ENTRYPOINT`, which would have
started no container at all. The `container` CI job now runs the image the way
the task definition does and drives real traffic through it, which is what
actually covers that block. The rest remains a reviewed starting point, not
something known to converge on the first apply.

## Building the container

```bash
docker build -t egressgate .

# A policy file mounted in:
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v "$(pwd)/policy.example.yaml:/etc/egressgate/policy.yaml:ro" \
  egressgate

# Or the policy in the environment, with a read-only root filesystem. This is
# how the ECS task definition runs it: no shell, and no writable path anywhere
# in the container.
docker run --rm --read-only -p 8080:8080 -p 9090:9090 \
  -e EGRESSGATE_POLICY="$(cat policy.example.yaml)" \
  egressgate serve --policy-env EGRESSGATE_POLICY \
    --listen 0.0.0.0:8080 --admin 0.0.0.0:9090
```

Static binary, non-root user (uid 65532), read-only root filesystem, Alpine
base. Alpine rather than distroless only for `wget`, which the ECS health check
uses. The container needs no shell: reading the policy from the environment is
what removed it.

Unlike the Terraform, this path **has** been run, and CI runs it on every push.
The `container` job builds the image, starts it read-only exactly as the task
definition does, checks that an allowed host returns 200 through the tunnel and
a denied host returns 403, then pipes the container's stdout into `egressgate
verify`. That last step is the one that matters: stdout is the default audit
sink, so it has to carry audit records and nothing else, or the verifier cannot
read the log the deployment actually produces.

## Development

```bash
go test ./... -race          # every test runs under the race detector
./scripts/coverage.sh        # same coverage floor CI uses
```

Test-driven throughout: 94% statement coverage, and the uncovered remainder is
listed in the code with the reason it cannot be reached. The tests that carry
the most weight are the ones asserting a denied request **never reaches the
upstream**, rather than merely that the client saw a 403. A proxy that
forwards first and reports 403 afterwards passes the weaker test and provides
no containment at all.

## Threat model

Who this stops, and who it does not.

**It stops** an agent that follows its `HTTP_PROXY` setting from reaching an
unlisted host, and an agent that ignores that setting from reaching anything at
all, because the security group leaves it exactly one route. It records every
decision somewhere the task itself cannot rewrite, and makes a later edit to
that record detectable.

**It does not stop** someone who compromises the gate task. That process holds
the policy, terminates the tunnels and writes the log. It is the trust
boundary, not something defended behind one. Run it in its own subnet, give it
no role it does not need (the task role here grants nothing at all), and treat
its image with the care you would give a bastion.

**The admin plane is separated by placement, not authenticated.** Anything that
can reach the admin port can read the metrics and reload the policy from its
file. That is a security-group boundary, so a mistake in those rules is a real
exposure rather than a second line to get past. Version one takes that trade
deliberately, and it is the first thing to change if the gate ever runs
somewhere less controlled.

**DNS is outside the boundary.** A rule names a host; resolution belongs to the
resolver. A poisoned resolver defeats a hostname allowlist here as everywhere.
The gate also reaches the VPC resolver without an egress rule, because security
groups do not filter that traffic. A VPC with a custom DHCP options set
pointing at a private forwarder would need a rule this module does not write.

**The example VPC gives agents a NAT route.** Both private subnets share one
route table with a default route to the NAT gateway, so only the security group
stands between an agent and the internet. That is why the agent group's single
egress rule carries so much weight. A stricter build would put agents in a
subnet with no default route at all, leaving a misconfigured group nowhere to
go.

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
