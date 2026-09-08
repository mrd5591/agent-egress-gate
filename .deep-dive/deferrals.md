# Deep-dive deferrals

Findings this repo has seen and not yet closed. Each entry carries a **class**
(`money` > `step` > `hours`; `hygiene` is never filed), an **effort** (`small` =
one sitting and one gate, or `own-pr`), and a **run count**. Selection order for
a debt pass is class, then effort, then run count.

Closed items move to `resolved.md`. They are not kept here.

Ceiling on `## Open`: 20. Rulings cap: 5.

## Open

### `money` · own-pr · run 1 — A tunnel open at shutdown leaves no audit record
A CONNECT record is written when the tunnel closes, and nothing drains or
audits an in-flight tunnel at SIGTERM. `http.Server.Shutdown` does not wait on
hijacked connections, and there is no `WaitGroup`/`ConnState`/
`RegisterOnShutdown` anywhere. A tunnel open when the task stops — the normal
case at the end of a CI job — is simply absent from the evidence, and it can
also race the chain-head print.
**Next action:** track hijacked connections and, at shutdown, close them and
write their records before printing the head.

### `money` · small · run 1 — `verify` exits 0 on an empty log
An empty or whitespace-only file is reported as `chain intact: 0 records`,
exit 0, so a consumer wired to the exit status cannot tell "nothing was
recorded" from "everything verified". The `container` CI job's vacuity was
closed this pass with a record-count assertion, but the tool still has the gap
and every other caller inherits it.
**Design gate.** Default if nobody rules by run 3: add `--min-records N`
(default 0, so today's behaviour is unchanged) and use it wherever a caller
knows traffic should have occurred.

### `money` · own-pr · run 1 — Chain continuity is unachievable in the shipped config
Resuming needs a file to read back, so it never happens under the default
stdout sink; the ECS task definition passes no `--audit`, so every restart
starts a new chain at sequence 1, and `desired_count` defaults to 2, so two
chains run at once. Documented honestly in the README this pass, but the
property the audit chain exists to provide is not actually delivered by the
deployment.
**Design gate.** Default if nobody rules by run 3: leave it documented and do
not build cross-restart continuity — the alternative (threading the head
through SSM or a sidecar) is a larger product than this one.

### `money` · small · run 1 — CloudWatch stream is not directly verifiable
The `awslogs` driver merges the container's stderr into the same stream as the
audit records on stdout, so the deployed log does not parse as one JSON object
per line. Reproduced: `chain BROKEN at record 1: could not decode record:
invalid character 'l'` — the `l` of the `listening:` startup line. Documented
this pass; the CI `container` job cannot see it because `docker logs` keeps the
streams apart.
**Design gate.** Default if nobody rules by run 3: ship a documented extraction
one-liner in the README rather than adding a quiet mode, since the diagnostics
on stderr are worth keeping.

### `money` · small · run 1 — Audit log group can be destroyed silently
`aws_cloudwatch_log_group.gate` has no `prevent_destroy`, and its name derives
from `var.name`, so renaming the module instance deletes the evidence artefact
the product is built around.
**Next action:** add a `lifecycle { prevent_destroy = true }`, or a variable
that governs it, and say why in the module docs.

### `step` · small · run 1 — `check` and `serve` disagree on dot-segment paths
`egressgate check GET http://example.com/allowed/../secret` reports **allow**,
while the running proxy 400s that request in `normalisedPath` before policy is
consulted. This contradicts the README and `run.go`'s own comment that `check`
"never promises an allow the gate would refuse". The direction is fail-safe
(the gate is stricter than the advice), but the tool's whole purpose is to model
the gate exactly.
**Next action:** share one normalisation path between `check` and the proxy;
today `normalisedPath` is unexported in `internal/proxy`, so this needs a small
move rather than a copy.

### `step` · small · run 1 — ECS service races its execution-role policy
`aws_ecs_service.gate` depends on `aws_iam_role.execution` but not on
`aws_iam_role_policy.execution`, so tasks can launch before the inline policy
exists, fail the image pull or `GetParameters`, and trip the deployment
circuit breaker on a correct configuration.
**Next action:** add the policy to `depends_on`.

### `step` · small · run 1 — Gate egress is hardcoded to 80/443
A policy rule may name arbitrary `ports`, and the gate's security group only
allows 80 and 443 outbound. A rule the gate accepts, evaluates as allow, and
audits as allow becomes an unexplained upstream timeout, with no variable to
widen the group.
**Next action:** either derive the egress ports from a variable, or reject a
policy naming a port the deployment cannot reach — and say which in the README.

### `hours` · small · run 1 — Transport has no idle or handshake bounds
`internal/proxy/proxy.go` builds an `http.Transport` without
`IdleConnTimeout`, `MaxIdleConns`, `MaxConnsPerHost` or `TLSHandshakeTimeout`.
Zero means unlimited for these (unlike `http.DefaultTransport`), so a
long-running gate holds an idle socket for every upstream it has ever contacted.
**Next action:** set the four fields, mirroring `DefaultTransport`'s values.

### `hours` · small · run 1 — Base images float while every tool is pinned
`Dockerfile` uses `golang:1.25-alpine` and `alpine:3.20` by tag. Every other
tool in the build — terraform, tflint, golangci-lint, govulncheck — is pinned to
an exact version on the stated principle that an unpinned tool works today and
fails later for reasons nobody wrote down. The two inputs that actually ship
are the unpinned ones.
**Next action:** pin both by digest and note the refresh procedure.

### `hours` · own-pr · run 1 — A rotated log segment cannot be verified
`Verify` always starts from `GenesisHash` and sequence 0, so a segment written
by `Resume` into a fresh file always reports BROKEN — `sequence jumped from 0
to 4`. `VerifyResult.LastSeq`'s own comment acknowledges a resumed log need not
start at one, but there is no `VerifyFrom(head, seq)` entry point.
**Next action:** add one, and let `verify` take the expected head and sequence.

### `hours` · small · run 1 — Audit timestamps are not sortable
Records use `time.RFC3339Nano`, which strips trailing zeros, so precision
varies per record and the timestamps do not sort lexicographically. Harmless to
the chain (the string is hashed as written) but wrong for an evidence log that
people will sort and diff.
**Next action:** fixed-width nanoseconds.

### `hours` · small · run 1 — `tflint --init` has no retry and fails on a live GitHub API blip
The plugin install fetches the AWS ruleset from the GitHub releases API on every
run, with no retry, so a transient API failure reds the whole `terraform` job on
a commit that touches no HCL. Seen twice now for different reasons: a `403 API
rate limit exceeded` (fixed by authenticating with `GITHUB_TOKEN`, commit
1d4c731) and a `500` on `checksums.txt.sig` during this pass, which passed on a
plain re-run. Authenticating fixed the rate-limit cause but not the class.
**Next action:** cache the plugin directory across runs, or wrap `tflint --init`
in a bounded retry, so a GitHub-side blip does not read as a code failure.

## Accepted / won't-action

- **A method/path-constrained rule cannot authorise a CONNECT tunnel.** Design
  decision, argued in the README. Do not re-report.
- **`--max-tunnel-bytes` caps tunnels only.** Documented as a resource guard,
  not an exfiltration control.
- **`POST /reload` answers 400 under `--policy-env`.** There is no file to
  re-read; changing the SSM parameter means a new deployment.
- **The Terraform module leaves the admin port closed by default.** Verified
  implemented as a `for_each` over an empty default — no unconditional rule.
- **Terraform is validated, never applied**, and `validate` does not inspect
  `container_definitions`. The `container` CI job is what covers that block.
- **The gate task is the trust boundary**, and the admin plane is separated by
  network placement rather than authentication. Both are stated in the threat
  model.
