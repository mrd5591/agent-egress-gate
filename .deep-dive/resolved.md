# Deep-dive resolved

Closed findings, newest first. Historical audit trail: this file is **not**
loaded at the start of a run and must never be pasted into an agent prompt.

## 2026-09-08 (debt pass)

A debt-burn pass that drained the whole `## Open` ledger: ten entries, closed
together because eight of them were `small` and the two `own-pr` items were the
two the product's central claim rested on. Every claim below was verified by
execution, not by reading, except where it says otherwise.

### `money` · FIXED — A tunnel open at shutdown leaves no audit record

The one that mattered most. A CONNECT record is written when the tunnel closes,
`http.Server.Shutdown` deliberately does not wait on hijacked connections, and
nothing tracked them — so a tunnel open at SIGTERM, which at the end of a CI job
is *every* tunnel, was simply absent from the evidence, and could also race the
chain-head print.

`Handler` now registers each hijacked tunnel under a mutex, and `Shutdown(ctx)`
closes both ends of every live tunnel and waits for each to write its record
before returning. `serve` calls it after the servers stop and before reading the
head, so the head it prints covers the tunnels. Registration and the closing
flag share one mutex, so a tunnel either registers before the snapshot and is
waited for, or is refused — the race has no third outcome.

A CONNECT arriving during shutdown is refused **before the dial**, with a real
503, so a stopping gate opens no upstream connection it will not audit. The
narrow window past the hijack (where the 200 has already gone and no HTTP
response is possible) closes the connection and still writes a record: the
failure mode being closed is "a tunnel with no trace", and that includes one
refused late.

Five tests: a single open tunnel audited at shutdown, four tunnels audited with
a contiguous sequence, the post-shutdown 503 and its record, the deadline path
reporting stranded tunnels rather than hanging, and the `activeTunnels`
bookkeeping.

### `money` · FIXED — `verify` exits 0 on an empty log

`--min-records N` (default 0, so the old behaviour is untouched). An empty or
whitespace-only log verifies as `chain intact: 0 records`, exit 0, which a
consumer wired to the exit status cannot tell apart from "everything verified" —
so a gate that was never in the traffic path read as a healthy one. Tested
against an empty file, a whitespace-only file, and floors above and below a real
log; documented in the README next to `verify`.

### `money` · FIXED — Audit log group can be destroyed silently

`lifecycle { prevent_destroy = true }` on `aws_cloudwatch_log_group.gate`. The
group's name derives from `var.name`, so renaming the module instance would have
deleted the evidence artefact as a side effect of a rename.

Not governed by a variable, and the comment says why: Terraform requires a
literal there and rejects a `var` reference. Removing the guard is therefore an
edit to `main.tf`, which is the right amount of friction.

### `step` · FIXED — `check` and `serve` disagree on dot-segment paths

`normalisedPath` is now exported as `proxy.NormalisedPath`, and `cmdCheck` calls
it in the same position the proxy does — before the policy is consulted — so
`check GET http://h/allowed/../secret` reports **refused** where it used to
report allow. That was the one direction `check` promises never to be wrong in.

The check is scoped to the plain-HTTP path: an https URL is modelled as a
CONNECT tunnel, which carries no path, and a test pins that a tunnel still gets
an ordinary answer rather than a spurious refusal.

### `step` · FIXED — ECS service races its execution-role policy

`depends_on = [aws_iam_role_policy.execution]` on `aws_ecs_service.gate`. The
task definition referenced the execution *role*, giving Terraform an edge to the
role but none to the inline policy, so tasks could launch before the policy
existed, fail the image pull or `GetParameters`, and trip the deployment circuit
breaker on a correct configuration.

### `step` · FIXED — Gate egress is hardcoded to 80/443

The two egress rules became one `for_each` over `var.upstream_ports`
(default `[80, 443]`, validated non-empty, in range, and duplicate-free). Two
`moved` blocks carry the old addresses across, so upgrading the module does not
destroy and recreate the gate's only egress — which for the length of an apply
would be an outage of the thing every agent routes through.

The other half of the finding — "or reject a policy naming a port the deployment
cannot reach" — is **not** implemented, and the reason is now recorded in three
places rather than discovered from a timeout: the policy lives in an SSM
parameter the module never reads, so Terraform cannot see the pair at all. The
README states the operator obligation, the variable's own description states it,
and it is filed under Accepted rather than left looking open.

### `hours` · FIXED — Transport has no idle or handshake bounds

`IdleConnTimeout`, `MaxIdleConns`, `MaxConnsPerHost` and `TLSHandshakeTimeout`
are now set. Zero means *unlimited* for these on `http.Transport`, so the gate
had been holding an idle socket for every upstream it had ever contacted.

Three mirror `http.DefaultTransport` (90s, 100, 10s). `MaxConnsPerHost` has no
DefaultTransport value to mirror — DefaultTransport leaves it unlimited — so 64
was chosen and the reasoning written down. They are `Config` fields, and `New`
fills any left at zero, because `cmd/egressgate` assembles its `Config` field by
field from flags and would otherwise opt out of every bound by omission. Both
halves are tested: defaults applied, explicit values preserved.

### `hours` · FIXED — A rotated log segment cannot be verified

`audit.VerifyFrom(r, head, seq)` added; `Verify` is now it, from genesis.
`verify --from-head HASH --from-seq N` exposes it. A segment written by `Resume`
into a fresh file used to report BROKEN — `sequence jumped from 0 to 4` — which
was a correct answer to the wrong question.

`--from-seq` without `--from-head` is a usage error rather than a silent
verify-from-genesis, and a segment spliced onto the wrong predecessor still
fails: the flag is a way to read a segment, not a way to launder a break.

### `hours` · FIXED — Audit timestamps are not sortable

`audit.TimeFormat` is RFC 3339 with the nanoseconds always written out,
replacing `time.RFC3339Nano`, whose fraction trims trailing zeros — so a
timestamp on a microsecond boundary was shorter than its neighbours and sorted
before times that preceded it.

**No existing log is invalidated.** The chain hashes each record's TS string as
written, so old records verify unchanged; the format is an output choice, not
part of the hash definition. `TestHashIsStableForAKnownRecord`'s hand-derived
constant is byte-identical after the change — it now pins `TS` explicitly, which
is what it should always have done, since that test is a statement about the
hash function over fixed bytes rather than about the default clock's layout.
The new test also asserts the *old* layout genuinely mis-sorted, so it is not
pinning something that was already true.

### `hours` · FIXED — `tflint --init` has no retry and fails on a GitHub API blip

Both halves, because they cover different paths. `actions/cache` on
`~/.tflint.d/plugins`, keyed on the tflint version and the `.tflint.hcl` hash,
so the common path makes no network call at all; and a three-attempt bounded
retry with a widening pause for the cache-miss path. A genuinely broken config
still fails, ~30s later. This step had gone red twice for reasons unrelated to
the code it lints: a 403 rate limit and a 500 on `checksums.txt.sig`.

### Verification for this pass

`go build`, `go vet`, `golangci-lint run` (0 issues), and `go test -shuffle=on
-covermode=atomic ./...` all green. Coverage **93.7%**, up from the 93.2%
baseline, against a 90% floor.

Terraform was executed locally for the first time in this repo's history,
closing a standing coverage gap: `fmt -check -recursive`, and `init
-backend=false` + `validate` against both the module and the example. All clean.

Still not run locally: `go test -race` (no C compiler on this machine — cgo is
unavailable and `-race` requires it; re-verified this pass rather than
inherited), `tflint`, and `govulncheck`. CI runs all three.

## 2026-09-08 (later)

### `hours` · FIXED — Base images float while every tool is pinned

Both `Dockerfile` bases are now pinned by digest alongside their tags
(`golang:1.27-alpine@sha256:cf6fca66…`, `alpine:3.24@sha256:28bd5fe8…`), so the
two inputs that actually ship are pinned as tightly as terraform, tflint,
golangci-lint and govulncheck already were. A tag is mutable; the image CI
verified and the image a later build produced need not have been the same bytes.

Found in the same pass that the Docker ecosystem was added to
`.github/dependabot.yml`, which immediately reported both images four and seven
versions behind. Dependabot updates a digest pin in place, so it now keeps them
current rather than letting them drift the other way. Build verified locally
against both digests, and the `container` job exercises the resulting image.

## 2026-09-08

### `money` · RULED — Chain continuity is unachievable in the shipped config

Filed run 1 as a design gate with the default "leave it documented and do not
build cross-restart continuity". Ruled that way rather than left to age out.

The deployed model is one chain per task instance: the task definition writes
audit records to stdout, so there is no file to read back and `Resume` never
runs. `awslogs-stream-prefix` gives each task its own CloudWatch stream, so the
concurrent chains under `desired_count = 2` do not interleave — each stream is a
complete, independently verifiable chain covering one task's lifetime.

Closed by documenting that model precisely (README, "What the chain means on
ECS", including a table of what the chain does and does not detect) and scoping
the restart-continuity bullet to `--audit <file>`, which is the only mode where
it was ever true. Threading the head through SSM or a sidecar was rejected: it
is a larger product than the gate, and it puts a write dependency on the
start-up path of the component whose job is to not be bypassable.

### `money` · FIXED — CloudWatch stream is not directly verifiable

Filed run 1 as a design gate with the default "ship a documented extraction
one-liner rather than adding a quiet mode". Fixed that way.

`awslogs` merges stderr into the audit stream, so the deployed log does not
parse: `chain BROKEN at record 1 ... invalid character 'l'`, from a `listening:`
line. Closed by `scripts/extract-audit.sh` plus a README recipe, and — the part
that keeps it closed — a `container` CI step that captures the merged
presentation, asserts `verify` **fails** on it, then asserts extraction recovers
a stream byte-identical to the stdout log. The negative control is load-bearing:
without it the extraction could become a no-op and the step would still pass.

The job previously could not see this defect at all, because `docker logs` keeps
the streams apart — the same shape as every other bug this repo has had.
