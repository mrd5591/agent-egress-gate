# Verification lessons — agent-egress-gate

Project-specific. Consulted when *verifying* a finding, never when discovering
one: every run reads this codebase with fresh eyes.

### The pattern this repo produces: a control real in one layer, absent in the layer that ships

Named in the design spec's postscript and confirmed again. The gate has six
layers — `internal/*` → `cmd/egressgate` wiring → the Dockerfile → the ECS
`container_definitions` → the module's variable defaults → `terraform/example`
— and a control can be correct in one and unreachable in the next. Unit tests
cannot see it, because they test the layer where the control is real.

Run this as a first-class review dimension: *for every control the README
claims, is it reachable in the shipped default configuration?* Trace the claim
down all six layers. Instances found so far, all genuine: a shell invocation
passed to an image with an `ENTRYPOINT`; `--max-tunnel-bytes` documented but
absent from the task definition; chain continuation that needs a file while the
deployment runs on stdout; a stdout-only audit contract that the `awslogs`
driver breaks by merging stderr.

### `terraform validate` cannot see `container_definitions`, and neither can tflint

It is an opaque JSON string. The command, the user, `readonlyRootFilesystem`,
the health check, the log configuration and the port mappings all live inside
it and get zero checking from the `terraform` CI job. Read that block by hand
every pass, and cross-check the `command` array against the actual flag names
in `cmd/egressgate/run.go` — a renamed flag would ship a task that never starts
and no gate would catch it. The `container` job is the only real coverage.

### The `container` CI job does not reproduce ECS in one specific way

It reads `docker logs egci 2>/dev/null`, which discards the container's stderr
because `docker logs` demultiplexes the two streams. The `awslogs` driver does
not: it sends stdout and stderr to one CloudWatch stream. So the job is green
on a log shape the deployment never produces. Any claim about "what the
deployment's log looks like" must be checked against a *merged* stream, not
against that job.

### Verify an audit-chain finding by running the real binary against a crafted log

Cheapest high-confidence loop in this repo, and it catches things reading does
not. Build to a scratch path, run `serve` with a policy that denies everything,
and drive a few requests through the proxy — a denied request needs no upstream
and still writes a record. That gives a genuine multi-record log to mutate.
Then check both halves: what `verify` says, *and* what the gate does when
started on it. They can disagree, and the gate's behaviour is the one that
matters, because the gate can modify the file.

### The race detector cannot run on the usual dev machine here

`go test -race` needs cgo and there is no C compiler on the Windows host, so
`scripts/coverage.sh` cannot run as CI runs it. Run `go test -shuffle=on
-covermode=atomic ./...` instead and say explicitly that the race gate was
delegated to CI. Never report the resulting build failure as a code finding,
and never claim a concurrency conclusion was observed rather than reasoned.

### `-shuffle=on` is in the coverage gate, so declaration-order dependence is already caught

Do not spend budget re-deriving it. What shuffle does *not* catch is worth
checking: wall-clock margins (two tests here rest on 300 ms and 3 s), fixed
ports, and package-level mutable state.

### Coverage here is high and says little about whether the guards can fail

93%+ statement coverage coexisted with a chain-link check, a
`DisallowUnknownFields` call, and the CONNECT no-dial guarantee all having no
test that could fail. Judge this suite by mutation, not by the percentage: for
each security-critical branch, delete it and see whether anything goes red. The
plain-HTTP `countingListener` test in `review_test.go` is the model — it counts
real TCP accepts, not handler invocations, and a handler-count test passes a
mutation that a listener-count test catches.
