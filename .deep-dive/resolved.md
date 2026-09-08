# Deep-dive resolved

Closed findings, newest first. Historical audit trail: this file is **not**
loaded at the start of a run and must never be pasted into an agent prompt.

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
