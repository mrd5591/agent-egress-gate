# Deep-dive deferrals

Findings this repo has seen and not yet closed. Each entry carries a **class**
(`money` > `step` > `hours`; `hygiene` is never filed), an **effort** (`small` =
one sitting and one gate, or `own-pr`), and a **run count**. Selection order for
a debt pass is class, then effort, then run count.

Closed items move to `resolved.md`. They are not kept here.

Ceiling on `## Open`: 20. Rulings cap: 5.

## Open

_(none — the 2026-09-08 debt pass drained the ledger. See `resolved.md`.)_

The one thing that pass could not do locally, and which is worth knowing before
the next one: `go test -race` still cannot run on this machine (no C compiler,
so cgo is unavailable and `-race` requires it — re-verified, not inherited from
the prior note). Every concurrency claim about the new tunnel-shutdown code is
therefore source-reading plus non-race test execution. CI runs the race
detector, and it is the gate that matters for that code.

Terraform, by contrast, **was** executed this pass: `fmt -check`, `init
-backend=false` and `validate` all ran locally against both the module and the
example, closing a coverage gap that had been carried since the first pass.
`tflint` and `govulncheck` remain CI-only.

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
- **The policy's ports and the security group's ports are not cross-checked.**
  Raised and closed as far as it can be: `upstream_ports` now exists so the
  deployment *can* be widened, and the README states the obligation. Terraform
  cannot verify the pair, because the policy lives in an SSM parameter the
  module never reads — by design. Do not re-file this as an open gap; it is a
  documented operator obligation.
