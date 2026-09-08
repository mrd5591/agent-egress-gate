# Deep-dive repo notes

Binding for this repository only, layered on the generic skill instructions.

## `main` is protected — land via pull request, never a direct push

Branch protection requires a pull request and every required check green, and
it is **enforced for administrators**. `git push origin main` is refused, and so
is `gh pr merge --admin`. Step 7d's direct merge-and-push cannot work here, and
a run that tries it will fail at the push with a protected-branch error rather
than anything wrong with the code.

Land the run's branch this way instead:

```bash
git push -u origin <run-branch>
gh pr create --fill --base main
gh pr merge --squash --delete-branch     # once the required checks are green
```

Required checks on `main`: `go (ubuntu-latest, 1.25)`, `go (windows-latest, 1.25)`, `lint`, `vulncheck`, `container`, `terraform`.

A run is not finished until the PR is merged and `origin/main` carries the
commit. Verify with `git -C <repo> fetch && git log origin/main -1` before
reporting done — a green PR that was never merged is an unfinished run.

Squash is the house default at the PR boundary: a run's internal fix-branch
merges are noise on `main`, and the PR body preserves the detail.
