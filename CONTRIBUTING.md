# Contributing

- Use pull requests for every change after repository bootstrap.
- Keep changes small and independently reviewable.
- Every functional scanner fix or check begins with a test shown failing before
  the implementation is applied.
- Report the exact pull-request head and tree for owner-requested external
  review. After approval, a maintainer applies `claude-reviewed` to release the
  required exact-head check. Any new push removes the label and invalidates the
  check; do not merge until the new head is reviewed.
- Every commit author and committer email must end in
  `@users.noreply.github.com`, except GitHub's own `noreply@github.com`.
- Scanner behavior is read-only. Do not add repair, mutation, quarantine,
  telemetry, or implicit network access.
