# Design

Lazyweb's GitHub code-review reference places change context beside review status. Put a compact, expandable status check in the repository audit header. Accept a PR number or the matching base-repository URL. Use the existing authenticated read transport. The summary includes open, draft, closed or merged, head and base, and update dates. A synthetic test-merge commit is excluded until GitHub confirms a merge. The user can copy the integrated SHA to the local re-audit control. See [GitHub's pull request endpoint](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request).
