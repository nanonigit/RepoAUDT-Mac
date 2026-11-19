# Commit-pinned audit requirements

- A GitHub repository URL, branch URL or full commit URL must resolve to one immutable commit before scanning.
- Every finding must inherit the scanned revision. A stale or dirty worktree must not stand in for GitHub.
- Source provenance must distinguish an explicit local scan from a fetched GitHub revision.
- A failed acquisition must leave previous results and the user's checkout intact.
