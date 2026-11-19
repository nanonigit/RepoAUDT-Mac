# GitHub REST transport

Provide an explicit switch for the live evidence and commit-resolution reads when the GitHub CLI can supply its local credential but its HTTP client cannot reach GitHub. Preserve the existing default, permissions, pinned revisions and diagnostics. Keep credentials out of command arguments, state, and error messages.
