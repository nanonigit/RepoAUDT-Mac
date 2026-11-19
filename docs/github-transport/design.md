# GitHub comparison transport

Backend-only work. Lazyweb is out of scope.

Keep reads on the fixed GitHub host and use the local GitHub CLI. Normalize the child process working directory and input handling for desktop launch. Classify stderr locally. Error details shown to the caller must come from a closed list or a sanitized HTTP status. Do not copy credentials between environments.

Check whether the GitHub CLI has a local credential by discarding all command output and using its exit status. Report that separately from API connectivity. Source comparison of an explicit branch stays on that branch. Commit URLs and default-branch scans compare against the repository default branch.
