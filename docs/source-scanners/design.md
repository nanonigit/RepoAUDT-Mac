# Source scanner design

This backend-only integration uses the existing results surface. Lazyweb is out of scope.

| Purpose | Common tools | Decision |
| --- | --- | --- |
| Language lint | [Ruff](https://docs.astral.sh/ruff/linter/), ESLint | Add Ruff for Python diagnostics. |
| Security static analysis | [CodeQL](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning) | Keep existing static checks. Treat CodeQL results as a separate integration. |
| Dependency vulnerabilities | [OSV-Scanner](https://google.github.io/osv-scanner/) | Existing direct OSV queries remain the dependency check. |
| Secret detection | [Gitleaks](https://github.com/gitleaks/gitleaks) | Add built-in Gitleaks rules for the checked-out tracked files. |
| CI workflows | [zizmor](https://docs.zizmor.sh/) | Already integrated. |

Both tools run against a temporary copy of bounded, regular files tracked by Git. Use explicit executable paths and isolated configuration. Skip symlinks, previous commits, external registries, repository execution and automatic fixes. Import only structured rule and location data. Ruff findings are quality observations. Gitleaks findings are candidates that warrant verification. Report any coverage limit or tool error in the MCP audit report.
