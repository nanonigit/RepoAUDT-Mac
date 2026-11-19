# Audit tool design

The integration is backend-only. Lazyweb is out of scope. Findings use the existing audit view, reports and MCP report tool.

| Candidate | Decision |
| --- | --- |
| [zizmor](https://docs.zizmor.sh/audits/) | Adopt offline. Structured workflow checks extend the existing regex-based checks with rules such as action pinning and checkout credential persistence. |
| [actionlint](https://github.com/rhysd/actionlint) | Consider separately for YAML and expression correctness. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | The existing OSV API already handles common dependency advisories. Evaluate lockfile coverage before adding another scanner. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | A later option for broader secret and commit history coverage. Separate working-tree and history scans to keep scope clear. |
| [GitHub MCP](https://docs.github.com/en/copilot/how-tos/copilot-in-your-ide/customize-copilot/extend-copilot-with-tools-and-context/configure-toolsets) | Useful for authorized GitHub security data. This local workflow scan needs no extra toolsets or token scopes. |
| [MUSUBI security-auditor](https://github.com/nahisaho/MUSUBI) | A review framework for triage and remediation. Detection in this integration uses engine output. |

Use an installed Homebrew executable at an absolute path. Copy bounded regular workflow files to a temporary directory. Use offline SARIF mode with independent rules and ignore settings, no inherited credentials, no fixes, and a timeout. Convert only rule IDs and line locations for staged files. Keep built-in findings that the external scanner does not corroborate. During a complete run, merge the reports and deduplicate the same rule at the same line. If the external scanner is unavailable or fails, keep built-in results and record the scanner status.
