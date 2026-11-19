# RepoAUDT Mac

**English** | [日本語](README.ja.md)

RepoAUDT Mac is a native macOS app for inspecting GitHub repositories, visualizing their architecture, and reviewing security and code-quality findings. **AUDT** stands for **Audit**.

Enter a GitHub repository URL or `owner/repo`, analyze the code, and inspect findings alongside architecture and sequence diagrams. Private repositories require access through your local GitHub / Git credentials. Findings and suggested fixes require review; zero findings do not establish that a repository is safe.

## Features

- **Repository workspace:** saved-repository dashboard, search, audit results, architecture diagrams, and execution flows.
- **Code audits:** static-analysis findings, dependency vulnerability checks, evidence, affected components, and remediation suggestions where available. Copy fix prompts and save reports for review.
- **Runtime inventory and security updates:** list repository-declared images, runtime pins and compatibility settings. Upstream lookups cover PHP, nginx, Node.js, Go and PostgreSQL. Findings link to the official advisory or security release and show the documented fixed version when available.
- **Python quality and secret candidates:** Ruff checks selected Python rules for issues such as undefined names and unused imports. Gitleaks scans tracked files for potential credentials. Secret findings are redacted in source previews and reports.
- **GitHub Actions audit:** optionally add [zizmor](https://docs.zizmor.sh/audits/). The app scans workflow copies offline and merges findings with its built-in checks. Open a finding for the file, line, and rule documentation.
- **Authorization evidence:** for supported GitHub-pinned Python HTTP handlers, findings trace the request entry, authorization boundary, input and privileged operation. The finding includes redacted recorded snippets, exact source links and a statically checked defensive patch. Recorded evidence remains available independently of live GitHub comparison.
- **Current source and history:** open a finding to see its audited and current source lines with commit links, the default branch's latest commit, the repository's last push, and the file's last change. Live evidence uses authenticated GitHub CLI access.
- **Audit chat:** start in the sidebar or from a finding. Each question checks GitHub again and sends the question, recent messages, and comparison metadata to the configured AI provider. Source lines stay in the workspace.
- **Native navigation:** a macOS sidebar and toolbar, optional detail inspector, and Japanese / English switching, aligned with NetworkPNTR Mac and NetworkISPR Mac.
- **Consistent colors:** light and dark appearances share semantic roles. Blue identifies actions and selection, red marks serious findings or failures, amber indicates caution, and green denotes confirmed success. Labels and symbols accompany severity colors.
- **Cloud AI:** settings and connection tests for OpenAI, Claude, Gemini, and Groq, using the existing audit integrations.
- **Local LLM:** connect to a loopback OpenAI-compatible API using its base URL and model identifier. An API key is optional.
- **MCP server:** seven tools for repository listings, architecture, security reports, repository analysis, snippet scanning, CycloneDX SBOM export, and SARIF export, available over stdio or local HTTP.
- **MCP client:** connect to stdio or HTTP servers, inspect tool schemas, enter JSON arguments, and explicitly run tools.

## Requirements

- Apple Silicon Mac running macOS 14 or later; the build script currently targets `arm64`.
- Xcode Command Line Tools with `swiftc`.
- Python 3, installed at `/opt/homebrew/bin/python3`, `/usr/local/bin/python3`, or `/usr/bin/python3`.
- Git and appropriate GitHub credentials for repositories you want to analyze. The analyzer can use local `gh` / Git authentication.
- Internet access for GitHub, vulnerability lookups, and cloud AI when those features are used. Local inference requires a separately running compatible model server.

## Build and install

```bash
./build.sh --install
```

The app is installed at `/Applications/RepoAUDT Mac.app`.

To build a bundle in the repository without installing it:

```bash
./build.sh --no-install
```

## Optional local scanners

```bash
brew install zizmor ruff gitleaks
```

Run **Re-scan** to add zizmor results to a saved audit. The app checks up to 25 local workflow files. zizmor receives no GitHub token or repository configuration. The app retains built-in checks when zizmor is missing, times out or cannot parse an input. The MCP audit report includes scan status.

Ruff and Gitleaks run on temporary copies of tracked working-tree files. The combined source scan is limited to 3,000 files, 256 KiB per file and 32 MiB in total. Gitleaks checks the current snapshot. The MCP audit report includes coverage status for both tools.

## Getting started

1. Open RepoAUDT Mac and choose **Add Repository**.
2. Enter a GitHub URL or `owner/repo`, then start analysis.
3. Select a repository and open audit results, architecture, or execution flows from the sidebar. Open details when needed.
4. Configure a provider in **AI Connections** to use AI analysis. For local inference, enter the base URL and the exact model identifier exposed by your server, then save and test.
5. Open **MCP** to copy the app's server configuration or configure an external server as a client. Review tool arguments before running a tool.

Saved analysis belongs to the recorded commit and can become outdated. Run analysis again to inspect newer code.

## Runtime patch coverage

Open **Component inventory and security updates** after re-scanning. The report includes Dockerfile and YAML images, version files, toolchain declarations and known compatibility fields. Vendor-unmapped images, unresolved tags and feed failures have separate statuses. The scan reads up to 200 declaration files and records up to 300 entries. It checks up to 16 pins per supported product, and shows the first 15 matching advisories per pin in the audit view. The structured MCP audit report contains the match list for checked pins.

PHP checks the latest 50 public php-src advisories and the upstream unsupported-branches page. nginx and PostgreSQL use official product advisories. Node.js and Go report their own branch's security releases. When a PHP advisory names affected functions, the app looks for those names in up to 120 PHP files. Results indicate possible source locations, with reachability and deployed versions unverified. Package-manager backports, base-image contents, and arbitrary dynamically resolved versions require separate evidence.

## Source revision

A GitHub repository URL resolves to the default branch's current commit. You can also specify `/tree/<branch>` or `/commit/<full-sha>`. Encode slashes in branch names as `%2F`. The audit checks out the verified commit and tree in an isolated temporary directory. The MCP audit report includes the source revision. Explicit local paths are recorded as local working-tree scans. Background refresh applies to single-repository default-branch scans. Explicit commit and branch scans remain pinned.

## Verification and current scope

```bash
python3 tests/e2e/run_all_tests.py
python3 -m unittest discover -s tests/connections -v
python3 -m unittest discover -s tests/ui -v
python3 -m unittest discover -s tests/audit -v
python3 -m unittest discover -s tests/audit-tools -v
python3 -m unittest discover -s tests/source-scanners -v
python3 -m unittest discover -s tests/runtime-patches -v
python3 -m unittest discover -s tests/source-revision -v
python3 -m unittest discover -s tests/authorization -v
python3 -m unittest discover -s tests/recorded-source -v
```

The verification run passed 197 existing tests, 8 connection tests, 3 palette tests, 5 audit evidence tests, 4 workflow-audit tests, 5 source-scanner tests, 6 runtime-patch tests, 5 source-revision tests, 5 authorization-evidence tests, and 3 recorded-source tests. The palette tests cover 46 foreground/background pairs across light and dark themes, each with a contrast ratio of at least 4.5:1. This is token-level verification, not an accessibility certification of every screen.

Local LLM requests were verified with a mock HTTP server; a live Ollama / LM Studio model was not tested. MCP tool discovery and snippet scanning were also checked in the installed app. The complete PR submission, progress tracking, and fix-verification workflow remains outside this delivery's completed scope.

## Design and implementation notes

The following implementation documents are currently in Japanese:

- [UI requirements](docs/ui-redesign/requirements.md)
- [UI design](docs/ui-redesign/design.md)
- [Color roles, references, and contrast checks](docs/ui-redesign/colors.md)
- [Verification record](docs/ui-redesign/verification.md)
- [Recorded-source design](docs/recorded-source/design.md)
- [Authorization evidence](docs/authorization-evidence/design.md)
- [Commit-pinned source](docs/commit-pinned-audit/design.md)
- [Runtime patch design](docs/runtime-patches/design.md)
- [Source scanner selection and scope](docs/source-scanners/design.md)
- [Audit tool evaluation and design](docs/audit-tools/design.md)
- [Audit evidence design](docs/audit-evidence/design.md) and [incident review](docs/audit-evidence/incident.md)

When features, setup instructions, or verification scope change, update both this English README and [the Japanese README](README.ja.md) together.
