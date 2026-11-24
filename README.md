# RepoAUDT Mac

**English** | [日本語](README.ja.md)

RepoAUDT Mac is a native macOS app for inspecting GitHub repositories, visualizing their architecture, and reviewing security and code-quality findings. **AUDT** stands for **Audit**.

Enter a GitHub repository URL or `owner/repo`, analyze the code, and inspect findings alongside architecture and sequence diagrams. Private repositories require access through your local GitHub / Git credentials. Findings and suggested fixes require review; zero findings do not establish that a repository is safe.

## Features

- **Repository workspace:** saved-repository dashboard with customizable sections, search, active-repository sidebar highlight across views (audit, architecture, execution flow, chat), and repository sorting including **Highest risk score**.
- **Code audits:** static-analysis findings, dependency vulnerability checks, Web/supply-chain config checks (`dangerouslyAllowSVG`, CORS wildcard + credentials, suspicious npm lifecycle hooks, committed keystores/sourcemaps), evidence, affected components, and remediation suggestions. Copy English-first / Japanese-second batch fix requests and save reports for review.
- **Live threat intelligence correlation:** fetches **CISA KEV** (Known Exploited Vulnerabilities) and **GitHub Security Advisories (Critical)** feeds and correlates them against saved repositories' detected stacks, files (`Dockerfile`, `nginx.conf`, `composer.json`, `package.json`, `*.tf`, Kubernetes Ingress), and known CVEs. Automatically refreshes on **Analyze All**, via **Fetch Live**, and is included in copied batch audit reports.
- **Remediation request tracker:** tracks Slack and GitHub Issue remediation requests per finding with elapsed days, `All` / `Unrequested` / `Requested` filters, automatic resolution on re-scan, and one-click GitHub Issue creation via `gh issue create`.
- **Runtime inventory and security updates:** list repository-declared images, runtime pins and compatibility settings. Upstream lookups cover PHP, nginx, Node.js, Go and PostgreSQL. Findings link to the official advisory or security release and show the documented fixed version when available.
- **Multi-scanner integration:** combines **Gitleaks** (working tree and Git commit history), **TruffleHog** (offline `--no-verification`), **Trivy** (SCA & IaC), **Semgrep**, **Hadolint** (Dockerfile), **Ruff**, and **zizmor**. Secret findings are redacted in source previews and reports, with CLI status shown in **Runtime & Updates**.
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
brew install zizmor ruff gitleaks trufflehog trivy semgrep hadolint
```

Run **Re-scan** to include installed CLI scanner results in a saved audit. You can verify installation status for all seven scanners in **Runtime & Updates**. zizmor checks up to 25 local workflow files offline without receiving any GitHub token. When any optional CLI is missing, times out, or fails to parse an input, built-in checks continue to run and scan status is recorded in the audit and MCP reports.

Gitleaks scans both tracked working-tree snapshots and Git commit history, and TruffleHog runs in offline mode (`--no-verification`) with deduplication against HEAD findings. Hadolint audits `Dockerfile` definitions, Trivy covers SCA & IaC, and Semgrep & Ruff analyze source code.

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

For official Docker images, the inventory can resolve simple numeric `ARG` defaults declared before the first `FROM`. It records the argument and image declaration lines and checks the default against the official feed. A build-time override can change the version. Unresolved expressions and digest-pinned images keep their existing unresolved status.

## Source revision

A GitHub repository URL resolves to the default branch's current commit. You can also specify `/tree/<branch>` or `/commit/<full-sha>`. Encode slashes in branch names as `%2F`. The audit checks out the verified commit and tree in an isolated temporary directory. The MCP audit report includes the source revision. Explicit local paths are recorded as local working-tree scans. Background refresh applies to single-repository default-branch scans. Explicit commit and branch scans remain pinned. A branch scan compares against that branch. GitHub diagnostics report local credential availability and API connectivity separately. Use **Verify diff locally** in a supported authorization finding to compare the same static rule before and after applying the recorded patch in a disposable directory.

In a supported authorization finding, enter the full SHA of a descendant commit and select **Check commit locally** to rerun the original rule on the same file. The matching local checkout must contain both commits. The result identifies both revisions and reflects local Git objects.

If the GitHub diagnostic finds a local credential but the API connection fails only inside RepoAUDT Mac, inspect outbound rules for the app and the GitHub CLI (`gh`) it launches. An app-specific rule can block connections to `github.com` even when `gh` works from a terminal. Recorded audit evidence is still available on supported findings, and the UI marks the current GitHub source as unavailable until a live read succeeds.

When the GitHub CLI can supply its local credential but its HTTP requests fail, quit RepoAUDT Mac and launch it with `open --env REPOAUDT_GITHUB_TRANSPORT=rest -a "/Applications/RepoAUDT Mac.app"`. This launch uses the same credential for read-only REST requests to GitHub and independently verifies the Git checkout when scanning.

In a finding that has a suggested command, select **Copy command** and review it in your own Terminal. The old embedded shell endpoint returns HTTP 410.

## Verification and current scope

For supported commit-pinned authorization findings, open **Private disclosure draft** to review or edit a draft and copy it. The repository's **Security policy** link opens separately so you can identify the maintainers' private channel. The draft is local to the current view.

```bash
node --test tests/ui/test_disclosure_draft.js
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
python3 -m unittest discover -s tests/github-transport -v
python3 -m unittest discover -s tests/diff-verification -v
```

The verification run passed 197 existing tests, 8 connection tests, 3 palette tests, 5 audit evidence tests, 4 workflow-audit tests, 5 source-scanner tests, 6 runtime-patch tests, 5 source-revision tests, 5 authorization-evidence tests, 3 recorded-source tests, 4 GitHub transport tests, and 4 diff-verification tests. The palette tests cover 46 foreground/background pairs across light and dark themes, each with a contrast ratio of at least 4.5:1. This is token-level verification, not an accessibility certification of every screen.

Local LLM requests were verified with a mock HTTP server; a live Ollama / LM Studio model was not tested. MCP tool discovery and snippet scanning were also checked in the installed app. The complete PR submission, progress tracking, and fix-verification workflow remains outside this delivery's completed scope.

## Design and implementation notes

The following implementation documents are currently in Japanese:

- [UI requirements](docs/ui-redesign/requirements.md)
- [UI design](docs/ui-redesign/design.md)
- [Color roles, references, and contrast checks](docs/ui-redesign/colors.md)
- [Verification record](docs/ui-redesign/verification.md)
- [Local diff verification](docs/diff-verification/design.md)
- [Recorded-source design](docs/recorded-source/design.md)
- [Authorization evidence](docs/authorization-evidence/design.md)
- [Commit-pinned source](docs/commit-pinned-audit/design.md)
- [Runtime patch design](docs/runtime-patches/design.md)
- [Source scanner selection and scope](docs/source-scanners/design.md)
- [Audit tool evaluation and design](docs/audit-tools/design.md)
- [Audit evidence design](docs/audit-evidence/design.md) and [incident review](docs/audit-evidence/incident.md)

When features, setup instructions, or verification scope change, update both this English README and [the Japanese README](README.ja.md) together.
