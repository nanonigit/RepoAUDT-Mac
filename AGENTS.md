# RepoAUDT Mac — Remote Agent Instruction & Architecture Guide

This document guides Google Antigravity Remote Agents (running in Google-managed cloud virtual machines) to understand, build, and extend the **RepoAUDT Mac** codebase.

---

## 1. Project Overview & Architecture
RepoAUDT Mac is a native macOS + WebUI Studio for GitHub repository architecture visualization, sequence flow tracking, and CodeRabbit AI security & code-quality auditing.

- **App Name**: `RepoAUDT Mac` (renamed from legacy RepoChex / RepoChecker across all configs, remotes, and codebases).
- **GitHub Repository**: `https://github.com/nanonigit/RepoAUDT-Mac.git`
- **Frontend / WebUI**: `Resources/webui/index.html` (Bilingual: Japanese & English, Mermaid.js diagram viewer, PanZoom, interactive inspectors).
- **Backend Generator & API**:
  - `Resources/backend/analyzer.py`: GitHub API & local repository scanner, AST parser, ecosystem builder, CVE & CodeRabbit issue collector.
  - `Resources/backend/portal_builder.py`: Generates the complete single-file interactive WebUI portal (`Resources/webui/index.html`).
  - `Resources/backend/server.py`: Local lightweight HTTP & REST API server (default port: `18765`).
  - `Resources/backend/security_audit_engine.py`: Vulnerability & architectural risk analysis engine.
- **Native macOS Shell**:
  - `Sources/RepoAUDTMacApp.swift`: SwiftUI + WKWebView native host container & backend server process manager.
  - `build.sh`: Builds and code-signs `/Applications/RepoAUDT Mac.app`.

---

## 2. Essential Commands

### Build & Regenerate Portal HTML
```bash
python3 -c "
import sys; sys.path.insert(0, 'Resources/backend')
import analyzer, portal_builder
saved = analyzer.load_saved_analyses()
portal_builder.build_portal_html(saved['diagrams'], is_shareable=False)
"
```

### Build Native macOS App (Local macOS Only)
```bash
./build.sh
```

### Start Backend Server (Port 18765)
```bash
cd Resources/backend && python3 server.py --port 18765
```

---

## 3. Handover Context & User Preferences (From Previous Chat)
The following features and UX requirements were implemented and verified with the user:

1. **Bilingual Support (Japanese & English)**:
   - Header contains `🌐 JA / EN` instant toggle button.
   - Text elements use `data-i18n` attributes backed by `I18N` dictionaries in `portal_builder.py`.
   - Never regress to single-language text; all newly added UI elements must have both `ja` and `en` definitions.
2. **Collapsible Accordions**:
   - Sidebar panels (Auto Sync, Search Filters) and Inspector Overview cards (Basic Info, System Responsibility, Processing Logic) are collapsible (`▼` / `▶`).
   - "Collapse All ▲ / Expand All ▼" batch toggle buttons are provided to minimize scrolling.
3. **Structured System Responsibility**:
   - The "System Responsibility" section must clearly explain what the system does in plain language (not raw boilerplate like `bootstrapped with create-next-app`).
   - Managed via `formatSystemResponsibility(...)` with structured duties, domain scopes, and tech foundations.
4. **Per-Issue Report Download**:
   - Each action-required alert provides a `📥 Download Report` (`📥 レポートDL`) button generating standalone markdown reports.
5. **Responsive Toolbar**:
   - Styled via CSS Container Queries (`@container mainpane`) so that buttons switch to icon-only gracefully on narrow pane widths without clipping.

---

## 4. Remote Agent Execution Runbook
When tasked with features, improvements, or refactorings in a Remote Agent cloud sandbox:
1. Pull latest commits: `git pull origin main`.
2. Always preserve the bilingual support (`I18N` dictionaries in `portal_builder.py`).
3. When modifying the UI or backend analysis logic, regenerate the portal HTML and ensure no syntax or execution errors occur.
4. Keep commit messages clear, descriptive, and pushed directly to `main` or a feature branch for user review.
