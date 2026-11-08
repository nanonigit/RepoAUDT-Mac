# RepoChex — Remote Agent Instruction & Architecture Guide

This document guides Google Antigravity Remote Agents (running in Google-managed cloud virtual machines) to understand, build, and extend the **RepoChex** codebase.

---

## 1. Project Overview & Architecture
RepoChex is a native macOS + WebUI Studio for GitHub repository architecture visualization, sequence flow tracking, and CodeRabbit AI security & code-quality auditing.

- **Frontend / WebUI**: `Resources/webui/index.html` (Bilingual: Japanese & English, Mermaid.js diagram viewer, PanZoom, interactive inspectors).
- **Backend Generator & API**:
  - `Resources/backend/analyzer.py`: GitHub API & local repository scanner, AST parser, ecosystem builder, CVE & CodeRabbit issue collector.
  - `Resources/backend/portal_builder.py`: Generates the complete single-file interactive WebUI portal (`Resources/webui/index.html`).
  - `Resources/backend/server.py`: Local lightweight HTTP & REST API server (default port: `18765`).
  - `Resources/backend/security_audit_engine.py`: Vulnerability & architectural risk analysis engine.
- **Native macOS Shell**:
  - `Sources/AppDelegate.swift`, `Sources/MainWindowController.swift`: Swift WKWebView native host container.
  - `build.sh`: Builds and code-signs `/Applications/RepoChex.app`.

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

## 3. Remote Agent Execution Runbook
When tasked with features, improvements, or refactorings in a Remote Agent cloud sandbox:
1. Always preserve the bilingual support (`I18N` dictionaries in `portal_builder.py`).
2. When modifying the UI or backend analysis logic, regenerate the portal HTML and ensure no syntax or execution errors occur.
3. Keep commit messages clear, descriptive, and pushed directly to `main` or a feature branch for user review.
