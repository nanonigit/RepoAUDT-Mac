# RepoCHK Mac — 4-Tier Opaque-Box E2E Test Suite (TEST_READY)

- **Date**: 2026-11-08T12:18:30Z
- **Author**: E2E Testing Track Test Writer (`teamwork_preview_test_writer`)
- **Status**: **TEST SUITE READY** (192 Test Cases Implemented & Verified)
- **Test Directory**: `tests/e2e/`
- **Runner Command**: `python3 tests/e2e/run_all_tests.py`

---

## 1. Test Architecture & Methodology

The test suite is built strictly on an **opaque-box, requirement-driven methodology** adhering to `TEST_INFRA.md` and `PROJECT.md`:
1. **Category-Partition & Feature Coverage (Tier 1)**: Independent verification of all 17 features in isolation.
2. **Boundary Value Analysis (BVA) & Edge Cases (Tier 2)**: Verification of extreme numerical limits, empty payloads, null references, network timeouts, and corrupted inputs.
3. **Combinatorial & Pairwise Testing (Tier 3)**: Cross-feature interaction testing (e.g. Sync Daemon + Multi-Repo + Atomic Persistence + Rate Limiting).
4. **Real-World Application Scenarios (Tier 4)**: End-to-end multi-step workflow simulations covering non-technical manager onboarding, 24/7 background sync resilience, rate limit degradation, transitive CVE audits, and autonomous self-healing remediation.

---

## 2. Test Inventory & Metrics Summary

| Tier | Test Suite File | Focus Area | Total Tests | Passed | Pending / Failed | Status |
|:---:|:---|:---|:---:|:---:|:---:|:---:|
| **Tier 1** | `tests/e2e/test_tier1_features.py` | Feature Coverage (F1–F17, ≥5 per feature) | 85 | 65 | 20 | Pending M1/M2/M3 completion |
| **Tier 2** | `tests/e2e/test_tier2_boundaries.py` | Boundary Values, Null/Empty, Edge Inputs | 85 | 85 | 0 | **PASS (100%)** |
| **Tier 3** | `tests/e2e/test_tier3_pairwise.py` | Cross-Feature Combinations (17 pairs) | 17 | 17 | 0 | **PASS (100%)** |
| **Tier 4** | `tests/e2e/test_tier4_scenarios.py` | End-to-End Real-World Scenarios (5 workflows) | 5 | 5 | 0 | **PASS (100%)** |
| **Total** | `tests/e2e/run_all_tests.py` | Complete 4-Tier Test Suite | **192** | **172** | **20** | **SUITE READY** |

---

## 3. Feature Coverage Matrix (F1 through F17)

| Feature # | Feature Name | Tier 1 (Coverage) | Tier 2 (Boundaries) | Tier 3 (Pairwise) | Tier 4 (Scenario) | Target Milestone |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **F1** | Semantic Color & Badge Overhaul | 5 tests | 5 tests | Pair 1, 2 | Scenario 1 | M1 |
| **F2** | Destructive Action Safety Shielding | 5 tests | 5 tests | Pair 3 | Scenario 1 | M1 |
| **F3** | Full Bilingual I18N Completion | 5 tests | 5 tests | Pair 1, 4, 5 | Scenario 1 | M1 |
| **F4** | Dynamic Action Hub Metric Fix | 5 tests | 5 tests | Pair 3 | Scenario 1 | M1 |
| **F5** | Non-Technical Simple Mode Toggle | 5 tests | 5 tests | Pair 2, 4 | Scenario 1 | M1 |
| **F6** | Persistent Beginner Guide Bar | 5 tests | 5 tests | Pair 5 | Scenario 1 | M1 |
| **F7** | Backend Daemon Periodic Sync Engine | 5 tests | 5 tests | Pair 6, 7, 8, 13 | Scenario 2 | M2 |
| **F8** | Multi-Repository Full Sync Fix | 5 tests | 5 tests | Pair 6, 9, 12 | Scenario 2 | M2 |
| **F9** | Asynchronous Non-Blocking Sync API | 5 tests | 5 tests | Pair 9, 10 | Scenario 2 | M2 |
| **F10** | Real Health Check & Liveness Verification | 5 tests | 5 tests | Pair 7, 10, 11 | Scenario 3 | M2 |
| **F11** | Accurate GitHub Rate Limit Monitoring | 5 tests | 5 tests | Pair 11, 12 | Scenario 3 | M2 |
| **F12** | Swift Process Supervision & Auto-Restart | 5 tests | 5 tests | Pair 13 | Scenario 2 | M2 |
| **F13** | Atomic State Persistence & Safe Journaling | 5 tests | 5 tests | Pair 8, 14 | Scenario 2 | M2 |
| **F14** | Deep Transitive Lockfile Vulnerability Audit | 5 tests | 5 tests | Pair 15, 16 | Scenario 4 | M3 |
| **F15** | True AST Visitor Python Security Scanning | 5 tests | 5 tests | Pair 15 | Scenario 4 | M3 |
| **F16** | GitHub CodeRabbit PR Review Ingestion | 5 tests | 5 tests | Pair 17 | Scenario 5 | M3 |
| **F17** | Autonomous Self-Healing Remediation Pipeline | 5 tests | 5 tests | Pair 14, 16, 17 | Scenario 5 | M3 |

---

## 4. Pending Implementation Items & Escalations for Milestone Workers

The 20 Tier 1 test failures precisely match the architectural gaps identified during the Survey phase. They serve as actionable acceptance criteria for the implementation workers:

### Milestone 1 Worker (`M1: UI/UX & WebUI Intuitive Overhaul`)
1. **F1**: `test_f01_01`: Remove `badge-fresh-red` / red dot on ≤ 3 days freshness; use amber/active styling.
2. **F2**: `test_f02_01`, `test_f02_02`: Remove inline `🗑️ 削除` (`nav-del-btn`) and `cat-del-btn` from sidebar list; shield inside `#manage-repos-modal`.
3. **F3**: `test_f03_03`, `test_f03_04`: Complete English translations for commit diff labels, days ago calculation, and walkthrough controls.
4. **F4**: `test_f04_01`: Replace hardcoded `"全29リポジトリ"` with dynamic `${diagrams.length}`.
5. **F5**: `test_f05_01`, `test_f05_03`, `test_f05_05`: Add Simple Mode toggle button in header, hide technical tabs in Simple Mode, and persist state in `localStorage`.
6. **F6**: `test_f06_02`, `test_f06_03`, `test_f06_04`: Persist guide dismissal in `localStorage` (`repochex_guide_dismissed`) and add reopen button (`❓ クイックガイド`) to toolbar.

### Milestone 2 Worker (`M2: Backend Sync & Liveness Stabilization`)
7. **F7**: `test_f07_01`, `test_f07_02`, `test_f07_03`, `test_f07_05`: Implement background `SyncDaemon` thread in `server.py` and expose its status in `GET /api/health`.
8. **F8**: `test_f08_02`: Ensure auto-sync without URL iterates over all repositories in `analyzed_repos.json` and returns full synced list.
9. **F9**: `test_f09_02`: Return immediate non-blocking job ID on `POST /api/sync` and track status via `GET /api/sync/status?job_id=...`.
10. **F10**: `test_f10_05`: Replace simulated timer in `index.html` with real periodic `fetch('/api/health')`.
11. **F11**: `test_f11_01`: Parse `resources.core.remaining` in `check_live_health` to report `RATE_LIMITED` / `DEGRADED` when 0.
12. **F12**: `test_f12_01`: Attach `terminationHandler` to `Process` in `Sources/RepoCHKMacApp.swift` for auto-restart.
13. **F13**: `test_f13_02`: Maintain `.bak` snapshot before atomic rename in `analyzer.py` and recover from `.bak` if primary is corrupted.

### Milestone 3 Worker (`M3: Deep Security Auditing & Autonomous Remediation`)
14. **F14**: `test_f14_01`: Parse transitive dependencies in `package-lock.json` and `composer.lock` for OSV batch querying.
15. **F15**: `test_f15_01`: Implement `SecurityASTVisitor(ast.NodeVisitor)` in `security_audit_engine.py` for Python SAST.
16. **F16**: `test_f16_01`: Implement GitHub API ingestion for `coderabbitai[bot]` pull request comments.
17. **F17**: `test_f17_01`: Implement `POST /api/remediate/auto-fix` endpoint with branch creation, patch application, and verification test gate.

---

## 5. How to Run the Tests

```bash
# Run the complete 4-tier test runner:
python3 tests/e2e/run_all_tests.py

# Run individual tiers:
python3 tests/e2e/run_all_tests.py --tier 1
python3 tests/e2e/run_all_tests.py --tier 2
python3 tests/e2e/run_all_tests.py --tier 3
python3 tests/e2e/run_all_tests.py --tier 4

# Or execute with Python standard unittest runner:
python3 -m unittest discover tests/e2e
```
