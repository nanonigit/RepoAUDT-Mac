"""Unit tests for ASPM Platform features: coverage matrix, criticality risk score, release gate, and 90-entry history."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import aspm_engine  # noqa: E402
import server  # noqa: E402


class TestAspmPlatform(unittest.TestCase):
    def test_coverage_matrix_all_six_domains(self) -> None:
        diagram = {
            "id": "d-1",
            "repo": "acme/web",
            "github_posture": {"visibility": "PUBLIC", "default_branch_protected": False},
            "deps": {
                "packages": [{"name": "react", "version": "19.0.0"}],
                "source_scan": {"trivy": "complete", "semgrep": "complete"},
                "workflow_scan": {"status": "no_workflows"},
            },
            "coderabbit": {
                "action_items": [
                    {"title": "Hardcoded API key", "category": "secrets", "priority_tier": "P0", "file": ".env:1"}
                ]
            },
        }
        cov = aspm_engine.compute_coverage_matrix(diagram)
        self.assertEqual(cov["secrets"]["status"], "issues")
        self.assertEqual(cov["secrets"]["count"], 1)
        self.assertEqual(cov["sca"]["status"], "clean")
        self.assertEqual(cov["sast"]["status"], "clean")
        self.assertEqual(cov["cicd"]["status"], "not_applicable")
        self.assertEqual(cov["iac"]["status"], "clean")
        self.assertEqual(cov["posture"]["status"], "issues")

        unscanned = aspm_engine.compute_coverage_matrix({"id": "d-empty", "repo": "acme/empty"})
        for domain in ("secrets", "sca", "sast", "cicd", "iac", "posture"):
            self.assertEqual(unscanned[domain]["status"], "unscanned")

    def test_criticality_weighting_and_portfolio_sort(self) -> None:
        base_items = [{"title": "SSRF", "priority_tier": "P1", "severity": "high", "file": "api.py:10"}]
        d_tier1 = {"id": "d1", "repo": "acme/prod", "criticality": "tier1_prod", "coderabbit": {"action_items": base_items}}
        d_tier2 = {"id": "d2", "repo": "acme/internal", "criticality": "tier2_internal", "coderabbit": {"action_items": base_items}}
        d_tier3 = {"id": "d3", "repo": "acme/demo", "criticality": "tier3_demo", "coderabbit": {"action_items": base_items}}

        r1 = aspm_engine.compute_risk_score(d_tier1)["risk_score"]
        r2 = aspm_engine.compute_risk_score(d_tier2)["risk_score"]
        r3 = aspm_engine.compute_risk_score(d_tier3)["risk_score"]
        self.assertGreater(r1, r2)
        self.assertGreater(r2, r3)

        portfolio = aspm_engine.build_aspm_portfolio([d_tier3, d_tier1, d_tier2])
        self.assertEqual([r["id"] for r in portfolio["repos"]], ["d1", "d2", "d3"])

    def test_release_gate_pass_warn_block(self) -> None:
        d_block_p0 = {"id": "1", "coderabbit": {"action_items": [{"priority_tier": "P0", "category": "secrets"}]}}
        self.assertEqual(aspm_engine.evaluate_release_gate(d_block_p0)["gate"], "BLOCK")

        d_block_kev = {
            "id": "2",
            "criticality": "tier1_prod",
            "coderabbit": {"action_items": [{"priority_tier": "P1", "in_cisa_kev": True}]},
        }
        self.assertEqual(aspm_engine.evaluate_release_gate(d_block_kev)["gate"], "BLOCK")

        d_warn = {
            "id": "3",
            "criticality": "tier2_internal",
            "coderabbit": {"action_items": [{"priority_tier": "P1", "in_cisa_kev": False}]},
        }
        self.assertEqual(aspm_engine.evaluate_release_gate(d_warn)["gate"], "WARN")

        d_pass = {"id": "4", "coderabbit": {"action_items": [{"priority_tier": "P2"}]}}
        self.assertEqual(aspm_engine.evaluate_release_gate(d_pass)["gate"], "PASS")

    def test_repo_meta_endpoint_and_history_90_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_file = root / "analyzed_repos.json"
            hist_file = root / "scan_history.json"
            state_file.write_text(
                json.dumps({"diagrams": [{"id": "diag-meta-1", "repo": "acme/core"}]}),
                encoding="utf-8",
            )

            captured: list[tuple[int, dict]] = []

            class DummyPostHandler(server.RepoAUDTRequestHandler):
                def __init__(self, body: dict) -> None:
                    raw = json.dumps(body).encode("utf-8")
                    self.path = "/api/repo/meta"
                    self.server_port = 8765
                    self.headers = {"Content-Length": str(len(raw))}
                    self.rfile = io.BytesIO(raw)
                    self.wfile = io.BytesIO()

                def _send_json(self, code: int, payload: object, cache_max_age: int = 0) -> None:
                    captured.append((code, payload))  # type: ignore[arg-type]

            with mock.patch.object(analyzer, "STATE_FILE", state_file):
                h = DummyPostHandler({"diagram_id": "diag-meta-1", "criticality": "tier1_prod"})
                h.do_POST()
            self.assertEqual(captured[-1][0], 200)
            self.assertEqual(captured[-1][1]["criticality"], "tier1_prod")

            # Verify 90-entry cap on scan history
            for i in range(95):
                analyzer.append_scan_history_snapshot(
                    {"id": "diag-meta-1", "repo": f"acme/core-{i}"},
                    resolved_since_prev=1,
                    new_since_prev=2,
                    history_file=hist_file,
                )
            history = analyzer.load_scan_history(hist_file)
            self.assertEqual(len(history), 90)
            self.assertEqual(history[0]["repo"], "acme/core-5")
            self.assertEqual(history[-1]["repo"], "acme/core-94")


if __name__ == "__main__":
    unittest.main()
