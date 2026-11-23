"""Unit tests for Phase 2: CycloneDX SBOM export, OSS license audit, and PDF report generation."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import server  # noqa: E402
import source_scanners  # noqa: E402
import triage_engine  # noqa: E402


class TestPhase2SbomLicensePdf(unittest.TestCase):
    def test_parse_trivy_licenses_flags_copyleft_and_summarizes_permissive(self) -> None:
        raw = json.dumps(
            {
                "Results": [
                    {
                        "Target": "package-lock.json",
                        "Licenses": [
                            {"PkgName": "react", "Name": "MIT", "Category": "permissive", "Severity": "UNKNOWN"},
                            {"PkgName": "typescript", "Name": "Apache-2.0", "Category": "permissive", "Severity": "UNKNOWN"},
                            {"PkgName": "chroma-lib", "Name": "BSD-3-Clause", "Category": "permissive", "Severity": "UNKNOWN"},
                            {"PkgName": "agpl-pkg", "Name": "AGPL-3.0-only", "Category": "restricted", "Severity": "HIGH"},
                            {"PkgName": "gpl-pkg", "Name": "GPL-3.0-or-later", "Category": "restricted", "Severity": "MEDIUM"},
                        ],
                    }
                ]
            }
        )
        findings, summary = source_scanners.parse_trivy_licenses(
            raw,
            ["package-lock.json"],
            lambda _path: "frontend",
        )
        self.assertEqual(summary["MIT"], 1)
        self.assertEqual(summary["Apache-2.0"], 1)
        self.assertEqual(summary["BSD"], 1)
        self.assertEqual(summary["copyleft_risk"], 2)
        self.assertEqual(len(findings), 2)
        for item in findings:
            self.assertEqual(item["category"], "license")
            self.assertEqual(item["priority_tier"], "P2")
            self.assertIn(item["rule_id"], {"AGPL-3.0-only", "GPL-3.0-or-later"})
            self.assertEqual(triage_engine.classify_category(item), "license")

    def test_sbom_endpoint_by_diagram_id_and_strict_trivy_missing(self) -> None:
        saved_state = {
            "diagrams": [
                {
                    "id": "diag-123",
                    "repo": "acme/demo-app",
                    "deps": {
                        "packages": [
                            {"name": "fastapi", "version": "0.115.0", "ecosystem": "PyPI"},
                        ]
                    },
                }
            ]
        }

        captured: list[tuple[int, dict]] = []

        class DummyHandler(server.RepoAUDTRequestHandler):
            def __init__(self, path: str) -> None:
                self.path = path
                self.server_port = 8765
                self.headers = {}
                self.wfile = io.BytesIO()

            def _send_json(self, code: int, payload: object, cache_max_age: int = 0) -> None:
                captured.append((code, payload))  # type: ignore[arg-type]

        with mock.patch.object(server.analyzer, "load_saved_analyses", return_value=saved_state):
            h = DummyHandler("/api/sbom?id=diag-123")
            h.do_GET()
        self.assertEqual(captured[-1][0], 200)
        self.assertEqual(captured[-1][1].get("bomFormat"), "CycloneDX")

        captured.clear()
        with mock.patch.object(server.analyzer, "load_saved_analyses", return_value=saved_state), \
             mock.patch.object(source_scanners, "executable", return_value=None):
            h_strict = DummyHandler("/api/sbom?id=diag-123&strict=1")
            h_strict.do_GET()
        self.assertEqual(captured[-1][0], 503)
        self.assertIn("Trivy", captured[-1][1].get("error", ""))

    def test_build_pdf_audit_html_redacts_secrets_and_includes_summary(self) -> None:
        diagrams = [
            {
                "id": "diag-1",
                "repo": "acme/prod-api",
                "source_revision": {"commit_sha": "abc123456789"},
                "github_posture": {
                    "visibility": "PUBLIC",
                    "default_branch_protected": False,
                },
                "deps": {
                    "license_summary": {"MIT": 10, "Apache-2.0": 4, "BSD": 1, "copyleft_risk": 1},
                },
                "coderabbit": {
                    "action_items": [
                        {
                            "title": "Hardcoded OpenAI key sk-proj-SECRET1234567890ABCDEF and AKIAIOSFODNN7EXAMPLE",
                            "file": ".env.production",
                            "severity": "critical",
                            "priority_tier": "P0",
                            "category": "secrets",
                            "desc": "Secret leaked in .env.production",
                        },
                        {
                            "title": "CVE-2024-0001 in openssl@1.1.1",
                            "file": "Dockerfile",
                            "severity": "critical",
                            "priority_tier": "P1",
                            "desc": "CISA KEV vulnerability",
                        },
                    ],
                },
            }
        ]
        html = triage_engine.build_pdf_audit_html(diagrams, lang="ja")
        self.assertIn("@page", html)
        self.assertIn("acme/prod-api", html)
        self.assertIn("abc123456789", html)
        self.assertIn("PUBLIC", html)
        self.assertIn("P0", html)
        self.assertIn("P1", html)
        self.assertIn("CVE-2024-0001", html)
        self.assertNotIn("sk-proj-SECRET1234567890ABCDEF", html)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", html)
        self.assertIn("[REDACTED", html)


if __name__ == "__main__":
    unittest.main()
