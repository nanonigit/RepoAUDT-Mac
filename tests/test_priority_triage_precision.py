"""Unit tests for P0/P1/aggregation priority triage precision."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import security_audit_engine  # noqa: E402
import triage_engine  # noqa: E402


class TestPriorityTriagePrecision(unittest.TestCase):
    def test_no_rce_substring_false_positive_on_source_or_resource(self) -> None:
        source_map_item = {
            "severity": "medium",
            "package_name": "source-map-js",
            "title": "source-map-js: Regular Expression Denial of Service (DoS)",
            "desc": "Inefficient regex in source-map-js.",
            "category": "sca",
        }
        zod_item = {
            "severity": "medium",
            "package_name": "zod",
            "title": "zod: Uncontrolled Resource Consumption in email validation",
            "desc": "Uncontrolled resource consumption leads to DoS.",
            "category": "sca",
        }
        t1, _ = triage_engine.classify_priority_tier(source_map_item, kev_set=set())
        t2, _ = triage_engine.classify_priority_tier(zod_item, kev_set=set())
        self.assertIn(t1, ("P2", "P3"))
        self.assertIn(t2, ("P2", "P3"))

    def test_secrets_and_env_production_are_p0_and_sort_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.production").write_text("DATABASE_URL=postgres://u:p@host/db\n", encoding="utf-8")
            (root / "cfg.py").write_text(
                "AWS_KEY = 'AKIAQWERTYUIOPASDF12'\nOPENAI_KEY = 'sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'\n",
                encoding="utf-8",
            )
            secret_findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _p: "api")
            self.assertGreaterEqual(len(secret_findings), 3)
            for sf in secret_findings:
                self.assertEqual(sf["priority_tier"], "P0")
                self.assertEqual(sf["category"], "secrets")

            p1_item = {
                "severity": "critical",
                "package_name": "next",
                "title": "next RCE vulnerability",
                "desc": "Remote Code Execution in Next.js",
                "category": "sca",
            }
            sorted_items = triage_engine.triage_and_validate_findings(
                [p1_item] + secret_findings,
                repo_id="acme/app",
                kev_set=set(),
            )
            self.assertEqual(sorted_items[0]["priority_tier"], "P0")
            self.assertEqual(sorted_items[-1]["priority_tier"], "P1")

    def test_aggregated_critical_and_p1_keywords_preserve_p1(self) -> None:
        # 1. Aggregated next (CRITICAL + RCE among 39 CVEs)
        advisories = [
            {
                "package": "next",
                "ecosystem": "npm",
                "installed": "14.0.0",
                "severity": "critical",
                "cve": "CVE-2025-29927",
                "title": "Next.js Middleware Authorization Bypass & RCE",
                "summary": "Remote code execution and middleware bypass.",
                "fixed_version": "14.2.25",
                "file": "package-lock.json",
            },
            {
                "package": "next",
                "ecosystem": "npm",
                "installed": "14.0.0",
                "severity": "medium",
                "cve": "CVE-2024-99999",
                "title": "Minor header issue",
                "summary": "Minor issue.",
                "fixed_version": "14.2.25",
                "file": "package-lock.json",
            },
        ]
        grouped = analyzer.group_advisories_by_package(advisories)
        self.assertEqual(len(grouped), 1)
        self.assertIn("[依存関係脆弱性集約]", grouped[0]["title"])
        self.assertEqual(grouped[0]["priority_tier"], "P1")

        # After full triage_and_validate_findings, it must stay P1 (not drop to P2)
        triaged = triage_engine.triage_and_validate_findings(grouped, repo_id="acme/web", kev_set=set())
        self.assertEqual(triaged[0]["priority_tier"], "P1")

        # 2. proxy-addr (CRITICAL / IP spoofing), @auth0/nextjs-auth0 (OAuth), @nestjs/common (execute arbitrary code)
        for pkg, sev, title, desc in [
            ("proxy-addr", "critical", "proxy-addr IP spoofing", "Allows IP spoofing via X-Forwarded-For."),
            ("@auth0/nextjs-auth0", "high", "@auth0/nextjs-auth0 OAuth query parameter injection", "OAuth flow manipulation."),
            ("@nestjs/common", "high", "@nestjs/common arbitrary code", "Allows attacker to execute arbitrary code."),
        ]:
            tier, _ = triage_engine.classify_priority_tier(
                {"package_name": pkg, "severity": sev, "title": title, "desc": desc, "category": "sca"},
                kev_set=set(),
            )
            self.assertEqual(tier, "P1", f"Expected P1 for {pkg}")


if __name__ == "__main__":
    unittest.main()
