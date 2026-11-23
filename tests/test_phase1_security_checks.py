"""Unit tests for Phase 1: MAL-* malware detection, GitHub Posture Check, and EOL detection."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import eol_checker  # noqa: E402
import security_audit_engine  # noqa: E402
import triage_engine  # noqa: E402


class TestPhase1SecurityChecks(unittest.TestCase):
    def test_osv_mal_package_separated_as_p0_critical_malware(self) -> None:
        vulns = [
            {"id": "MAL-2026-1234", "summary": "Malicious exfiltration script"},
            {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Regular CVE"},
        ]
        entries = security_audit_engine._build_osv_advisory_entries(
            "npm", "evil-pkg", "1.0.2", vulns, fetch_details=False
        )
        self.assertEqual(len(entries), 2)
        mal = entries[0]
        self.assertTrue(mal["is_malware"])
        self.assertEqual(mal["category"], "malware")
        self.assertEqual(mal["priority_tier"], "P0")
        self.assertEqual(mal["severity"], "CRITICAL")
        self.assertIn("マルウェアパッケージ検出", mal["title"])
        self.assertIn("アンインストール", mal["summary"])

        grouped = analyzer.group_advisories_by_package(entries)
        mal_item = next(g for g in grouped if g.get("is_malware"))
        self.assertEqual(mal_item["fix_cmd"], "npm uninstall evil-pkg")
        triaged = triage_engine.triage_and_validate_findings([mal_item], repo_id="org/app")
        self.assertEqual(triaged[0]["priority_tier"], "P0")
        self.assertEqual(triaged[0]["category"], "malware")

    def test_github_posture_fetch_and_risk_linkage(self) -> None:
        def fake_gh(endpoint: str):
            if endpoint == "repos/org/public-app":
                return {
                    "visibility": "PUBLIC",
                    "default_branch": "main",
                    "security_and_analysis": {
                        "secret_scanning": {"status": "enabled"},
                        "dependabot_security_updates": {"status": "disabled"},
                    },
                }
            if endpoint == "repos/org/public-app/branches/main/protection":
                return {"message": "Branch not protected"}
            return None

        posture = analyzer.fetch_github_posture("org/public-app", gh_runner=fake_gh)
        self.assertEqual(posture["visibility"], "PUBLIC")
        self.assertFalse(posture["default_branch_protected"])
        self.assertTrue(posture["secret_scanning_enabled"])
        self.assertFalse(posture["dependabot_alerts_enabled"])

        # Permission-denied / offline fallback returns 'unknown' without raising
        unknown_posture = analyzer.fetch_github_posture("org/private-app", gh_runner=lambda _: None)
        self.assertEqual(unknown_posture["visibility"], "unknown")
        self.assertEqual(unknown_posture["default_branch_protected"], "unknown")

        cr = {
            "action_items": [
                {
                    "severity": "critical",
                    "category": "Secrets",
                    "title": "🚨 [シークレット漏洩検知] AWS Key",
                    "desc": "Detected AWS key",
                }
            ],
            "findings": [],
        }
        analyzer.apply_github_posture_to_audit(cr, posture, "org/public-app")
        self.assertIn("公開（PUBLIC）リポジトリのため即時侵害リスクあり", cr["action_items"][0]["desc"])
        bp_finding = next(
            (it for it in cr["action_items"] if "Branch Protection" in it["title"]),
            None,
        )
        self.assertIsNotNone(bp_finding)
        self.assertEqual(bp_finding["priority_tier"], "P2")

    def test_eol_extraction_and_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"engines": {"node": ">=18.0.0"}, "dependencies": {"next": "^13.5.8", "react": "^19.0.0"}}',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                '[project]\nrequires-python = ">=3.8"\n',
                encoding="utf-8",
            )
            extracted = eol_checker.extract_repo_runtime_and_framework_versions(root)
            self.assertEqual(extracted["nodejs"], ">=18.0.0")
            self.assertEqual(extracted["nextjs"], "^13.5.8")
            self.assertEqual(extracted["react"], "^19.0.0")
            self.assertEqual(extracted["python"], ">=3.8")

            def fake_fetcher(url: str, timeout: float):
                if "nodejs.json" in url:
                    return [{"cycle": "22", "eol": "2027-04-30"}, {"cycle": "18", "eol": "2025-04-30"}]
                if "nextjs.json" in url:
                    return [{"cycle": "16", "eol": False}, {"cycle": "13", "eol": "2024-10-25"}]
                if "react.json" in url:
                    return [{"cycle": "19", "eol": False}]
                if "python.json" in url:
                    return [{"cycle": "3.13", "eol": False}, {"cycle": "3.8", "eol": "2024-10-07"}]
                return []

            results = eol_checker.evaluate_runtime_eol(
                extracted,
                today="2026-11-23",
                fetcher=fake_fetcher,
                use_cache=False,
            )
            by_prod = {r["product"]: r for r in results}
            self.assertTrue(by_prod["nodejs"]["is_eol"])
            self.assertTrue(by_prod["nodejs"]["eol_over_1y"])
            self.assertTrue(by_prod["nextjs"]["is_eol"])
            self.assertFalse(by_prod["react"]["is_eol"])


if __name__ == "__main__":
    unittest.main()
