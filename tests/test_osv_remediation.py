"""Regression tests for OSV advisory package_name, fixed_version, diff, and fix_cmd generation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import security_audit_engine  # noqa: E402


class TestOsvRemediation(unittest.TestCase):
    def test_extract_osv_fixed_version_from_affected_ranges(self) -> None:
        vuln = {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "affected": [
                {
                    "package": {"name": "uuid", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "13.0.0"}, {"fixed": "14.0.0"}],
                        }
                    ],
                }
            ],
        }
        self.assertEqual(
            security_audit_engine._extract_osv_fixed_version(vuln, "uuid", "npm"),
            "14.0.0",
        )

    def test_npm_uuid_remediation_avoids_1_7_4_and_ecosystem_parens(self) -> None:
        adv = {
            "package_name": "uuid",
            "ecosystem": "npm",
            "pkg": "uuid (npm)",
            "installed": "13.0.0",
            "fixed_version": "14.0.0",
            "safe_version": "14.0.0",
        }
        rem = analyzer.build_advisory_remediation(adv)
        self.assertEqual(rem["file"], "package.json")
        self.assertEqual(rem["fix_cmd"], "npm install uuid@^14.0.0")
        self.assertNotIn("(npm)", rem["fix_cmd"])
        self.assertIn('"uuid": "^13.0.0"', rem["diff"])
        self.assertIn('"uuid": "^14.0.0"', rem["diff"])
        self.assertNotIn("^1.7.4", rem["diff"])
        self.assertNotIn("uuid (npm)", rem["diff"])

    def test_legacy_pkg_without_fixed_version_strips_ecosystem_parens(self) -> None:
        adv = {"pkg": "uuid (npm)", "installed": "13.0.0"}
        rem = analyzer.build_advisory_remediation(adv)
        self.assertEqual(rem["file"], "package.json")
        self.assertEqual(rem["fix_cmd"], "npm install uuid@latest")
        self.assertEqual(rem["diff"], "")

    def test_pypi_and_go_remediation(self) -> None:
        pypi_rem = analyzer.build_advisory_remediation(
            {"package_name": "urllib3", "ecosystem": "PyPI", "installed": "1.26.4", "fixed_version": "2.2.2"}
        )
        self.assertEqual(pypi_rem["file"], "requirements.txt")
        self.assertEqual(pypi_rem["fix_cmd"], 'pip install --upgrade "urllib3>=2.2.2"')
        self.assertIn("urllib3>=2.2.2", pypi_rem["diff"])

        go_rem = analyzer.build_advisory_remediation(
            {"package_name": "golang.org/x/crypto", "ecosystem": "Go", "installed": "0.17.0", "fixed_version": "0.31.0"}
        )
        self.assertEqual(go_rem["file"], "go.mod")
        self.assertEqual(go_rem["fix_cmd"], "go get golang.org/x/crypto@v0.31.0")
        self.assertIn("golang.org/x/crypto v0.31.0", go_rem["diff"])

    def test_trivy_comma_separated_fixed_versions_picks_matching_branch(self) -> None:
        import json
        import source_scanners

        trivy_payload = json.dumps({
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-75604",
                            "PkgName": "next",
                            "InstalledVersion": "16.2.0",
                            "FixedVersion": "15.5.24, 16.3.3",
                            "Severity": "HIGH",
                            "Title": "Next.js vulnerability",
                        }
                    ],
                }
            ]
        })
        _, advisories = source_scanners.parse_trivy(
            trivy_payload,
            {"package-lock.json": 100},
            lambda _: "Frontend",
        )
        self.assertEqual(len(advisories), 1)
        adv = advisories[0]
        self.assertEqual(adv["package_name"], "next")
        self.assertEqual(adv["installed"], "16.2.0")
        self.assertEqual(adv["installed_version"], "16.2.0")
        self.assertEqual(adv["fixed_version"], "16.3.3")
        self.assertEqual(adv["ecosystem"], "npm")
        rem = analyzer.build_advisory_remediation(adv)
        self.assertEqual(rem["fix_cmd"], "npm install next@^16.3.3")
        self.assertNotIn(",", rem["fix_cmd"])


if __name__ == "__main__":
    unittest.main()
