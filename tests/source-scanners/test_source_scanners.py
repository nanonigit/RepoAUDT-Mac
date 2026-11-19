import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import audit_evidence
import source_scanners

SYNTHETIC_TOKEN = "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2"
REFERENCE = 'AUTH0_CLIENT_SECRET = "${aws_secretsmanager_secret.this["fixture/prod/auth0"].arn}:client_secret::"\n'


class SourceScannerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")

    def git(self, *args):
        subprocess.run(
            ["/usr/bin/git", *args], cwd=self.repo, check=True, capture_output=True
        )

    def test_only_tracked_regular_files_are_staged(self):
        (self.repo / "tracked.py").write_text("x = 1\n")
        (self.repo / "untracked.py").write_text("x = 2\n")
        (self.repo / "linked.py").symlink_to(self.repo / "untracked.py")
        self.git("add", "tracked.py", "linked.py")
        stage = self.root / "stage"
        stage.mkdir()
        files, partial = source_scanners.stage_sources(
            self.repo,
            stage,
            {"PATH": "/usr/bin:/bin", "HOME": str(self.root)},
            python_only=False,
        )
        self.assertEqual(files, {"tracked.py": 1})
        self.assertTrue(partial)

    def test_missing_tools_leave_other_scans_available(self):
        with patch.object(source_scanners, "TOOL_DIRS", ()):
            result = source_scanners.scan_source(self.repo, str)
        self.assertEqual(
            result, ([], {"ruff": "not_installed", "gitleaks": "not_installed"})
        )

    def test_parser_rejects_files_outside_staging(self):
        raw = json.dumps([{"File": "../outside", "StartLine": 1, "RuleID": "test"}])
        with self.assertRaises(ValueError):
            source_scanners.parse_findings("gitleaks", raw, self.root, {}, str)

    def test_secret_candidate_source_preview_is_redacted(self):
        repo = {
            "id": "fixture",
            "github_url": "https://github.com/example/fixture",
            "coderabbit": {
                "action_items": [
                    {
                        "file": "settings.yml:1 (Target: A)",
                        "scanner": "gitleaks",
                        "severity": "high",
                    }
                ]
            },
        }
        status = {"head": "a" * 40, "saved_commit": "a" * 7, "same_head": True}
        with (
            patch.object(audit_evidence, "repository_status", return_value=status),
            patch.object(
                audit_evidence,
                "read_file",
                return_value=("blob", ["synthetic arbitrary value"]),
            ),
            patch.object(audit_evidence, "github", return_value=[]),
        ):
            result = audit_evidence.handle(
                {"repository": "fixture", "path": "settings.yml", "line": 1},
                {"diagrams": [repo]},
            )
        self.assertEqual(
            result["audited_line"]["text"], "[credential-like line redacted]"
        )
        self.assertEqual(
            result["current_line"]["text"], "[credential-like line redacted]"
        )

    @unittest.skipUnless(
        all(source_scanners.executable(tool) for tool in ("ruff", "gitleaks")),
        "Install Ruff and Gitleaks for the real-tool check",
    )
    def test_real_tools_report_quality_and_redacted_credential_candidates(self):
        (self.repo / "main.py").write_text("import os\nprint(undefined_name)\n")
        (self.repo / "settings.yml").write_text(f"token: {SYNTHETIC_TOKEN}\n")
        (self.repo / "reference.tf").write_text(REFERENCE)
        (self.repo / ".gitleaks.toml").write_text(
            "intentionally invalid configuration\n"
        )
        self.git("add", "--", ".")
        findings, status = source_scanners.scan_source(self.repo, lambda _: "fixture")
        self.assertEqual(status, {"ruff": "complete", "gitleaks": "complete"})
        self.assertEqual(
            {f["rule_id"] for f in findings if f["scanner"] == "ruff"}, {"F401", "F821"}
        )
        self.assertTrue(
            any(
                f["file"].startswith("settings.yml:1")
                for f in findings
                if f["scanner"] == "gitleaks"
            )
        )
        self.assertFalse(any(f["file"].startswith("reference.tf:1") for f in findings))
        self.assertNotIn(SYNTHETIC_TOKEN, json.dumps(findings))
