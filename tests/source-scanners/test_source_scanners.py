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

    def test_gitleaks_ignores_truncated_jwt_in_docs_and_keeps_real_keys(self):
        docs_rel = "src/features/admin/auth/auth.docs.ts"
        prod_rel = "src/config/keys.ts"
        docs_file = self.root / docs_rel
        prod_file = self.root / prod_rel
        docs_file.parent.mkdir(parents=True, exist_ok=True)
        prod_file.parent.mkdir(parents=True, exist_ok=True)
        docs_file.write_text(
            '/**\n *                     token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."\n */\n',
            encoding="utf-8",
        )
        prod_file.write_text(
            'export const AWS_KEY = "AKIA1234567890EXAMPLE";\n'
            'export const API_SECRET = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";\n',
            encoding="utf-8",
        )
        raw = json.dumps(
            [
                {"File": docs_rel, "StartLine": 2, "RuleID": "generic-api-key"},
                {"File": prod_rel, "StartLine": 1, "RuleID": "aws-access-token"},
                {"File": prod_rel, "StartLine": 2, "RuleID": "generic-api-key"},
            ]
        )
        findings = source_scanners.parse_findings(
            "gitleaks",
            raw,
            self.root,
            {docs_rel: 3, prod_rel: 2},
            lambda _: "Core",
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["severity"] == "high" for f in findings))
        self.assertEqual(
            [f["rule_id"] for f in findings],
            ["aws-access-token", "generic-api-key"],
        )
        self.assertNotIn("eyJhbGci", json.dumps(findings))

    def test_gitleaks_ignores_doc_ellipsis_pem_but_keeps_real_private_key(self):
        doc_rel = "docs/cloudfront-video-signed-url-setup.md"
        real_rel = "certs/server.key"
        doc_file = self.root / doc_rel
        real_file = self.root / real_rel
        doc_file.parent.mkdir(parents=True, exist_ok=True)
        real_file.parent.mkdir(parents=True, exist_ok=True)
        doc_file.write_text(
            'VIDEO_CLOUDFRONT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...(base64 content on one line with \\n for newlines)...\\n-----END RSA PRIVATE KEY-----"\n',
            encoding="utf-8",
        )
        real_file.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAt8realkeymaterial\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        raw = json.dumps(
            [
                {"File": doc_rel, "StartLine": 1, "RuleID": "private-key"},
                {"File": real_rel, "StartLine": 1, "RuleID": "private-key"},
            ]
        )
        findings = source_scanners.parse_findings(
            "gitleaks",
            raw,
            self.root,
            {doc_rel: 1, real_rel: 3},
            lambda _: "Core",
        )
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["file"].startswith("certs/server.key:1"))
        self.assertEqual(findings[0]["severity"], "high")

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

    def test_semgrep_and_trivy_missing_tools_fallback(self):
        with patch.object(source_scanners, "TOOL_DIRS", ()):
            sast, advs, statuses = source_scanners.scan_semgrep_and_trivy(self.repo, str)
        self.assertEqual(sast, [])
        self.assertEqual(advs, [])
        self.assertEqual(statuses, {"semgrep": "not_installed", "trivy": "not_installed"})

    def test_parse_semgrep_and_trivy_outputs(self):
        semgrep_raw = json.dumps({
            "results": [
                {
                    "check_id": "javascript.express.security.audit.xss.direct-response-write",
                    "path": "src/app.ts",
                    "start": {"line": 12},
                    "extra": {"severity": "ERROR", "message": "Potential XSS"},
                },
                {
                    "check_id": "outside.rule",
                    "path": "../secret.ts",
                    "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "Outside"},
                },
            ]
        }).encode("utf-8")
        sast = source_scanners.parse_semgrep(semgrep_raw, self.root, {"src/app.ts": 30}, lambda _: "App")
        self.assertEqual(len(sast), 1)
        self.assertEqual(sast[0]["scanner"], "semgrep")
        self.assertEqual(sast[0]["severity"], "high")

        trivy_raw = json.dumps({
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-99999",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "FixedVersion": "4.17.21",
                            "Severity": "HIGH",
                            "Title": "Prototype Pollution",
                        }
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0002",
                            "Title": "Image user should not be root",
                            "Severity": "HIGH",
                            "Description": "Running as root",
                            "Resolution": "Add USER nonroot",
                            "CauseMetadata": {"StartLine": 5},
                        }
                    ],
                },
            ]
        }).encode("utf-8")
        misconfs, vulns = source_scanners.parse_trivy(
            trivy_raw, {"package-lock.json": 100, "Dockerfile": 20}, lambda _: "Infra"
        )
        self.assertEqual(len(misconfs), 1)
        self.assertEqual(misconfs[0]["scanner"], "trivy")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cve"], "CVE-2024-99999")

    def test_snake_case_identifier_key_constant_is_not_generic_api_key(self):
        self.assertTrue(
            source_scanners._is_snake_case_identifier_key_line(
                "const PROVENANCE_KEY = 'cerebras_gemma4_retirement_provenance';"
            )
        )
        self.assertFalse(
            source_scanners._is_snake_case_identifier_key_line(
                "const CLIENT_SECRET = 'cerebras_gemma4_retirement_provenance';"
            )
        )
        self.assertFalse(
            source_scanners._is_snake_case_identifier_key_line(
                "const API_KEY = 'sk_live_abc123_def456_ghi789';"
            )
        )
        self.assertFalse(
            source_scanners._is_snake_case_identifier_key_line(
                "const API_KEY = 'A9xK2mPq8vL4nR7tW1zY3bC6dF0hJ5kM';"
            )
        )
