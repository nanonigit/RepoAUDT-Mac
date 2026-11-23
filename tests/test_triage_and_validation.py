"""Unit tests for zizmor grouping, P0-P3 triage, CISA KEV, reachability, output validator, and fingerprint suppression."""

from __future__ import annotations

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
import source_scanners  # noqa: E402
import triage_engine  # noqa: E402
import workflow_audit  # noqa: E402


class TestTriageAndValidation(unittest.TestCase):
    def test_zizmor_groups_by_file_and_rule_id(self) -> None:
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "zizmor/template-injection",
                            "level": "error",
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/deploy.yml"}, "region": {"startLine": 80}}}
                            ],
                        },
                        {
                            "ruleId": "zizmor/template-injection",
                            "level": "error",
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/deploy.yml"}, "region": {"startLine": 57}}}
                            ],
                        },
                        {
                            "ruleId": "zizmor/unpinned-uses",
                            "level": "warning",
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/deploy.yml"}, "region": {"startLine": 12}}}
                            ],
                        },
                    ]
                }
            ]
        }
        grouped = workflow_audit.parse_sarif(
            json.dumps(sarif),
            {".github/workflows/deploy.yml": 120},
            lambda _: "CI/CD",
        )
        self.assertEqual(len(grouped), 2)
        ti = next(g for g in grouped if g["rule_id"] == "template-injection")
        self.assertEqual(ti["lines"], [57, 80])
        self.assertEqual(ti["occurrence_count"], 2)
        self.assertIn("2箇所: L57, L80", ti["title"])
        self.assertTrue(ti["file"].startswith(".github/workflows/deploy.yml:57"))

    def test_priority_tiers_p0_to_p3_and_kev_sorting(self) -> None:
        items = [
            {"title": "[zizmor] unpinned-uses (ci.yml:10)", "rule_id": "unpinned-uses", "scanner": "zizmor", "severity": "high"},
            {"title": "postcss DoS", "package_name": "postcss", "severity": "high", "desc": "Minor ReDoS"},
            {"title": "CVE-2026-9999 next RCE", "cve": "CVE-2026-9999", "severity": "high", "desc": "Remote Code Execution"},
            {"title": "🚨 [シークレット漏洩検知] AWS Access Key ID", "severity": "critical", "file": "src/aws.ts:1"},
            {"title": "[trivy] Unencrypted SNS", "scanner": "trivy", "severity": "high", "file": "infra/main.tf:4"},
        ]
        triaged = triage_engine.triage_and_validate_findings(
            items,
            repo_id="org/app",
            kev_set={"CVE-2026-9999"},
        )
        self.assertEqual([i["priority_tier"] for i in triaged], ["P0", "P1", "P2", "P3", "P3"])
        p1 = triaged[1]
        self.assertTrue(p1["in_cisa_kev"])

    def test_reachability_checks_public_key_internal_alb_windows_and_gha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Public reCaptchaKey / NEXT_PUBLIC_* excluded from Gitleaks generic-api-key
            pub_file = root / "src" / "Recaptcha.tsx"
            pub_file.parent.mkdir(parents=True)
            pub_file.write_text('const x = <GoogleReCaptchaProvider reCaptchaKey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" />;\n')
            raw_gl = json.dumps([{"File": "src/Recaptcha.tsx", "StartLine": 1, "RuleID": "generic-api-key"}])
            self.assertEqual(
                source_scanners.parse_findings("gitleaks", raw_gl, root, {"src/Recaptcha.tsx": 1}, str),
                [],
            )

            # 2. Terraform internal ALB (AVD-AWS-0054) downgraded to medium/mitigated
            alb_dir = root / "modules" / "alb"
            alb_dir.mkdir(parents=True)
            (alb_dir / "main.tf").write_text('resource "aws_lb" "int" {\n  internal = true\n}\n')
            trivy_json = json.dumps({
                "Results": [{
                    "Target": "modules/alb/main.tf",
                    "Misconfigurations": [{
                        "ID": "AVD-AWS-0054",
                        "Title": "Use of plain HTTP.",
                        "Severity": "CRITICAL",
                        "CauseMetadata": {"StartLine": 1},
                    }],
                }]
            })
            misconfs, _ = source_scanners.parse_trivy(trivy_json, {"modules/alb/main.tf": 10}, str, repo_dir=root)
            self.assertEqual(misconfs[0]["severity"], "medium")
            self.assertEqual(misconfs[0]["reachability"], "mitigated")

            # 3. Windows-only CVE on Linux Dockerfile repo -> reachability: unlikely
            (root / "Dockerfile").write_text("FROM node:22-alpine\n")
            win_triaged = triage_engine.triage_and_validate_findings(
                [{"title": "next Windows-hosted RCE", "desc": "Affects Windows servers only", "severity": "high"}],
                repo_dir=root,
            )
            self.assertEqual(win_triaged[0]["reachability"], "unlikely")

            # 4. Safe GitHub Actions pull_request_target with workflow_sha
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            wf = wf_dir / "safe.yml"
            wf.write_text("on: pull_request_target\nsteps:\n  - uses: actions/checkout@abc\n    with:\n      ref: ${{ github.workflow_sha }}\n")
            annotated = workflow_audit.annotate_workflow_reachability(
                [wf],
                [{"rule_id": "dangerous-triggers", "file": ".github/workflows/safe.yml:1 (Target: CI)", "severity": "high"}],
            )
            self.assertEqual(annotated[0]["reachability"], "mitigated")
            self.assertEqual(annotated[0]["severity"], "medium")

    def test_output_validator_blocks_downgrades_prereleases_and_secret_leaks(self) -> None:
        ajv_bad = {
            "title": "ajv vuln",
            "diff": '- "ajv": "^8.17.1"\n+ "ajv": "^6.14.0"',
            "fix_cmd": "npm install ajv@^6.14.0",
        }
        triage_engine.validate_and_sanitize_finding(ajv_bad)
        self.assertEqual(ajv_bad["diff"], "")
        self.assertEqual(ajv_bad["fix_cmd"], "npm install ajv@latest")

        rc_bad = {
            "title": "sentry vuln",
            "diff": '- "@sentry/nextjs": "^10.38.0"\n+ "@sentry/nextjs": "^11.0.0-rc.1"',
            "fix_cmd": "npm install @sentry/nextjs@^11.0.0-rc.1",
        }
        triage_engine.validate_and_sanitize_finding(rc_bad)
        self.assertEqual(rc_bad["diff"], "")
        self.assertEqual(rc_bad["fix_cmd"], "npm install @sentry/nextjs@latest")

        secret_bad = {
            "title": "🚨 [シークレット漏洩検知] AWS Access Key ID",
            "diff": "- AKIA1234,[REDACTED_NOT_REALLY_40CHARSECRET]",
        }
        triage_engine.validate_and_sanitize_finding(secret_bad)
        self.assertEqual(secret_bad["diff"], "- [REDACTED SECRET LINE]")

    def test_fingerprint_suppression_and_is_new_tracking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "saved_analyses.json"
            with mock.patch.object(analyzer, "STATE_FILE", state_file), \
                 mock.patch.object(analyzer, "ensure_dirs"):
                item1 = {"title": "Existing issue", "file": "a.ts:1", "severity": "medium"}
                item1["fingerprint"] = triage_engine.compute_finding_fingerprint("org/repo", item1)
                analyzer.save_analysis_result({
                    "diagram": {
                        "id": "repo-1",
                        "repo": "org/repo",
                        "github_url": "https://github.com/org/repo",
                        "coderabbit": {"action_items": [item1], "findings": []},
                    }
                })

                supp = analyzer.set_finding_suppression(item1["fingerprint"], reason="False positive", suppress=True)
                self.assertIn(item1["fingerprint"], supp)

                item2 = {"title": "Brand new issue", "file": "b.ts:2", "severity": "high"}
                saved = analyzer.save_analysis_result({
                    "diagram": {
                        "id": "repo-1",
                        "repo": "org/repo",
                        "github_url": "https://github.com/org/repo",
                        "coderabbit": {"action_items": [item1, item2], "findings": []},
                    }
                })
                acts = saved["diagrams"][0]["coderabbit"]["action_items"]
                by_title = {a["title"]: a for a in acts}
                self.assertTrue(by_title["Existing issue"]["suppressed"])
                self.assertFalse(by_title["Existing issue"]["is_new"])
                self.assertFalse(by_title["Brand new issue"]["suppressed"])
                self.assertTrue(by_title["Brand new issue"]["is_new"])


if __name__ == "__main__":
    unittest.main()
