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
            history_file = Path(tmp) / "scan_history.json"
            with mock.patch.object(analyzer, "STATE_FILE", state_file), \
                 mock.patch.object(analyzer, "HISTORY_FILE", history_file), \
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

    def test_triage_snooze_and_auto_expiry_plus_category_and_update_type(self) -> None:
        self.assertEqual(
            triage_engine.classify_category({"title": "[zizmor] unpinned-uses", "scanner": "zizmor", "file": ".github/workflows/ci.yml:1"}),
            "CI/CD",
        )
        self.assertEqual(
            triage_engine.classify_update_type({"diff": '- "next": "^16.2.0"\n+ "next": "^16.4.5"'}),
            "Safe Patch/Minor",
        )
        self.assertEqual(
            triage_engine.classify_update_type({"diff": '- "next": "^15.5.0"\n+ "next": "^16.4.5"'}),
            "Breaking Major",
        )

        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "saved_analyses.json"
            history_file = Path(tmp) / "scan_history.json"
            with mock.patch.object(analyzer, "STATE_FILE", state_file), \
                 mock.patch.object(analyzer, "HISTORY_FILE", history_file), \
                 mock.patch.object(analyzer, "ensure_dirs"):
                item = {"title": "Temp snooze issue", "file": "a.ts:1", "severity": "high"}
                fp = triage_engine.compute_finding_fingerprint("org/repo", item)
                item["fingerprint"] = fp
                analyzer.save_analysis_result({
                    "diagram": {
                        "id": "repo-1",
                        "repo": "org/repo",
                        "github_url": "https://github.com/org/repo",
                        "coderabbit": {"action_items": [item], "findings": []},
                    }
                })
                supp = analyzer.set_finding_triage(fp, action="snooze", reason="Scheduled", note="Sprint 12", days=7)
                self.assertEqual(supp[fp]["status"], "snoozed")
                self.assertIsNotNone(supp[fp]["expires_at"])

                # Force expires_at into the past and verify reload auto-restores to active
                raw = json.loads(state_file.read_text(encoding="utf-8"))
                raw["suppressed_findings"][fp]["expires_at"] = "2020-01-01T00:00:00+00:00"
                state_file.write_text(json.dumps(raw), encoding="utf-8")

                reloaded = analyzer.load_saved_analyses()
                self.assertNotIn(fp, reloaded["suppressed_findings"])
                self.assertFalse(reloaded["diagrams"][0]["coderabbit"]["action_items"][0]["suppressed"])

    def test_dependency_batch_plan_separates_safe_minor_from_breaking_major(self) -> None:
        items = [
            {
                "title": "[依存関係脆弱性集約] next v16.2.0",
                "package_name": "next",
                "category": "Dependencies (SCA)",
                "diff": '- "next": "^16.2.0"\n+ "next": "^16.4.5"',
                "fix_cmd": "npm install next@^16.4.5",
                "update_type": "Safe Patch/Minor",
            },
            {
                "title": "[OSV脆弱性検出] axios v1.8.4",
                "package_name": "axios",
                "category": "Dependencies (SCA)",
                "diff": '- "axios": "^1.8.4"\n+ "axios": "^1.20.0"',
                "fix_cmd": "npm install axios@^1.20.0",
                "update_type": "Safe Patch/Minor",
            },
            {
                "title": "[OSV脆弱性検出] joi v17.13.3",
                "package_name": "joi",
                "category": "Dependencies (SCA)",
                "diff": '- "joi": "^17.13.3"\n+ "joi": "^18.3.1"',
                "fix_cmd": "npm install joi@^18.3.1",
                "update_type": "Breaking Major",
            },
            {
                "title": "[OSV脆弱性検出] sentry rc",
                "package_name": "@sentry/nextjs",
                "category": "Dependencies (SCA)",
                "diff": '- "@sentry/nextjs": "^10.38.0"\n+ "@sentry/nextjs": "^11.0.0-rc.1"',
                "fix_cmd": "npm install @sentry/nextjs@^11.0.0-rc.1",
            },
        ]
        plan = triage_engine.build_dependency_batch_plan(items)
        self.assertEqual(len(plan["safe_patch_minor"]), 2)
        self.assertEqual(len(plan["breaking_major"]), 2)
        self.assertEqual(plan["combined_npm_command"], "npm install next@^16.4.5 axios@^1.20.0")
        self.assertNotIn("-rc", plan["combined_npm_command"])

    def test_slack_digest_redacts_secrets_and_formats_p0_p1(self) -> None:
        raw_secret = "sk-proj-RealSecretValueThatMustNeverAppearInSlack123456"
        diagrams = [
            {
                "repo": "plusimpact/maice-backend",
                "coderabbit": {
                    "action_items": [
                        {
                            "priority_tier": "P0",
                            "severity": "critical",
                            "title": f"🚨 [シークレット漏洩検知] OpenAI API Key ({raw_secret})",
                            "file": "src/config.ts:6",
                            "fix_cmd": "sed -n '4,8p' src/config.ts",
                        },
                        {
                            "priority_tier": "P1",
                            "severity": "high",
                            "in_cisa_kev": True,
                            "title": "next RCE",
                            "file": "package.json",
                            "fix_cmd": "npm install next@^16.4.5",
                        },
                        {
                            "priority_tier": "P3",
                            "severity": "low",
                            "title": "unpinned-uses",
                            "file": ".github/workflows/ci.yml:10",
                        },
                    ]
                },
            }
        ]
        digest_ja = triage_engine.build_slack_digest(diagrams, lang="ja")
        self.assertNotIn(raw_secret, digest_ja)
        self.assertIn("[REDACTED_API_KEY]", digest_ja)
        self.assertIn("*• plusimpact/maice-backend*", digest_ja)
        self.assertIn("`[P0]`", digest_ja)
        self.assertIn("`[P1]` 🔥KEV", digest_ja)
        self.assertIn("`npm install next@^16.4.5`", digest_ja)
        self.assertNotIn("unpinned-uses", digest_ja)

        digest_both = triage_engine.build_slack_digest(diagrams, lang="both")
        self.assertIn("Security Audit Digest", digest_both)


if __name__ == "__main__":
    unittest.main()
