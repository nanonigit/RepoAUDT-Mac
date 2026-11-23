"""Unit tests for sync failure visibility, secret/Gitleaks dedup, unchanged skip, and LLM empty response handling."""

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
import security_audit_engine  # noqa: E402
import server  # noqa: E402


class TestSyncAndOpsImprovements(unittest.TestCase):
    def test_record_sync_status_error_and_clear_on_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "analyzed_repos.json"
            state_file.write_text(
                json.dumps(
                    {
                        "diagrams": [
                            {
                                "id": "gh-acme-api-overall",
                                "repo": "acme/api",
                                "github_url": "https://github.com/acme/api",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.object(analyzer, "STATE_FILE", state_file):
                ok = analyzer.record_sync_status(
                    "gh-acme-api-overall",
                    sync_status="error",
                    last_sync_error="git fetch timed out with token ghp_SECRET1234567890",
                )
                self.assertTrue(ok)
                saved = json.loads(state_file.read_text(encoding="utf-8"))
                d = saved["diagrams"][0]
                self.assertEqual(d["sync_status"], "error")
                self.assertIn("[REDACTED]", d["last_sync_error"])
                self.assertNotIn("ghp_SECRET1234567890", d["last_sync_error"])

                analyzer.record_sync_status("gh-acme-api-overall", sync_status="ok")
                saved_ok = json.loads(state_file.read_text(encoding="utf-8"))
                self.assertEqual(saved_ok["diagrams"][0]["sync_status"], "ok")
                self.assertIsNone(saved_ok["diagrams"][0]["last_sync_error"])

    def test_merge_secret_and_gitleaks_same_file_and_line(self) -> None:
        items = [
            {
                "severity": "critical",
                "priority_tier": "P0",
                "category": "secrets",
                "title": "🚨 [シークレット漏洩検知] OpenAI API Key が平文でハードコードされています (config.ts:6)",
                "file": "src/config.ts:6 (Target: api)",
                "desc": "Masked secret description",
                "diff": "- const key = [REDACTED]\n+ const key = process.env.OPENAI_API_KEY",
            },
            {
                "severity": "critical",
                "scanner": "gitleaks",
                "rule_id": "openai-api-key",
                "title": "[gitleaks] openai-api-key",
                "file": "src/config.ts:6 (Target: api)",
                "official_source": "https://github.com/gitleaks/gitleaks",
            },
            {
                "severity": "high",
                "scanner": "semgrep",
                "title": "[semgrep] sql-injection",
                "file": "src/db.ts:12 (Target: api)",
            },
        ]
        merged = security_audit_engine.merge_secret_and_gitleaks_findings(items)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["detected_by"], ["secret_scanner", "gitleaks"])
        self.assertEqual(merged[0]["official_source"], "https://github.com/gitleaks/gitleaks")
        self.assertEqual(merged[0]["gitleaks_rule_id"], "openai-api-key")

    def test_should_skip_unchanged_repo_and_force_override(self) -> None:
        diagram = {
            "id": "gh-acme-web-overall",
            "github_url": "https://github.com/acme/web",
            "sync_status": "ok",
            "audit_engine_version": analyzer.AUDIT_ENGINE_VERSION,
            "source_revision": {"commit_sha": "abcdef123456"},
        }
        with mock.patch.object(
            server.audit_evidence,
            "repository_status",
            return_value={"head": "abcdef123456", "same_head": True},
        ):
            skip, reason = server.should_skip_unchanged_repo(diagram, force=False)
            self.assertTrue(skip)
            self.assertEqual(reason, "skipped_unchanged")

            skip_force, reason_force = server.should_skip_unchanged_repo(diagram, force=True)
            self.assertFalse(skip_force)
            self.assertEqual(reason_force, "forced")

    def test_llm_empty_and_fenced_json_handling(self) -> None:
        self.assertEqual(security_audit_engine._parse_deep_audit_items(""), [])
        self.assertEqual(security_audit_engine._parse_deep_audit_items("   \n  "), [])
        fenced = '```json\n[{"title": "SQLi", "desc": "Unsanitized input", "severity": "high", "file": "app.py", "line": 10}]\n```'
        parsed = security_audit_engine._parse_deep_audit_items(fenced)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["title"], "SQLi")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
            with mock.patch.object(security_audit_engine, "load_settings", return_value={}), \
                 mock.patch.object(security_audit_engine, "choose_active_llm", return_value=("openai", "sk-test", "gpt-4o-mini")), \
                 mock.patch.object(security_audit_engine, "call_llm_provider", side_effect=["", "   "]) as mock_llm:
                items, _lbl, status = security_audit_engine.run_llm_deep_vulnerability_audit_with_status(
                    root, "acme/demo", [{"name": "web"}]
                )
                self.assertEqual(items, [])
                self.assertEqual(status, "skipped")
                self.assertEqual(mock_llm.call_count, 2)


if __name__ == "__main__":
    unittest.main()
