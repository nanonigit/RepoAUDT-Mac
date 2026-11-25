"""Unit tests for lightweight HEAD commit monitoring in SyncDaemon."""

from __future__ import annotations

import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import server  # noqa: E402


class TestCommitMonitor(unittest.TestCase):
    def test_check_once_reanalyzes_only_repos_with_new_head_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "commit_monitor.json"
            rev_file = Path(tmp) / "secret_revocations.json"
            ev_file = Path(tmp) / "monitor_events.json"
            with mock.patch.object(server, "_monitor_config_path", return_value=cfg_file), \
                 mock.patch.object(server, "_revocations_path", return_value=rev_file), \
                 mock.patch.object(server, "_monitor_events_path", return_value=ev_file):
                daemon = server.SyncDaemon(interval_sec=300)

                saved_state = {
                    "diagrams": [
                        {
                            "id": "org-root",
                            "is_root": True,
                            "github_url": "https://github.com/example-org",
                        },
                        {
                            "id": "repo-1",
                            "repo": "example-org/unchanged",
                            "github_url": "https://github.com/example-org/unchanged",
                            "commit_hash": "1111111",
                            "source_revision": {"commit_sha": "1" * 40},
                        },
                        {
                            "id": "repo-2",
                            "repo": "example-org/updated",
                            "github_url": "https://github.com/example-org/updated",
                            "commit_hash": "2222222",
                            "source_revision": {"commit_sha": "2" * 40},
                            "coderabbit": {
                                "action_items": [
                                    {
                                        "title": "Hardcoded AWS Key",
                                        "file": "src/config.ts:5 (Target: Core)",
                                        "severity": "critical",
                                    },
                                    {
                                        "title": "Existing low warning",
                                        "file": "src/app.ts:10",
                                        "severity": "low",
                                    },
                                ]
                            },
                        },
                    ]
                }

                def fake_repo_status(root: str, saved: str):
                    if root == "repos/example-org/unchanged":
                        return {"head": "1" * 40, "same_head": True}
                    return {"head": "3" * 40, "same_head": False}

                analyzed_urls = []

                def fake_analyze(url: str):
                    analyzed_urls.append(url)
                    return {
                        "diagram": {
                            "id": "repo-2",
                            "repo": "example-org/updated",
                            "github_url": url,
                            "coderabbit": {
                                "action_items": [
                                    {
                                        "title": "Existing low warning",
                                        "file": "src/app.ts:10",
                                        "severity": "low",
                                    }
                                ]
                            },
                        }
                    }

                with mock.patch.object(server.analyzer, "load_saved_analyses", return_value=saved_state), \
                     mock.patch.object(server.audit_evidence, "repository_status", side_effect=fake_repo_status), \
                     mock.patch.object(server.analyzer, "analyze_any_github_target", side_effect=fake_analyze), \
                     mock.patch.object(server.analyzer, "save_analysis_result") as mock_save:
                    status = daemon.check_once()

                self.assertEqual(analyzed_urls, ["https://github.com/example-org/updated"])
                mock_save.assert_called_once()
                self.assertEqual(len(status["detected_updates"]), 1)
                self.assertEqual(status["detected_updates"][0]["repo"], "example-org/updated")
                self.assertEqual(status["detected_updates"][0]["new_commit"], "3333333")
                self.assertEqual(status["detected_updates"][0]["findings"], 1)
                self.assertEqual(status["detected_updates"][0]["resolved_count"], 1)
                self.assertEqual(status["detected_updates"][0]["resolved_high_count"], 1)
                self.assertEqual(
                    status["detected_updates"][0]["resolved_findings"][0]["title"],
                    "Hardcoded AWS Key",
                )
                self.assertTrue(status["detected_updates"][0]["resolved_findings"][0]["requires_revoke"])
                self.assertEqual(len(status["revocation_checks"]), 1)
                self.assertFalse(status["revocation_checks"][0]["revoked_confirmed"])

                rev_key = status["revocation_checks"][0]["key"]
                updated_status = daemon.confirm_revocation(rev_key, True)
                self.assertTrue(updated_status["revocation_checks"][0]["revoked_confirmed"])
                self.assertIn("2件確認", status["last_check_summary"])
                self.assertIn("1件の新着コミット", status["last_check_summary"])

    def test_configure_persists_enabled_and_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "commit_monitor.json"
            ev_file = Path(tmp) / "monitor_events.json"
            plist_file = Path(tmp) / "com.repoaudt.mac.monitor.plist"
            with mock.patch.object(server, "_monitor_config_path", return_value=cfg_file), \
                 mock.patch.object(server, "_monitor_events_path", return_value=ev_file), \
                 mock.patch.object(server, "_launchd_plist_path", return_value=plist_file), \
                 mock.patch.object(server, "sync_launchd_agent") as mock_sync:
                daemon = server.SyncDaemon()
                res = daemon.configure(enabled=False, interval_sec=300)
                self.assertFalse(res["enabled"])
                self.assertEqual(res["interval_sec"], 300)
                mock_sync.assert_called_once_with(False, 300)

                reloaded = server.SyncDaemon()
                self.assertFalse(reloaded.enabled)
                self.assertEqual(reloaded.interval_sec, 300)

    def test_sync_launchd_agent_writes_and_removes_plist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plist_file = Path(tmp) / "LaunchAgents" / "com.repoaudt.mac.monitor.plist"
            with mock.patch.object(server, "_launchd_plist_path", return_value=plist_file):
                res_on = server.sync_launchd_agent(True, 10800, run_launchctl=False)
                self.assertTrue(res_on["launchd_installed"])
                self.assertTrue(plist_file.exists())
                with open(plist_file, "rb") as fp:
                    loaded = plistlib.load(fp)
                self.assertEqual(loaded["Label"], server.LAUNCHD_MONITOR_LABEL)
                self.assertEqual(loaded["StartInterval"], 10800)
                self.assertEqual(loaded["ProgramArguments"][-1], "--monitor-once")

                res_off = server.sync_launchd_agent(False, 10800, run_launchctl=False)
                self.assertFalse(res_off["launchd_installed"])
                self.assertFalse(plist_file.exists())

    def test_ai_finding_rephrasing_does_not_trigger_false_resolved(self) -> None:
        before_diag = {
            "coderabbit": {
                "action_items": [
                    {
                        "title": "[GEMINI_CLI AI監査] knexfile.ts にデータベースパスワードがハードコードされている (CWE-798)",
                        "file": "knexfile.ts:14 (Target: core)",
                        "severity": "high",
                    },
                    {
                        "title": "[GEMINI_CLI AI監査] ワークフロー全体に過剰な書き込み権限 (CWE-269)",
                        "file": ".github/workflows/doc.yml:22 (Target: ci)",
                        "severity": "medium",
                    },
                ]
            }
        }
        after_diag = {
            "coderabbit": {
                "action_items": [
                    {
                        "title": "[GEMINI_CLI AI監査] knexfile.ts にデータベースパスワードのフォールバック値がハードコードされている (CWE-798)",
                        "file": "knexfile.ts:14 (Target: core)",
                        "severity": "high",
                    },
                    {
                        "title": "[GEMINI_CLI AI監査] ワークフロー全体に過剰な書き込み権限が付与されている (CWE-269)",
                        "file": ".github/workflows/doc.yml:23 (Target: ci)",
                        "severity": "medium",
                    },
                ]
            }
        }
        before_sigs = server.SyncDaemon._collect_finding_signatures(before_diag)
        after_sigs = server.SyncDaemon._collect_finding_signatures(after_diag)
        resolved = [info for k, info in before_sigs.items() if k not in after_sigs]
        self.assertEqual(resolved, [])

    def test_git_history_persistence_detects_removed_from_head_and_in_history(self) -> None:
        import subprocess
        import revocation_checker
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            secret_file = repo / "config" / "cred.json"
            secret_file.parent.mkdir(parents=True)
            secret_file.write_text('{"accessKeyId":"AKIA5S1234567890ABCD"}', encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "add cred"], cwd=repo, check=True)

            h1 = revocation_checker.check_git_history_persistence(repo, "config/cred.json:1")
            self.assertEqual(h1["status"], "still_in_head")

            secret_file.unlink()
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "remove cred"], cwd=repo, check=True)

            h2 = revocation_checker.check_git_history_persistence(repo, "config/cred.json:1")
            self.assertEqual(h2["status"], "head_removed_in_history")
            self.assertGreaterEqual(h2["commit_count"], 1)


if __name__ == "__main__":
    unittest.main()
