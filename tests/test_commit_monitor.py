"""Unit tests for lightweight HEAD commit monitoring in SyncDaemon."""

from __future__ import annotations

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
            with mock.patch.object(server, "_monitor_config_path", return_value=cfg_file), \
                 mock.patch.object(server, "_revocations_path", return_value=rev_file):
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
            with mock.patch.object(server, "_monitor_config_path", return_value=cfg_file):
                daemon = server.SyncDaemon()
                res = daemon.configure(enabled=False, interval_sec=300)
                self.assertFalse(res["enabled"])
                self.assertEqual(res["interval_sec"], 300)

                reloaded = server.SyncDaemon()
                self.assertFalse(reloaded.enabled)
                self.assertEqual(reloaded.interval_sec, 300)


if __name__ == "__main__":
    unittest.main()
