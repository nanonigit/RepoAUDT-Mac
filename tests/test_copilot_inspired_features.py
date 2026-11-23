"""Unit tests for custom instructions, chat slash commands, used references, diff path verification, and endoflife.date EOL checks."""

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

import audit_evidence  # noqa: E402
import eol_checker  # noqa: E402


class TestCustomInstructionsAndChat(unittest.TestCase):
    def test_load_custom_instructions_from_local_repo_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh_dir = root / ".github"
            gh_dir.mkdir(parents=True)
            (gh_dir / "copilot-instructions.md").write_text(
                "Use parameterized SQL.\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
                encoding="utf-8",
            )
            (root / "AGENTS.md").write_text("Run pytest before commit.", encoding="utf-8")

            loaded = audit_evidence.load_custom_instructions(
                None,
                None,
                repo={"local_path": str(root)},
            )
            paths = [item["path"] for item in loaded]
            self.assertEqual(paths, [".github/copilot-instructions.md", "AGENTS.md"])
            self.assertIn("Use parameterized SQL.", loaded[0]["content"])
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", loaded[0]["content"])
            self.assertIn("[credential-like line redacted]", loaded[0]["content"])

    def test_expand_slash_commands(self) -> None:
        explain_ja = audit_evidence.expand_slash_command("/explain", "ja")
        self.assertIn("根本原因", explain_ja)
        fix_en = audit_evidence.expand_slash_command("/fix focus on auth.py", "en")
        self.assertIn("unified diff", fix_en)
        self.assertIn("focus on auth.py", fix_en)
        tests_en = audit_evidence.expand_slash_command("/tests", "en")
        self.assertIn("regression test", tests_en)
        plain = audit_evidence.expand_slash_command("What is the risk?", "en")
        self.assertEqual(plain, "What is the risk?")

    def test_extract_and_verify_diff_paths(self) -> None:
        answer = (
            "Here is the fix:\n"
            "```diff\n"
            "--- a/src/auth.py\n"
            "+++ b/src/auth.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-pass\n"
            "+return True\n"
            "--- a/src/ghost_hallucinated.py\n"
            "+++ b/src/ghost_hallucinated.py\n"
            "```"
        )
        paths = audit_evidence.extract_diff_paths(answer)
        self.assertEqual(paths, ["src/auth.py", "src/ghost_hallucinated.py"])

        repo = {
            "components": [{"files": ["src/auth.py", "src/main.py"]}],
            "coderabbit": {"action_items": []},
        }
        checks = audit_evidence.verify_diff_paths(paths, repo, None, None)
        self.assertEqual(
            checks,
            [
                {"path": "src/auth.py", "verified": True},
                {"path": "src/ghost_hallucinated.py", "verified": False},
            ],
        )

    def test_chat_answer_returns_references_instructions_and_diff_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("Follow strict typing.", encoding="utf-8")
            repo = {
                "local_path": str(root),
                "components": [{"files": ["app.py"]}],
                "coderabbit": {"action_items": []},
                "deps": {
                    "runtime": {"python": "3.8.10"},
                    "runtime_eol": [
                        {
                            "product": "python",
                            "declared": "3.8.10",
                            "cycle": "3.8",
                            "eol": "2024-10-07",
                            "is_eol": True,
                            "source": "endoflife.date",
                        }
                    ],
                },
            }
            evidence = {
                "path": "app.py",
                "head": "1234567890abcdef",
                "current_line": {"number": 42, "text": "x = 1"},
            }
            captured_user_payload = {}

            def fake_call_llm(provider, key, model, system, user_msg):
                captured_user_payload.update(json.loads(user_msg))
                return "--- a/app.py\n+++ b/app.py\n--- a/fake/file.py\n+++ b/fake/file.py"

            with mock.patch.object(audit_evidence, "load_settings", return_value={"active_provider": "openai"}), \
                 mock.patch.object(audit_evidence, "choose_active_llm", return_value=("openai", "sk-test", "gpt-4o-mini")), \
                 mock.patch.object(audit_evidence, "call_llm_provider", side_effect=fake_call_llm):
                res = audit_evidence.chat_answer(
                    {"question": "/fix", "language": "en", "history": []},
                    evidence,
                    repo=repo,
                )

            self.assertEqual(res["instructions_loaded"], ["AGENTS.md"])
            self.assertEqual(
                res["diff_path_checks"],
                [
                    {"path": "app.py", "verified": True},
                    {"path": "fake/file.py", "verified": False},
                ],
            )
            ref_kinds = [r["kind"] for r in res["references"]]
            self.assertIn("file", ref_kinds)
            self.assertIn("commit", ref_kinds)
            self.assertIn("instruction", ref_kinds)
            self.assertIn("eol", ref_kinds)
            self.assertIn("custom_instructions", captured_user_payload["verified_evidence"])
            self.assertIn("runtime_eol", captured_user_payload["verified_evidence"])


class TestEolChecker(unittest.TestCase):
    def test_evaluate_runtime_eol_with_live_mock(self) -> None:
        def fake_fetcher(url: str, timeout: float):
            if "python.json" in url:
                return [
                    {"cycle": "3.13", "eol": "2029-10-31", "latest": "3.13.2"},
                    {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"},
                ]
            if "nodejs.json" in url:
                return [
                    {"cycle": "22", "eol": "2027-04-30", "latest": "22.14.0"},
                    {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.7"},
                ]
            return []

        results = eol_checker.evaluate_runtime_eol(
            {"python": "3.8.10", "node": ">=22.0.0"},
            today="2026-11-23",
            fetcher=fake_fetcher,
            use_cache=False,
        )
        by_product = {r["product"]: r for r in results}
        self.assertTrue(by_product["python"]["is_eol"])
        self.assertEqual(by_product["python"]["latest_active_cycle"], "3.13")
        self.assertFalse(by_product["nodejs"]["is_eol"])
        self.assertEqual(by_product["nodejs"]["source"], "endoflife.date")

    def test_evaluate_runtime_eol_offline_fallback(self) -> None:
        def failing_fetcher(url: str, timeout: float):
            raise OSError("offline")

        results = eol_checker.evaluate_runtime_eol(
            {"php": "^7.4"},
            today="2026-11-23",
            fetcher=failing_fetcher,
            use_cache=False,
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["is_eol"])
        self.assertEqual(results[0]["cycle"], "7.4")
        self.assertEqual(results[0]["source"], "static-fallback")


if __name__ == "__main__":
    unittest.main()
