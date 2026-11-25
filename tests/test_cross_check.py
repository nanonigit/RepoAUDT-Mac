import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent.parent / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import security_audit_engine


class TestCrossCheckAndStaticOnlyMode(unittest.TestCase):
    def test_static_only_mode_makes_zero_llm_calls(self) -> None:
        settings = {
            "active_provider": "none",
            "secondary_provider": "none",
            "keys": {"openai": "sk-test-1234567890"},
            "models": {"openai": "gpt-4o"},
            "skills": {"llm_deep_audit": True},
        }
        self.assertIsNone(security_audit_engine.choose_active_llm(settings))
        self.assertIsNone(security_audit_engine.choose_secondary_llm(settings))

        with mock.patch.object(security_audit_engine, "call_llm_provider") as call_mock:
            res = security_audit_engine.cross_check_finding(
                "org/repo",
                {"title": "Test finding", "file": "package.json", "tier": "P1"},
                settings=settings,
            )
        call_mock.assert_not_called()
        self.assertEqual(res["mode"], "static_only")
        self.assertEqual(res["consensus"], "static_only")

    def test_dual_ai_agreed_confirmed(self) -> None:
        settings = {
            "active_provider": "gemini_cli",
            "secondary_provider": "copilot",
            "secondary_model": "auto",
            "keys": {"gemini_cli": "", "copilot": ""},
            "models": {"gemini_cli": "gemini-4-neon-high", "copilot": "auto"},
            "skills": {"llm_deep_audit": True},
        }
        reply = '{"verdict":"confirmed","confidence":"high","summary":"実コードで到達可能","action":"即修正"}'
        with mock.patch.object(security_audit_engine.gemini_cli_bridge, "is_gemini_cli_ready", return_value=True), \
             mock.patch.object(security_audit_engine.copilot_bridge, "is_copilot_ready", return_value=True), \
             mock.patch.object(security_audit_engine, "call_llm_provider", return_value=reply) as call_mock:
            res = security_audit_engine.cross_check_finding(
                "org/repo",
                {"title": "Sentry tunnel bypass", "file": "next.config.ts:63", "tier": "P1"},
                code_context="tunnelRoute: '/monitoring'",
                settings=settings,
            )
        self.assertEqual(call_mock.call_count, 2)
        self.assertEqual(res["mode"], "dual_ai")
        self.assertEqual(res["consensus"], "agreed_confirmed")
        self.assertEqual(res["primary"]["provider"], "gemini_cli")
        self.assertEqual(res["secondary"]["provider"], "copilot")

    def test_dual_ai_split_verdict_flags_disagreed(self) -> None:
        settings = {
            "active_provider": "gemini_cli",
            "secondary_provider": "copilot",
            "keys": {"gemini_cli": "", "copilot": ""},
            "models": {"gemini_cli": "auto", "copilot": "auto"},
            "skills": {"llm_deep_audit": True},
        }
        def fake_call(provider, *_args, **_kwargs):
            if provider == "gemini_cli":
                return '{"verdict":"confirmed","confidence":"medium","summary":"可能性あり","action":"確認"}'
            return '{"verdict":"likely_false_positive","confidence":"high","summary":"設定非該当","action":"不要"}'

        with mock.patch.object(security_audit_engine.gemini_cli_bridge, "is_gemini_cli_ready", return_value=True), \
             mock.patch.object(security_audit_engine.copilot_bridge, "is_copilot_ready", return_value=True), \
             mock.patch.object(security_audit_engine, "call_llm_provider", side_effect=fake_call):
            res = security_audit_engine.cross_check_finding(
                "org/repo",
                {"title": "Next.js SVG RCE", "file": "package.json", "tier": "P1"},
                settings=settings,
            )
        self.assertEqual(res["mode"], "dual_ai")
        self.assertEqual(res["consensus"], "disagreed")


if __name__ == "__main__":
    unittest.main()
