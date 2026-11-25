import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent.parent / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gemini_cli_bridge
import security_audit_engine


class TestGeminiCliBridge(unittest.TestCase):
    def test_extract_response_text_handles_json_and_prefixed_warnings(self) -> None:
        raw = 'Warning: something\n{"response": "OK ready"}'
        self.assertEqual(gemini_cli_bridge._extract_response_text(raw), "OK ready")

    def test_call_gemini_cli_sync_invokes_headless_plan_mode(self) -> None:
        fake_proc = mock.Mock(returncode=0, stdout='{"response": "{\\"status\\": \\"ok\\"}"}', stderr="")
        with mock.patch.object(gemini_cli_bridge, "find_gemini_cli", return_value="/opt/homebrew/bin/gemini"), \
             mock.patch("subprocess.run", return_value=fake_proc) as run_mock:
            out = gemini_cli_bridge.call_gemini_cli_sync(
                model="gemini-2.5-pro",
                system_prompt="Be concise",
                user_prompt="Verify CVE",
            )
        self.assertEqual(out, '{"status": "ok"}')
        args = run_mock.call_args[0][0]
        self.assertEqual(
            args,
            ["/opt/homebrew/bin/gemini", "-p", "", "-o", "json", "--approval-mode", "plan", "-m", "gemini-2.5-pro"],
        )
        self.assertIn("[System Instructions]", run_mock.call_args[1]["input"])
        self.assertIn("Verify CVE", run_mock.call_args[1]["input"])

    def test_call_gemini_cli_sync_reports_login_required_clearly(self) -> None:
        fake_proc = mock.Mock(returncode=1, stdout="", stderr="Error: User unauthenticated. Please login.")
        with mock.patch.object(gemini_cli_bridge, "find_gemini_cli", return_value="/opt/homebrew/bin/gemini"), \
             mock.patch("subprocess.run", return_value=fake_proc):
            with self.assertRaises(RuntimeError) as ctx:
                gemini_cli_bridge.call_gemini_cli_sync(user_prompt="Ping")
        self.assertIn("Google アカウント", str(ctx.exception))

    def test_security_audit_engine_resolves_and_dispatches_gemini_cli(self) -> None:
        settings = {
            "active_provider": "gemini_cli",
            "keys": {"gemini_cli": ""},
            "models": {"gemini_cli": "auto"},
        }
        with mock.patch.object(gemini_cli_bridge, "is_gemini_cli_ready", return_value=True):
            resolved = security_audit_engine.choose_active_llm(settings)
        self.assertEqual(resolved, ("gemini_cli", "", "auto"))

        with mock.patch.object(gemini_cli_bridge, "call_gemini_cli_sync", return_value="verified") as call_mock:
            res = security_audit_engine.call_llm_provider("gemini_cli", "", "auto", "sys", "usr")
        self.assertEqual(res, "verified")
        call_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
