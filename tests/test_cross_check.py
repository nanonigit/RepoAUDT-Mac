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

    def test_llm_connection_respects_model_override(self) -> None:
        fake_settings = {
            "active_provider": "gemini_cli",
            "keys": {"gemini_cli": ""},
            "models": {"gemini_cli": "gemini-4-neon-medium"},
        }
        with mock.patch.object(security_audit_engine, "load_settings", return_value=fake_settings), \
             mock.patch.object(security_audit_engine, "call_llm_provider", return_value='{"status":"ok"}') as call_mock:
            res = security_audit_engine.test_llm_connection(
                "gemini_cli",
                model_override="claude-opus-5-5-high",
            )
        self.assertTrue(res["ok"])
        self.assertEqual(res["model"], "claude-opus-5-5-high")
        self.assertEqual(call_mock.call_args.kwargs.get("model"), "claude-opus-5-5-high")

    def test_server_imports_re_for_cross_check_redaction(self) -> None:
        import server
        self.assertTrue(hasattr(server, "re"), "server.py must import re for /api/audit/cross-check secret redaction")

    def test_merge_ai_and_static_findings_deduplicates_osv_and_gha(self) -> None:
        items = [
            # AI duplicate of OSV next
            {
                "severity": "critical",
                "title": "[GEMINI_CLI AI監査] Next.js 13.5.8 における Middleware 認可バイパス脆弱性 (CVE-2025-29927)",
                "file": "package.json:34 (Target: configs)",
                "desc": "Next.js 13.5.8 には認可バイパスがあります。",
                "diff": '- "next": "13.5.8"\n+ "next": "13.5.9"',
            },
            # AI unique dependency finding NOT in OSV -> must be preserved
            {
                "severity": "high",
                "title": "[GEMINI_CLI AI監査] mysql2 が脆弱な 2.x 系に固定されている (CWE-94)",
                "file": "package.json:39 (Target: auth)",
                "desc": "mysql2 2.3.3 には任意コード実行リスクがあります。",
                "diff": '- "mysql2": "^2.3.3"\n+ "mysql2": "^3.9.7"',
            },
            # OSV canonical finding for next
            {
                "severity": "high",
                "title": "[OSV脆弱性検出] next v13.5.8 (GHSA-2464-fhr4-w9xw)",
                "file": "package.json",
                "desc": "OSV.dev 脆弱性データベースにおいて next v13.5.8 に既知の脆弱性が報告されています。",
            },
            # AI consolidated GitHub Actions injection finding
            {
                "severity": "critical",
                "title": "[GEMINI_CLI AI監査] GitHub Actions の run ブロックにおける github.head_ref 直接展開によるコマンドインジェクション (CWE-78)",
                "file": ".github/workflows/branch-merge-validation.yml:19 (Target: components)",
                "desc": "env 経由で参照してください。",
            },
            # Static per-line GitHub Actions injection findings -> should collapse into AI finding
            {
                "severity": "critical",
                "title": "🚨 [GitHub Actions監査] `${{ ... }}` によるシェルインジェクションリスク (branch-merge-validation.yml:31)",
                "file": ".github/workflows/branch-merge-validation.yml:31 (Target: components)",
                "desc": "31行目で直接展開されています。",
            },
            {
                "severity": "critical",
                "title": "🚨 [GitHub Actions監査] `${{ ... }}` によるシェルインジェクションリスク (branch-merge-validation.yml:43)",
                "file": ".github/workflows/branch-merge-validation.yml:43 (Target: components)",
                "desc": "43行目で直接展開されています。",
            },
            # AI unique CI/CD finding (self-hosted runner) -> must be preserved
            {
                "severity": "high",
                "title": "[GEMINI_CLI AI監査] pull_request トリガーで未検証のPRコードを共有セルフホストランナー上で実行している (CWE-94)",
                "file": ".github/workflows/astra-review-tests.yml:14 (Target: components)",
                "desc": "ubuntu-latest へ移行してください。",
            },
        ]
        merged = security_audit_engine.merge_ai_and_static_findings(items)
        self.assertEqual(len(merged), 4)
        titles = [m["title"] for m in merged]
        # OSV next kept and enriched with AI note
        osv_next = next(m for m in merged if m["title"].startswith("[OSV脆弱性検出] next"))
        self.assertTrue(osv_next.get("ai_corroborated"))
        self.assertIn("【AI監査補足】", osv_next["desc"])
        # Unique AI mysql2 kept
        self.assertTrue(any("mysql2" in t for t in titles))
        # AI GHA kept with static lines L31, L43 appended, static rows collapsed
        ai_gha = next(m for m in merged if "branch-merge-validation.yml" in m["file"])
        self.assertIn("【静的スキャナ検知行】L31, L43", ai_gha["desc"])
        self.assertTrue(ai_gha.get("static_corroborated"))
        self.assertFalse(any("[GitHub Actions監査]" in t for t in titles))
        # Unique AI astra-review-tests.yml kept
        self.assertTrue(any("astra-review-tests.yml" in m["file"] for m in merged))


if __name__ == "__main__":
    unittest.main()
