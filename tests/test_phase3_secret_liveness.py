"""Unit tests for Phase 3: Opt-in, read-only secret liveness verification."""

from __future__ import annotations

import io
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
import secret_verifier  # noqa: E402
import security_audit_engine  # noqa: E402
import server  # noqa: E402


class TestPhase3SecretLiveness(unittest.TestCase):
    def test_providers_active_and_revoked_without_exposing_raw_secrets(self) -> None:
        cases = [
            ("openai", "config.py", "OPENAI_API_KEY = 'sk-proj-LIVE999988887777666655554444'\n", "sk-proj-LIVE999988887777666655554444", ""),
            ("github", ".env", "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n", "ghp_1234567890abcdef1234567890abcdef1234", ""),
            ("slack", "bot.env", "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890-abcdef123456\n", "xoxb-1234567890-1234567890-abcdef123456", ""),
            (
                "aws",
                "aws.env",
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for provider, fname, content, raw_primary, raw_secondary in cases:
                (root / fname).write_text(content, encoding="utf-8")

                # 1. Active case
                if provider == "slack":
                    active_resp = (200, json.dumps({"ok": True}))
                    revoked_resp = (200, json.dumps({"ok": False, "error": "token_revoked"}))
                elif provider == "aws":
                    active_resp = (200, "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>")
                    revoked_resp = (403, "<Error><Code>InvalidClientTokenId</Code></Error>")
                else:
                    active_resp = (200, "{}")
                    revoked_resp = (401, '{"error":"invalid_api_key"}')

                with self.subTest(provider=provider, state="active"):
                    with mock.patch.object(secret_verifier, "_http_request", return_value=active_resp):
                        res = secret_verifier.verify_secret_in_file(root, fname, line_hint=1)
                    self.assertEqual(res["status"], "active")
                    self.assertEqual(res["provider"], provider)
                    if provider == "aws":
                        self.assertEqual(res.get("account_id"), "123456789012")
                    serialized = json.dumps(res)
                    self.assertNotIn(raw_primary, serialized)
                    if raw_secondary:
                        self.assertNotIn(raw_secondary, serialized)

                with self.subTest(provider=provider, state="revoked"):
                    with mock.patch.object(secret_verifier, "_http_request", return_value=revoked_resp):
                        res_rev = secret_verifier.verify_secret_in_file(root, fname, line_hint=1)
                    self.assertEqual(res_rev["status"], "revoked")
                    self.assertEqual(res_rev["provider"], provider)
                    serialized_rev = json.dumps(res_rev)
                    self.assertNotIn(raw_primary, serialized_rev)
                    if raw_secondary:
                        self.assertNotIn(raw_secondary, serialized_rev)

    def test_api_secrets_verify_endpoint_downgrades_revoked_and_hides_raw_secret(self) -> None:
        raw_key = "sk-proj-SECRETKEYVALUE9876543210ABCDEF"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(f"OPENAI_API_KEY={raw_key}\n", encoding="utf-8")
            state_file = root / "saved_analyses.json"
            initial_state = {
                "diagrams": [
                    {
                        "id": "diag-sec-1",
                        "repo": "acme/sec-app",
                        "local_path": str(root),
                        "coderabbit": {
                            "action_items": [
                                {
                                    "fingerprint": "fp-sec-1",
                                    "title": "Hardcoded OpenAI key",
                                    "file": ".env:1 (Target: backend)",
                                    "priority_tier": "P0",
                                    "category": "secrets",
                                }
                            ]
                        },
                    }
                ]
            }
            state_file.write_text(json.dumps(initial_state), encoding="utf-8")

            captured: list[tuple[int, dict]] = []

            class DummyPostHandler(server.RepoAUDTRequestHandler):
                def __init__(self, body: dict) -> None:
                    raw = json.dumps(body).encode("utf-8")
                    self.path = "/api/secrets/verify"
                    self.server_port = 8765
                    self.headers = {"Content-Length": str(len(raw))}
                    self.rfile = io.BytesIO(raw)
                    self.wfile = io.BytesIO()

                def _send_json(self, code: int, payload: object, cache_max_age: int = 0) -> None:
                    captured.append((code, payload))  # type: ignore[arg-type]

            with mock.patch.object(analyzer, "STATE_FILE", state_file), \
                 mock.patch.object(secret_verifier, "_http_request", return_value=(401, "{}")):
                handler = DummyPostHandler(
                    {"diagram_id": "diag-sec-1", "fingerprint": "fp-sec-1", "file": ".env:1 (Target: backend)"}
                )
                handler.do_POST()

            self.assertEqual(captured[-1][0], 200)
            resp_payload = captured[-1][1]
            self.assertEqual(resp_payload["status"], "revoked")
            self.assertNotIn(raw_key, json.dumps(resp_payload))

            saved = json.loads(state_file.read_text(encoding="utf-8"))
            item = saved["diagrams"][0]["coderabbit"]["action_items"][0]
            self.assertEqual(item["priority_tier"], "P3")
            self.assertEqual(item["secret_liveness"]["status"], "revoked")
            self.assertNotIn(raw_key, json.dumps(saved))

    def test_normal_secret_scan_never_calls_external_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("OPENAI_API_KEY = 'sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as mock_urlopen:
                findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _p: "app")
                self.assertTrue(len(findings) >= 1)
                mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
