"""Regression tests for secret scanning false positives and language-aware diff generation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import security_audit_engine  # noqa: E402


class TestSecretScanRegression(unittest.TestCase):
    def test_ignores_unit_test_file_and_placeholder_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_file = root / "src" / "external-services" / "__tests__" / "auth0-management-retry.test.ts"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "process.env.AUTH0_CLIENT_SECRET = 'unit-test-client-secret';\n",
                encoding="utf-8",
            )

            non_test_placeholder = root / "src" / "dev-defaults.ts"
            non_test_placeholder.write_text(
                "const client_secret = 'mock-placeholder-secret-value';\n",
                encoding="utf-8",
            )

            findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _: "Core")
            self.assertEqual(findings, [])

    def test_real_secret_uses_language_appropriate_diff_ts_and_py(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)

            ts_file = src_dir / "db.ts"
            ts_file.write_text(
                "const db_password = 'SuperRealProdPassword99!';\n",
                encoding="utf-8",
            )
            py_file = src_dir / "settings.py"
            py_file.write_text(
                'db_password = "SuperRealProdPassword99!"\n',
                encoding="utf-8",
            )

            findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _: "Core")
            self.assertEqual(len(findings), 2)

            by_file = {f["file"].split(":", 1)[0]: f for f in findings}
            ts_diff = by_file["src/db.ts"]["diff"]
            self.assertIn("process.env.DB_PASSWORD", ts_diff)
            self.assertNotIn("os.environ.get", ts_diff)

            py_diff = by_file["src/settings.py"]["diff"]
            self.assertIn('os.environ.get("DB_PASSWORD"', py_diff)
            self.assertNotIn("process.env.", py_diff)

    def test_csv_secondary_secret_never_leaks_in_diff_or_desc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_file = root / "src" / "common" / "configs" / "account.csv"
            csv_file.parent.mkdir(parents=True)
            secret_access_key = "8niyOBASWqv14LGf7K8GIt6Zgr+QyrSCxskHFLxh"
            csv_file.write_text(
                f"AKIA5S1234567890H27A,{secret_access_key}\n",
                encoding="utf-8",
            )

            findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _: "Core")
            self.assertEqual(len(findings), 1)
            serialized = str(findings[0])
            self.assertNotIn(secret_access_key, serialized)
            self.assertIn("- [REDACTED SECRET LINE]", findings[0]["diff"])

    def test_ignores_doc_ellipsis_pem_and_xxxx_openai_key_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "setup.md").write_text(
                'VIDEO_CLOUDFRONT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...(base64 content)...\\n-----END RSA PRIVATE KEY-----"\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                'OPENAI_API_KEY="sk-proj-example1234567890abcdefxxxx"\n',
                encoding="utf-8",
            )
            findings = security_audit_engine.scan_secrets_and_credentials(root, lambda _: "Docs")
            self.assertEqual(findings, [])

    def test_ignores_recaptcha_public_sitekey_but_keeps_secret_key(self) -> None:
        import source_scanners
        self.assertTrue(
            source_scanners._is_public_client_key_line(
                "sitekey:'6LfsDt0sAAAAALb1234567890abcdef1234PfIK',size:'normal'"
            )
        )
        self.assertTrue(
            source_scanners._is_public_client_key_line(
                "assert.equal(f.captcha.sitekey,'6LfsDt0sAAAAALb1234567890abcdef1234PfIK')"
            )
        )
        self.assertTrue(
            source_scanners._is_public_client_key_line(
                '    "aws_appsync_apiKey": "da2-xf1234567890abcdefghijkxhcu",'
            )
        )
        self.assertFalse(
            source_scanners._is_public_client_key_line(
                "RECAPTCHA_SECRET_KEY='6LfsDt0sAAAAALb1234567890abcdef1234PfIK'"
            )
        )


if __name__ == "__main__":
    unittest.main()
