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


if __name__ == "__main__":
    unittest.main()
