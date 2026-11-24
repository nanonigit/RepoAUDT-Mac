"""Golden benchmark regression tests for SSVC-based P0-P3 triage and false-positive exclusions."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import security_audit_engine  # noqa: E402
import triage_engine  # noqa: E402

GOLDEN_PATH = Path(__file__).resolve().parent / "golden_cases.json"


class TestGoldenTriage(unittest.TestCase):
    def test_golden_triage_cases(self) -> None:
        cases = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))["triage_cases"]
        self.assertGreaterEqual(len(cases), 20)
        for case in cases:
            with self.subTest(case=case["name"]):
                item = dict(case["item"])
                res = triage_engine.classify_priority_ssvc(item, kev_set=set())
                self.assertEqual(res["priority_tier"], case["expected_tier"], case["name"])
                self.assertEqual(res["confidence"], case["expected_confidence"], case["name"])
                self.assertTrue(len(res["priority_evidence"]) >= 1, case["name"])

    def test_false_positive_exclusions_zero_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. auth.docs.ts truncated JWT placeholder
            (root / "auth.docs.ts").write_text(
                'export const EXAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";\n',
                encoding="utf-8",
            )
            # 2. PROVENANCE_KEY snake_case constant & Recaptcha public Site Key
            (root / "constants.ts").write_text(
                'export const PROVENANCE_KEY = "PROVENANCE_KEY_METADATA";\n'
                'export const RECAPTCHA_SITE_KEY = "6Lc_public_recaptcha_site_key_example";\n',
                encoding="utf-8",
            )
            secret_hits = security_audit_engine.scan_secrets_and_credentials(root, lambda _p: "web")
            self.assertEqual(secret_hits, [])

            # 3. Safe GitHub Actions workflows (env: context & with: ref:)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "slack-notifications.yml").write_text(
                "on: [push]\njobs:\n  notify:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Notify\n        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$PR_TITLE\"\n",
                encoding="utf-8",
            )
            (wf_dir / "architecture-doc-autodraft.yml").write_text(
                "on: [pull_request]\njobs:\n  docs:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          ref: ${{ github.head_ref }}\n",
                encoding="utf-8",
            )
            wf_findings = security_audit_engine.scan_github_actions_workflows(root, lambda _p: "ci")
            self.assertEqual(wf_findings, [])


if __name__ == "__main__":
    unittest.main()
