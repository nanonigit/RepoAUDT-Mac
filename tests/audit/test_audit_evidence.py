import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import audit_evidence as evidence
import security_audit_engine as engine

REFERENCE = 'DB_PASSWORD = "${aws_secretsmanager_secret.this["fixture/prod/db"].arn}:password::"'
LITERAL = 'DB_PASSWORD = "synthetic-fixture-password"'
HEAD = "a" * 40
OLD = "b" * 40
ROOT = "repos/example/fixture"
FILE = "modules/secrets/main.tf"


def git_blob(line, sha):
    return {
        "type": "file",
        "encoding": "base64",
        "sha": sha,
        "content": base64.b64encode(line.encode()).decode(),
    }


class AuditEvidenceTests(unittest.TestCase):
    def test_terraform_arn_reference_does_not_hide_literals_or_non_hcl(self):
        variants = [
            REFERENCE,
            REFERENCE.replace("DB_PASSWORD", "AUTH0_CLIENT_SECRET"),
            REFERENCE.replace("DB_PASSWORD", "AUTH0_MANAGEMENT_CLIENT_SECRET"),
        ]
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "main.tf").write_text("\n".join([*variants, LITERAL]))
            findings = engine.scan_secrets_and_credentials(folder, lambda _: "fixture")
            self.assertEqual([f["file"].split()[0] for f in findings], ["main.tf:4"])
            self.assertNotIn("synthetic-fixture-password", json.dumps(findings))
        self.assertFalse(engine.is_terraform_secret_arn("fixture.py", REFERENCE))
        self.assertFalse(
            engine.is_terraform_secret_arn(FILE, REFERENCE[:-1] + 'extra"')
        )

    def test_same_head_pins_content_and_identifies_saved_false_positive(self):
        repo = {
            "id": "fixture",
            "github_url": "https://github.com/example/fixture",
            "commit_hash": HEAD[:7],
            "coderabbit": {
                "action_items": [
                    {
                        "title": "シークレット漏洩検知 Database / Hardcoded Password",
                        "file": FILE + ":1 (Target: Test)",
                    }
                ]
            },
        }
        commit = {
            "sha": HEAD,
            "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}},
        }
        routes = {
            ROOT: {"default_branch": "master", "pushed_at": "2026-01-02T00:00:00Z"},
            f"{ROOT}/branches/master": {"commit": commit},
            f"{ROOT}/contents/{FILE}?ref={HEAD}": git_blob(REFERENCE, "same"),
            f"{ROOT}/commits?sha={HEAD}&path=modules%2Fsecrets%2Fmain.tf&per_page=1": [
                commit
            ],
        }
        with patch.object(evidence, "github", side_effect=routes.__getitem__) as github:
            result = evidence.handle(
                {"repository": "fixture", "path": FILE, "line": 1}, {"diagrams": [repo]}
            )
        self.assertEqual(github.call_count, 4)
        self.assertTrue(result["false_positive"])
        self.assertEqual(result["saved_sha"], HEAD)
        self.assertEqual(result["audited_line"], result["current_line"])

    def test_changed_line_can_be_linked_by_unique_assignment_but_ambiguous_line_is_unknown(
        self,
    ):
        self.assertEqual(
            evidence.match_line([LITERAL], ["# added", REFERENCE], 1, False, FILE), 2
        )
        self.assertIsNone(
            evidence.match_line([LITERAL], [REFERENCE, REFERENCE], 1, False, FILE)
        )
        self.assertIsNone(
            evidence.match_line([LITERAL], ["other"], 1, False, "main.py")
        )
        self.assertNotIn(
            "synthetic-fixture-password",
            evidence.source_line(FILE, [LITERAL], 1)["text"],
        )

    def test_chat_keeps_source_lines_out_of_provider_prompt(self):
        with (
            patch.object(evidence, "load_settings", return_value={}),
            patch.object(
                evidence, "choose_active_llm", return_value=("local", "", "test")
            ),
            patch.object(
                evidence, "call_llm_provider", return_value="A verified answer"
            ) as provider,
        ):
            result = evidence.chat_answer(
                {
                    "question": "What changed?",
                    "history": [{"role": "user", "text": "First"}],
                },
                {"head": HEAD, "current_line": {"text": LITERAL, "number": 42}},
            )
        self.assertEqual(result["answer"], "A verified answer")
        request = json.loads(provider.call_args.args[-1])
        self.assertEqual(request["verified_evidence"]["current_line"], {"number": 42})
        self.assertEqual(request["verified_evidence"]["head"], HEAD)

    def test_invalid_path_stops_before_network(self):
        repo = {"id": "fixture", "github_url": "https://github.com/example/fixture"}
        with patch.object(evidence, "github") as github:
            with self.assertRaises(evidence.EvidenceError):
                evidence.handle(
                    {"repository": "fixture", "path": "../secret", "line": 1},
                    {"diagrams": [repo]},
                )
            github.assert_not_called()
