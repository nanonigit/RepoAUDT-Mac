import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import audit_evidence as audit

SHA = "a" * 40
FILE = "server.py"
TEXT = "LOCAL_RECORDED_SOURCE"


def saved_state(sha=SHA):
    return {
        "diagrams": [
            {
                "id": "fixture",
                "github_url": "https://github.com/owner/repo",
                "commit_hash": SHA,
                "source_revision": {"kind": "github_commit", "commit_sha": SHA},
                "coderabbit": {
                    "action_items": [
                        {
                            "file": f"{FILE}:4",
                            "scanner": "authorization-evidence",
                            "recorded_source": {
                                "commit": sha,
                                "file": FILE,
                                "number": 4,
                                "text": TEXT,
                            },
                        }
                    ]
                },
            }
        ]
    }


class RecordedSourceTests(unittest.TestCase):
    def test_unavailable_live_comparison_keeps_only_the_recorded_revision(self):
        payload = {"repository": "fixture", "path": FILE, "line": 4}
        with patch.object(
            audit, "repository_status", side_effect=audit.EvidenceError("offline")
        ):
            result = audit.handle(payload, saved_state())
        self.assertEqual(result["saved_sha"], SHA)
        self.assertEqual(result["audited_source"], "recorded")
        self.assertEqual(result["audited_line"]["text"], TEXT)
        self.assertTrue(result["latest_unavailable"])
        self.assertNotIn("head", result)
        self.assertEqual(result["line_comparison"], "unresolved")

    def test_record_for_another_commit_cannot_be_used(self):
        payload = {"repository": "fixture", "path": FILE, "line": 4}
        with (
            patch.object(
                audit, "repository_status", side_effect=audit.EvidenceError("offline")
            ),
            self.assertRaisesRegex(audit.EvidenceError, "offline"),
        ):
            audit.handle(payload, saved_state("b" * 40))

    def test_offline_chat_evidence_excludes_the_source_text(self):
        payload = {
            "repository": "fixture",
            "path": FILE,
            "line": 4,
            "question": "What is verified?",
        }
        with (
            patch.object(
                audit, "repository_status", side_effect=audit.EvidenceError("offline")
            ),
            patch.object(audit, "load_settings", return_value={}),
            patch.object(
                audit, "choose_active_llm", return_value=("local", "", "test")
            ),
            patch.object(
                audit, "call_llm_provider", return_value="fixture answer"
            ) as model,
        ):
            result = audit.handle(payload, saved_state(), chat=True)
        sent = model.call_args.args[-1]
        self.assertNotIn(TEXT, sent)
        self.assertEqual(
            json.loads(sent)["verified_evidence"]["audited_source"], "recorded"
        )
        self.assertEqual(result["answer"], "fixture answer")
