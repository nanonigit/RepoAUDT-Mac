from pathlib import Path
import subprocess
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import audit_evidence as audit

ENDPOINT = "repos/sample/repo"
STATUS_SHA = "a" * 40


class GitHubTransportTests(TestCase):
    def test_socket_failure_reports_only_the_transport_category(self):
        failure = subprocess.CompletedProcess(
            [], 1, b"", b"dial tcp: connect: bad file descriptor; fixture private text"
        )
        with patch.object(audit.subprocess, "run", return_value=failure) as run:
            with self.assertRaisesRegex(
                audit.EvidenceError, r"^GitHub CLI could not connect to GitHub\.$"
            ):
                audit.github(ENDPOINT)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_auth_denial_and_timeouts_are_distinct(self):
        failure = subprocess.CompletedProcess(
            [], 1, b"", b"HTTP 403: fixture private text"
        )
        with patch.object(audit.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(
                audit.EvidenceError,
                r"^GitHub returned HTTP 403\. Check access and retry\.$",
            ):
                audit.github(ENDPOINT)
        with patch.object(
            audit.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 1)
        ):
            with self.assertRaisesRegex(audit.EvidenceError, "timed out"):
                audit.github(ENDPOINT)

    def test_local_credential_health_discards_sensitive_outputs_and_does_not_claim_access(
        self,
    ):
        with (
            patch.object(audit, "installed_github_cli", return_value="/test/gh"),
            patch.object(
                audit.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
            ) as run,
        ):
            self.assertEqual(audit.github_cli_credential_status(), "present")
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        with patch.object(audit, "installed_github_cli", return_value=None):
            self.assertEqual(audit.github_cli_credential_status(), "not_installed")

    def test_saved_branch_is_preserved_in_current_source_lookup(self):
        saved = {
            "id": "fixture",
            "github_url": "https://github.com/sample/repo",
            "commit_hash": STATUS_SHA,
            "source_revision": {
                "kind": "github_commit",
                "selection": "branch",
                "branch": "feature/review",
            },
        }
        status = {
            "sha": STATUS_SHA,
            "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}},
        }
        with patch.object(
            audit,
            "github",
            side_effect=[{"default_branch": "main"}, {"commit": status}],
        ) as lookup:
            outcome = audit.handle({"repository": "fixture"}, {"diagrams": [saved]})
        self.assertEqual(outcome["branch"], "feature/review")
        self.assertEqual(
            lookup.call_args.args, (ENDPOINT + "/branches/feature%2Freview",)
        )
