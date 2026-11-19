import os
import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import audit_evidence as audit

ENDPOINT = "repos/sample/repo"
STATUS_SHA = "a" * 40


class GitHubTransportTests(TestCase):
    def test_opt_in_rest_keeps_credential_out_of_arguments_and_targets_github(self):
        credential = b"fixture_credential_only_in_memory"
        reply = subprocess.CompletedProcess([], 0, b'{"ok":true}\n200 0.000010')
        with (
            patch.dict(os.environ, {"REPOAUDT_GITHUB_TRANSPORT": "rest"}),
            patch.object(audit, "rest_credential", return_value=credential),
            patch.object(audit.subprocess, "run", return_value=reply) as run,
        ):
            self.assertEqual(audit.github(ENDPOINT), {"ok": True})
        args = run.call_args.args[0]
        self.assertEqual(args[-1], "https://api.github.com/" + ENDPOINT)
        self.assertIn("--disable", args)
        self.assertNotIn("--location", args)
        self.assertNotIn(credential.decode(), " ".join(args))
        self.assertIn(
            b"Authorization: Bearer " + credential, run.call_args.kwargs["input"]
        )
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_rest_rejects_out_of_scope_endpoints_before_reading_credentials(self):
        with patch.object(audit, "rest_credential") as credential:
            for target in (
                "https://example.invalid/",
                ENDPOINT + "/contents/%2e%2e/file",
            ):
                with (
                    self.subTest(target=target),
                    self.assertRaisesRegex(
                        audit.EvidenceError, "Invalid GitHub repository endpoint"
                    ),
                ):
                    audit.github_rest(target)
        credential.assert_not_called()

    def test_rest_reports_http_status_without_body_and_does_not_follow_redirects(self):
        with patch.object(
            audit, "rest_credential", return_value=b"fixture_no_real_token"
        ):
            for status in (301, 403, 404):
                result = subprocess.CompletedProcess(
                    [], 0, f"private fixture\n{status} 0.000010".encode()
                )
                with (
                    self.subTest(status=status),
                    patch.object(audit.subprocess, "run", return_value=result),
                    self.assertRaisesRegex(
                        audit.EvidenceError, rf"^(?!.*private).*(?:{status})"
                    ),
                ):
                    audit.github_rest(ENDPOINT)

    def test_rest_diagnoses_timeout_before_dns_resolution_completed(self):
        result = subprocess.CompletedProcess([], 28, b"\n000 0.000000")
        with (
            patch.object(
                audit, "rest_credential", return_value=b"fixture_no_real_token"
            ),
            patch.object(audit.subprocess, "run", return_value=result),
            self.assertRaisesRegex(
                audit.EvidenceError, "could not resolve api.github.com"
            ),
        ):
            audit.github_rest(ENDPOINT)

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
