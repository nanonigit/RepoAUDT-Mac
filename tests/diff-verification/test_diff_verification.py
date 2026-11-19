from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import authorization_audit
import diff_verification as verify

FIXTURE = """class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        origin = self.headers.get("Origin")
        if origin and not self._get_allowed_origin():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body_raw = self.rfile.read(length).decode("utf-8")
        if self.path.startswith("/api/example"):
            body = json.loads(body_raw)
            cmd = (body.get("command") or "").strip()
            if not cmd:
                return
            output = subprocess.run(cmd, shell=True)
            return
"""


class DiffVerificationTests(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "server.py"
        self.git("init")
        self.git("config", "remote.origin.url", "https://github.com/example/repo.git")
        self.source.write_text(FIXTURE)
        self.git("add", "server.py")
        self.git("commit", "-m", "static fixture")
        sha, tree = self.git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
        self.revision = {
            "kind": "github_commit",
            "repository": "example/repo",
            "commit_sha": sha,
            "tree_sha": tree,
        }
        report, _ = authorization_audit.scan_authorization(
            self.root, self.revision, str
        )
        self.finding = report[0]
        self.state = {
            "diagrams": [
                {
                    "id": "fixture",
                    "source_revision": self.revision,
                    "commit_hash": sha,
                    "coderabbit": {"action_items": report},
                }
            ]
        }
        self.payload = {
            "repository": "fixture",
            "path": "server.py",
            "line": int(self.finding["file"].split(":")[1]),
        }

    def git(self, *args):
        return subprocess.check_output(
            [
                "/usr/bin/git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=fixture@example.invalid",
                *args,
            ],
            cwd=self.root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()

    def test_local_git_blob_verifies_diff_without_changing_dirty_files(self):
        self.source.write_text("uncommitted source\n")
        head = self.git("rev-parse", "HEAD")
        with patch.object(
            verify.source_revision,
            "checkout",
            side_effect=AssertionError("network not needed"),
        ):
            result = verify.handle(self.payload, self.state, lambda *_: self.root)
        self.assertEqual(result["status"], "clear")
        self.assertEqual(result["source"], "local_git")
        self.assertEqual(result["commit"], head)
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        self.assertEqual(self.source.read_text(), "uncommitted source\n")

    def test_modified_saved_diff_never_reaches_git_apply(self):
        self.finding["diff"] += "\n"
        with self.assertRaisesRegex(
            verify.VerificationError, "recorded diff does not match"
        ):
            verify.handle(self.payload, self.state, lambda *_: self.root)

    def test_wrong_tree_or_wrong_origin_cannot_be_used(self):
        other = {**self.revision, "tree_sha": "0" * 40}
        with self.assertRaisesRegex(verify.VerificationError, "tree does not match"):
            verify.local_blob(self.root, other, "server.py")
        self.git("config", "remote.origin.url", "https://github.com/example/different")
        with self.assertRaisesRegex(verify.VerificationError, "origin does not match"):
            verify.local_blob(self.root, self.revision, "server.py")

    def test_missing_pinned_source_or_unsupported_path_is_not_clear(self):
        with patch.object(
            verify.source_revision, "checkout", side_effect=ValueError("offline")
        ):
            with self.assertRaisesRegex(
                verify.VerificationError, "pinned source is unavailable"
            ):
                verify.handle(self.payload, self.state, lambda *_: None)
        with self.assertRaisesRegex(verify.VerificationError, "supported source line"):
            verify.handle(
                {**self.payload, "path": "../server.py"},
                self.state,
                lambda *_: self.root,
            )
