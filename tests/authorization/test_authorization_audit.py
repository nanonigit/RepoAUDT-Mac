from pathlib import Path
from unittest import TestCase
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import authorization_audit as audit

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

PIN = {"kind": "github_commit", "repository": "owner/repo", "commit_sha": "a" * 40}


class AuthorizationTests(TestCase):
    def test_evidence_is_ordered_and_anchored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(FIXTURE)
            findings, scope = audit.scan_authorization(root, PIN, str)
        self.assertEqual(scope["matches"], 1)
        result = findings[0]
        self.assertEqual(
            [step["kind"] for step in result["evidence_chain"]],
            ["entry", "boundary", "input", "privileged_effect"],
        )
        lines = [step["line"] for step in result["evidence_chain"]]
        self.assertEqual(lines, sorted(lines))
        self.assertTrue(
            all(
                step["commit"] == PIN["commit_sha"] for step in result["evidence_chain"]
            )
        )
        self.assertIn(PIN["commit_sha"], result["official_source"])

    def test_unknown_authorization_or_shadowing_route_abstains(self):
        for guard in (
            "        if not self.authorize_request():\n            return\n",
            '        if self.path.startswith("/api"):\n            return\n',
        ):
            guarded = FIXTURE.replace(
                '        if self.path.startswith("/api/example"):',
                guard + '        if self.path.startswith("/api/example"):',
            )
            self.assertEqual(list(audit.trace(guarded)), [])

    def test_unknown_authorization_inside_route_abstains(self):
        guarded = FIXTURE.replace(
            "            output = subprocess.run",
            "            if not self.allowed():\n                return\n            output = subprocess.run",
        )
        self.assertEqual(list(audit.trace(guarded)), [])
        self.assertEqual(
            list(audit.trace(FIXTURE.replace("shell=True", "shell=False"))), []
        )

    def test_defensive_patch_applies_and_stops_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "server.py"
            source.write_text(FIXTURE)
            findings, _ = audit.scan_authorization(root, PIN, str)
            diff = findings[0]["diff"]
            subprocess.run(
                ["/usr/bin/git", "apply", "--check", "-"],
                cwd=root,
                input=diff,
                text=True,
                check=True,
            )
            subprocess.run(
                ["/usr/bin/git", "apply", "-"],
                cwd=root,
                input=diff,
                text=True,
                check=True,
            )
            self.assertEqual(list(audit.trace(source.read_text())), [])
            self.assertIn("_send_json(410", source.read_text())

    def test_local_tree_has_no_pinned_authorization_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, scope = audit.scan_authorization(
                Path(tmp), {"kind": "local_worktree"}, str
            )
        self.assertEqual(findings, [])
        self.assertEqual(scope["status"], "requires_github_pin")

    def test_current_local_server_has_no_request_to_shell_match(self):
        backend = Path(__file__).resolve().parents[2] / "Resources/backend"
        self.assertEqual(list(audit.trace((backend / "server.py").read_text())), [])
