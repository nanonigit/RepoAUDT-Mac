from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import analyzer
import source_revision

SHA = "a" * 40
TREE = "b" * 40


class SourceRevisionTests(unittest.TestCase):
    def test_github_resolution_returns_canonical_branch_commit_and_tree(self):
        responses = [
            {"full_name": "example/current", "default_branch": "main"},
            {"commit": {"sha": SHA, "commit": {"tree": {"sha": TREE}}}},
        ]
        with patch.object(source_revision, "github", side_effect=responses) as github:
            revision, _ = source_revision.resolve("example", "former")
        self.assertEqual(revision["repository"], "example/current")
        self.assertEqual(revision["branch"], "main")
        self.assertEqual(revision["commit_sha"], SHA)
        self.assertEqual(revision["tree_sha"], TREE)
        self.assertEqual(
            github.call_args.args, ("repos/example/current/branches/main",)
        )

    def test_background_refresh_spares_explicit_audit_targets(self):
        url = "https://github.com/example/repo"
        self.assertEqual(analyzer.automatic_refresh_url({"github_url": url}), url)
        for target in (
            {"is_root": True},
            {"source_revision": {"selection": "commit", "kind": "github_commit"}},
            {"source_revision": {"selection": "branch", "kind": "github_commit"}},
            {"source_revision": {"kind": "local_worktree"}},
        ):
            self.assertIsNone(
                analyzer.automatic_refresh_url({"github_url": url, **target})
            )

    def test_explicit_ref_survives_entrypoint(self):
        with patch.object(
            analyzer, "analyze_repository", return_value={"ok": True}
        ) as analyze:
            url = f"https://github.com/example/repo/commit/{SHA}"
            self.assertEqual(analyzer.analyze_any_github_target(url), {"ok": True})
            analyze.assert_called_once_with(url)
        self.assertEqual(
            analyzer.parse_github_target(
                "https://github.com/example/repo/tree/fix%2Fauth"
            )["branch"],
            "fix/auth",
        )
        for suffix in ("/commit/aabbcc0", "/blob/main/app.py", "/tree/..%2Fmain"):
            with self.assertRaises(ValueError):
                analyzer.parse_github_target(f"https://github.com/example/repo{suffix}")

    def test_pinned_checkout_uses_verified_commit_bytes_without_touching_dirty_source(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            origin = Path(folder)

            def git(*arguments):
                return subprocess.check_output(
                    [
                        "/usr/bin/git",
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=fixture@example.invalid",
                        *arguments,
                    ],
                    cwd=origin,
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()

            git("init")
            (origin / ".gitattributes").write_text("*.py text eol=crlf ident\n")
            (origin / "app.py").write_bytes(b"# $Id$\nprint(1)\n")
            (origin / "link.py").symlink_to("/private-fixture-only")
            git("add", ".")
            git("commit", "-m", "audit fixture")
            sha, tree = git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
            (origin / "app.py").write_text("uncommitted fixture\n")
            revision = {
                "repository": "example/repo",
                "commit_sha": sha,
                "tree_sha": tree,
            }
            run_git = source_revision.run_git

            def local_transport(root, arguments, **kwargs):
                if arguments[0] == "fetch":
                    self.assertEqual(arguments[-1], sha)
                    arguments = [*arguments[:-2], str(origin), sha]
                return run_git(root, arguments, **kwargs)

            with patch.object(source_revision, "run_git", side_effect=local_transport):
                with source_revision.checkout(revision) as checkout:
                    self.assertEqual(
                        (checkout / "app.py").read_bytes(), b"# $Id$\nprint(1)\n"
                    )
                    self.assertFalse((checkout / "link.py").is_symlink())
                self.assertFalse(checkout.exists())
                with self.assertRaisesRegex(ValueError, "do not match"):
                    with source_revision.checkout({**revision, "tree_sha": TREE}):
                        self.fail("An unverified tree reached the scanner")
            self.assertEqual((origin / "app.py").read_text(), "uncommitted fixture\n")

    def test_remote_analysis_never_uses_a_matching_local_clone(self):
        revision = {
            "repository": "example/repo",
            "kind": "github_commit",
            "commit_sha": SHA,
            "tree_sha": TREE,
        }

        @contextmanager
        def checkout(source):
            self.assertEqual(source, revision)
            yield Path("/tmp/pinned-fixture")

        with (
            patch.object(source_revision, "resolve", return_value=(revision, {})),
            patch.object(source_revision, "checkout", side_effect=checkout),
            patch.object(
                analyzer,
                "find_existing_local_repo",
                side_effect=AssertionError("local clone must not be read"),
            ),
            patch.object(
                analyzer, "analyze_checkout", return_value={"ok": True}
            ) as scan,
        ):
            self.assertEqual(
                analyzer.analyze_repository("https://github.com/example/repo"),
                {"ok": True},
            )
        self.assertEqual(scan.call_args.args[0], Path("/tmp/pinned-fixture"))
        self.assertEqual(scan.call_args.args[5], revision)

    def test_deleted_repos_stay_deleted_across_org_scan_and_sync(self):
        with tempfile.TemporaryDirectory() as folder:
            state_file = Path(folder) / "state.json"
            with patch.object(analyzer, "STATE_FILE", state_file):
                org_result = {
                    "mode": "org",
                    "owner": "nanonigit",
                    "diagrams": [
                        {
                            "id": "gh-org-nanonigit-ecosystem",
                            "repo": "nanonigit (全体エコシステム)",
                            "github_url": "https://github.com/nanonigit",
                            "is_root": True,
                        },
                        {
                            "id": "gh-nanonigit-desktopcalendar-overall",
                            "repo": "nanonigit/DesktopCalendar",
                            "github_url": "https://github.com/nanonigit/DesktopCalendar",
                            "is_root": False,
                        },
                    ],
                }
                analyzer.save_analysis_result(org_result)
                analyzer.delete_saved_diagram(
                    diagram_id="gh-nanonigit-desktopcalendar-overall"
                )

                # Org re-scan or background sync must not resurrect deleted child repos
                state_after_org = analyzer.save_analysis_result(org_result)
                self.assertEqual(
                    [d["id"] for d in state_after_org["diagrams"]],
                    ["gh-org-nanonigit-ecosystem"],
                )
                self.assertIn(
                    "gh-nanonigit-desktopcalendar-overall",
                    state_after_org["deleted_ids"],
                )

                # Sync with respect_deleted=True must also keep deleted repos hidden
                state_after_sync = analyzer.save_analysis_result(
                    {
                        "mode": "repo",
                        "diagrams": [
                            {
                                "id": "gh-nanonigit-desktopcalendar-overall",
                                "repo": "nanonigit/DesktopCalendar",
                                "github_url": "https://github.com/nanonigit/DesktopCalendar",
                            }
                        ],
                    },
                    respect_deleted=True,
                )
                self.assertEqual(
                    [d["id"] for d in state_after_sync["diagrams"]],
                    ["gh-org-nanonigit-ecosystem"],
                )
                self.assertIn(
                    "gh-nanonigit-desktopcalendar-overall",
                    state_after_sync["deleted_ids"],
                )

                # Explicit manual re-add (respect_deleted=False, mode="repo") restores it
                state_after_manual_add = analyzer.save_analysis_result(
                    {
                        "mode": "repo",
                        "diagrams": [
                            {
                                "id": "gh-nanonigit-desktopcalendar-overall",
                                "repo": "nanonigit/DesktopCalendar",
                                "github_url": "https://github.com/nanonigit/DesktopCalendar",
                            }
                        ],
                    }
                )
                self.assertEqual(
                    {d["id"] for d in state_after_manual_add["diagrams"]},
                    {
                        "gh-org-nanonigit-ecosystem",
                        "gh-nanonigit-desktopcalendar-overall",
                    },
                )
                self.assertNotIn(
                    "gh-nanonigit-desktopcalendar-overall",
                    state_after_manual_add["deleted_ids"],
                )
