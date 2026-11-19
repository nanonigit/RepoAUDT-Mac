"""Resolve and acquire GitHub source without using the user's worktree."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from urllib.parse import quote

from audit_evidence import github, installed_github_cli

FULL_SHA = re.compile(r"[0-9a-f]{40}")
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.{1,2}$)[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,239}")


def valid_branch(branch):
    return (
        isinstance(branch, str)
        and bool(BRANCH.fullmatch(branch))
        and ".." not in branch
        and all(
            part and not part.startswith(".") and not part.endswith((".", ".lock"))
            for part in branch.split("/")
        )
    )


def resolve(owner, repo, *, branch=None, commit=None):
    if not SLUG.fullmatch(f"{owner}/{repo}"):
        raise ValueError("Invalid GitHub repository")
    if branch is not None and not valid_branch(branch):
        raise ValueError("Invalid GitHub branch")
    if commit is not None and (branch is not None or not FULL_SHA.fullmatch(commit)):
        raise ValueError("Select one GitHub branch or a full commit SHA")
    meta = github(f"repos/{owner}/{repo}")
    slug = meta["full_name"]
    default = meta["default_branch"]
    if not SLUG.fullmatch(slug) or not valid_branch(default):
        raise ValueError("GitHub returned invalid repository metadata")
    selected_branch = branch or (None if commit else default)
    if selected_branch is not None:
        data = github(f"repos/{slug}/branches/{quote(selected_branch, safe='')}")[
            "commit"
        ]
    else:
        data = github(f"repos/{slug}/commits/{commit}")
    sha = data["sha"]
    tree = data["commit"]["tree"]["sha"]
    if (
        not FULL_SHA.fullmatch(sha)
        or not FULL_SHA.fullmatch(tree)
        or (commit and sha != commit)
    ):
        raise ValueError("GitHub did not confirm the requested commit and tree")
    return {
        "kind": "github_commit",
        "selection": "commit" if commit else "branch" if branch else "default_branch",
        "repository": slug,
        "commit_sha": sha,
        "tree_sha": tree,
        "branch": selected_branch,
        "default_branch": default,
    }, {
        "createdAt": meta.get("created_at"),
        "updatedAt": meta.get("updated_at"),
        "pushedAt": meta.get("pushed_at"),
        "description": meta.get("description") or "",
    }


def isolated_git_environment():
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GH_PROMPT_DISABLED": "1",
        }
    )
    return env


def run_git(root, arguments, *, timeout=65, authorize=False):
    gh = installed_github_cli()
    config = [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.autocrlf=false",
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
    ]
    if authorize and gh:
        config += [
            "-c",
            f"credential.https://github.com.helper=!{shlex.quote(gh)} auth git-credential",
        ]
    try:
        result = subprocess.run(
            ["/usr/bin/git", *config, *arguments],
            cwd=root,
            env=isolated_git_environment(),
            timeout=timeout,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git could not acquire the pinned source") from exc
    if result.returncode:
        raise ValueError(
            "Git could not acquire the pinned source. Check repository access and retry."
        )
    return result.stdout.strip()


@contextmanager
def checkout(revision):
    slug = revision["repository"]
    sha = revision["commit_sha"]
    expected_tree = revision["tree_sha"]
    if (
        not SLUG.fullmatch(slug)
        or not FULL_SHA.fullmatch(sha)
        or not FULL_SHA.fullmatch(expected_tree)
    ):
        raise ValueError("Invalid source revision")
    with tempfile.TemporaryDirectory(prefix="repoaudt-pinned-") as tmp:
        root = Path(tmp)
        run_git(root, ["init", "--quiet", "--template="])
        run_git(
            root,
            [
                "fetch",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                f"https://github.com/{slug}.git",
                sha,
            ],
            authorize=True,
        )
        head = run_git(root, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"])
        tree = run_git(root, ["rev-parse", "--verify", "FETCH_HEAD^{tree}"])
        if head != sha or tree != expected_tree:
            raise ValueError(
                "Fetched Git objects do not match the selected GitHub revision"
            )
        # This untracked, highest-priority attributes file disables checkout conversions.
        info = root / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "attributes").write_text(
            "* !filter !working-tree-encoding !eol -text -ident\n"
        )
        run_git(root, ["checkout", "--quiet", "--detach", sha])
        yield root
