"""Read-only verification of the deterministic authorization remediation."""

import hashlib
from pathlib import Path
import subprocess
import tempfile

import authorization_audit
import source_revision
from workflow_audit import MAX_FILE_BYTES


class VerificationError(ValueError):
    pass


def git_bytes(directory, args, *, patch=None):
    env = source_revision.isolated_git_environment()
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        result = subprocess.run(
            [
                "/usr/bin/git",
                "--no-replace-objects",
                "-c",
                "protocol.allow=never",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            cwd=directory,
            env=env,
            input=patch,
            capture_output=True,
            check=False,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("Git could not complete the local check.") from exc
    if result.returncode:
        raise VerificationError(
            "Git could not read the requested object or apply the recorded diff."
        )
    return result.stdout


def local_blob(directory, revision, path):
    slug = revision["repository"]
    accepted = {
        f"https://github.com/{slug}".lower(),
        f"https://github.com/{slug}.git".lower(),
        f"git@github.com:{slug}.git".lower(),
        f"ssh://git@github.com/{slug}.git".lower(),
    }
    remote = (
        git_bytes(directory, ["config", "--local", "--get", "remote.origin.url"])
        .decode()
        .strip()
        .lower()
    )
    if remote not in accepted:
        raise VerificationError(
            "The local origin does not match the recorded GitHub repository."
        )
    return pinned_blob(directory, revision, path)


def pinned_blob(directory, revision, path):
    sha, tree = revision["commit_sha"], revision["tree_sha"]
    actual = (
        git_bytes(directory, ["rev-parse", "--verify", sha + "^{tree}"])
        .strip()
        .decode("ascii")
    )
    if actual != tree:
        raise VerificationError("The local tree does not match the audit revision.")
    entry = sha + ":" + path
    size = int(git_bytes(directory, ["cat-file", "-s", entry]).strip())
    if not 0 <= size <= MAX_FILE_BYTES:
        raise VerificationError(
            "The audited source file exceeds the verification limit."
        )
    record = git_bytes(directory, ["ls-tree", "-z", sha, "--", path])
    header, separator, name = record.partition(b"\t")
    fields = header.split()
    if (
        not separator
        or name != path.encode() + b"\0"
        or len(fields) != 3
        or fields[0] not in (b"100644", b"100755")
        or fields[1] != b"blob"
    ):
        raise VerificationError("The pinned path is not a regular source file.")
    expected = fields[2].decode("ascii")
    data = git_bytes(directory, ["cat-file", "blob", entry])
    if (
        len(data) != size
        or hashlib.sha1(f"blob {size}\0".encode() + data).hexdigest() != expected
    ):
        raise VerificationError("The source bytes do not match the pinned Git blob.")
    return data


def obtain_source(revision, path, find_local):
    owner, repo = revision["repository"].split("/")
    local = find_local(owner, repo)
    if local is not None:
        try:
            return local_blob(local, revision, path), "local_git"
        except (VerificationError, ValueError, UnicodeError):
            pass
    try:
        with source_revision.checkout(revision) as directory:
            return pinned_blob(directory, revision, path), "github_checkout"
    except (OSError, ValueError) as exc:
        raise VerificationError(
            "The pinned source is unavailable from local Git objects and GitHub."
        ) from exc


def verify_source(data, path, line, stored_diff):
    try:
        source = data.decode("utf-8")
        before = list(authorization_audit.trace(source))
    except (UnicodeError, SyntaxError, ValueError, RecursionError) as exc:
        raise VerificationError(
            "The pinned Python source could not be analyzed."
        ) from exc
    matches = [route for route, _ in before if route.lineno == line]
    if len(matches) != 1:
        raise VerificationError("The original finding did not match the pinned source.")
    proposed = authorization_audit.proposed_patch(source, path, matches[0])
    if (
        not proposed
        or proposed != stored_diff
        or len(proposed.encode()) > MAX_FILE_BYTES
    ):
        raise VerificationError(
            "The recorded diff does not match the generated remediation."
        )
    patch = proposed.encode()
    with tempfile.TemporaryDirectory(prefix="repoaudt-diff-verify-") as tmp:
        root = Path(tmp)
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        git_bytes(root, ["init", "--quiet", "--template="])
        git_bytes(root, ["apply", "--check", "-"], patch=patch)
        git_bytes(root, ["apply", "-"], patch=patch)
        try:
            after = list(authorization_audit.trace(target.read_bytes().decode("utf-8")))
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError) as exc:
            raise VerificationError("The patched copy could not be analyzed.") from exc
    target_route = authorization_audit.route_path(matches[0])
    remains = any(
        authorization_audit.route_path(route) == target_route for route, _ in after
    )
    return {
        "status": "clear" if not remains else "still_detected",
        "before": "detected",
        "after": "detected" if remains else "not_detected",
        "other_matches_before": len(before) - 1,
        "matches_after": len(after),
        "diff_sha256": hashlib.sha256(patch).hexdigest(),
    }


def handle(payload, state, find_local):
    if not isinstance(payload, dict):
        raise VerificationError("Select a saved finding.")
    path, line = payload.get("path"), payload.get("line")
    if (
        not isinstance(path, str)
        or not authorization_audit.SAFE_PATH.fullmatch(path)
        or len(path) > 500
        or any(part in ("", ".", "..", ".git") for part in path.split("/"))
        or type(line) is not int
        or not 1 <= line <= 1_000_000
    ):
        raise VerificationError("Select a supported source line.")
    repo = next(
        (
            item
            for item in state.get("diagrams", [])
            if item.get("id") == payload.get("repository") and not item.get("is_root")
        ),
        None,
    )
    revision = (repo.get("source_revision") or {}) if repo else {}
    sha, tree, slug = (
        revision.get(key) for key in ("commit_sha", "tree_sha", "repository")
    )
    if (
        revision.get("kind") != "github_commit"
        or not all(isinstance(value, str) for value in (sha, tree, slug))
        or not source_revision.FULL_SHA.fullmatch(sha)
        or not source_revision.FULL_SHA.fullmatch(tree)
        or not source_revision.SLUG.fullmatch(slug)
        or repo.get("commit_hash") != sha
    ):
        raise VerificationError("A verified GitHub commit is required.")
    items = (repo.get("coderabbit") or {}).get("action_items") or []
    match = next(
        (
            item
            for item in items
            if item.get("scanner") == "authorization-evidence"
            and item.get("id") == authorization_audit.RULE_ID
            and item.get("file") == f"{path}:{line}"
        ),
        None,
    )
    if not match or not isinstance(match.get("diff"), str):
        raise VerificationError("This finding has no supported saved diff.")
    source, provenance = obtain_source(revision, path, find_local)
    return {
        **verify_source(source, path, line, match["diff"]),
        "commit": sha,
        "tree": tree,
        "file": path,
        "line": line,
        "source": provenance,
        "rule": authorization_audit.RULE_ID,
    }
