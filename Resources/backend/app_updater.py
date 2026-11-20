"""Check for GitHub updates and trigger detached rebuild + relaunch for RepoAUDT Mac."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict


def find_repo_dir() -> Path:
    """Locate the local RepoAUDT-Mac git repository directory."""
    candidates = []
    env_dir = (os.environ.get("REPOAUDT_REPO_DIR") or "").strip()
    if env_dir:
        candidates.append(Path(env_dir).expanduser())
    candidates.append(Path.home() / "Git" / "RepoAUDT-Mac")
    candidates.append(Path(__file__).resolve().parent.parent.parent)

    for candidate in candidates:
        if (candidate / ".git").exists() and (candidate / "build.sh").exists():
            return candidate
    raise FileNotFoundError(
        "RepoAUDT-Mac のローカル Git リポジトリ (~/Git/RepoAUDT-Mac) が見つかりません。"
    )


def _git(repo_dir: Path, *args: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def check_for_updates() -> Dict[str, Any]:
    """Fetch origin/main and compare local HEAD against GitHub origin/main."""
    repo_dir = find_repo_dir()

    fetch = _git(repo_dir, "fetch", "origin", "main", timeout=30)
    if fetch.returncode != 0:
        err = (fetch.stderr or fetch.stdout or "git fetch origin main failed").strip()
        raise RuntimeError(f"GitHub からの最新情報取得に失敗しました: {err}")

    local_sha = _git(repo_dir, "rev-parse", "--short", "HEAD").stdout.strip()
    remote_sha = _git(repo_dir, "rev-parse", "--short", "origin/main").stdout.strip()
    behind_raw = _git(repo_dir, "rev-list", "--count", "HEAD..origin/main").stdout.strip()
    behind_count = int(behind_raw) if behind_raw.isdigit() else 0

    latest_msg = _git(repo_dir, "log", "-1", "--pretty=%s", "origin/main").stdout.strip()
    dirty = bool(_git(repo_dir, "status", "--porcelain").stdout.strip())

    return {
        "ok": True,
        "repo_dir": str(repo_dir),
        "local_commit": local_sha,
        "remote_commit": remote_sha,
        "behind_count": behind_count,
        "update_available": behind_count > 0,
        "latest_message": latest_msg,
        "dirty": dirty,
    }


def start_update_and_relaunch() -> Dict[str, Any]:
    """Pull origin/main, run ./build.sh --install, and relaunch RepoAUDT Mac in a detached process."""
    repo_dir = find_repo_dir()
    status = check_for_updates()
    if status.get("dirty"):
        raise RuntimeError(
            "ローカルリポジトリに未コミットの変更があるため自動アップデートできません。変更をコミットまたは退避してから再実行してください。"
        )
    if not status.get("update_available"):
        return {
            "ok": True,
            "started": False,
            "already_latest": True,
            "local_commit": status.get("local_commit", ""),
        }

    quoted_dir = shlex.quote(str(repo_dir))
    log_path = "/tmp/repoaudt-mac-update.log"
    script = (
        f"cd {quoted_dir} && "
        f"git pull --ff-only origin main && "
        f"./build.sh --install && "
        f'open -a "/Applications/RepoAUDT Mac.app"'
    )
    with open(log_path, "wb") as log_file:
        subprocess.Popen(
            ["/bin/bash", "-lc", script],
            cwd=str(repo_dir),
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )

    return {
        "ok": True,
        "started": True,
        "already_latest": False,
        "log_path": log_path,
        "remote_commit": status.get("remote_commit", ""),
    }
