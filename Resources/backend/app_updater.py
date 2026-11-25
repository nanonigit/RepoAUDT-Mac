"""Check for GitHub updates and trigger detached rebuild + relaunch for RepoAUDT Mac."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict

import copilot_bridge
import gemini_cli_bridge

BREW_UPGRADABLE_TOOLS = frozenset({
    "gh",
    "gitleaks",
    "trufflehog",
    "trivy",
    "semgrep",
    "ruff",
    "zizmor",
    "hadolint",
})


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
    fetch_output = (fetch.stderr or fetch.stdout or "").strip()
    log_lines = [f"Checking RepoAUDT Mac updates from {repo_dir}..."]
    if fetch_output:
        log_lines.append(fetch_output)
    if behind_count == 0:
        log_lines.append(f"Already up to date ({local_sha}).")
    else:
        log_lines.append(
            f"{behind_count} new commit(s) available ({local_sha} -> {remote_sha}): {latest_msg}"
        )

    return {
        "ok": True,
        "repo_dir": str(repo_dir),
        "local_commit": local_sha,
        "remote_commit": remote_sha,
        "behind_count": behind_count,
        "update_available": behind_count > 0,
        "latest_message": latest_msg,
        "dirty": dirty,
        "log": "\n".join(log_lines),
    }


def _find_brew() -> str:
    for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if Path(candidate).exists():
            return candidate
    return shutil.which("brew") or ""


def _probe_brew_outdated() -> Dict[str, str]:
    """Return {formula_name: latest_version} for outdated allowlisted Homebrew tools."""
    brew_bin = _find_brew()
    if not brew_bin:
        return {}
    env = dict(os.environ)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"
    try:
        proc = subprocess.run(
            [brew_bin, "outdated", "--formula", "--json=v2"],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        data = json.loads(proc.stdout)
        outdated: Dict[str, str] = {}
        for formula in data.get("formulae") or []:
            if not isinstance(formula, dict):
                continue
            name = str(formula.get("name") or "").strip().lower()
            latest = str(formula.get("current_version") or "").strip()
            if name in BREW_UPGRADABLE_TOOLS and latest:
                outdated[name] = latest
        return outdated
    except Exception:
        return {}


def _probe_pypi_latest(package: str) -> str:
    """Return the latest version string for a PyPI package, or empty string on error."""
    try:
        req = urllib.request.Request(
            f"https://pypi.org/pypi/{package}/json",
            headers={"User-Agent": "RepoAUDT-Mac/1.2"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return str((data.get("info") or {}).get("version") or "").strip()
    except Exception:
        return ""


def _probe_cli_scanners(outdated_map: Dict[str, str] | None = None) -> list[Dict[str, Any]]:
    """Probe installed CLI security scanners for the Runtime Diagnostics screen."""
    outdated = outdated_map if isinstance(outdated_map, dict) else {}
    specs = [
        ("gitleaks", "Gitleaks (Secrets + Git History)", ["version"], "brew install gitleaks"),
        ("trufflehog", "TruffleHog (800+ Secret Detectors)", ["--version"], "brew install trufflehog"),
        ("trivy", "Trivy (SCA / IaC / License / SBOM)", ["--version"], "brew install trivy"),
        ("semgrep", "Semgrep (SAST)", ["--version"], "brew install semgrep"),
        ("ruff", "Ruff (Python Lint / SAST)", ["--version"], "brew install ruff"),
        ("zizmor", "zizmor (GitHub Actions Audit)", ["--version"], "brew install zizmor"),
        ("hadolint", "Hadolint (Dockerfile Audit)", ["--version"], "brew install hadolint"),
    ]
    tool_dirs = ("/opt/homebrew/bin", "/usr/local/bin")
    results: list[Dict[str, Any]] = []
    for name, label, ver_args, hint in specs:
        found = next((f"{d}/{name}" for d in tool_dirs if Path(f"{d}/{name}").exists()), "") or (shutil.which(name) or "")
        version = ""
        if found:
            try:
                proc = subprocess.run(
                    [found, *ver_args],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                first_line = ((proc.stdout or proc.stderr or "").strip().splitlines() or [""])[0].strip()
                version = first_line[:60]
            except Exception:
                version = "installed"
        latest = outdated.get(name, "")
        results.append({
            "name": name,
            "label": label,
            "installed": bool(found),
            "path": found,
            "version": version,
            "install_hint": hint,
            "update_available": bool(found and latest),
            "latest_version": latest,
        })
    return results


def upgrade_cli_tool(tool_name: str) -> Dict[str, Any]:
    """Upgrade (or install) an allowlisted CLI tool via Homebrew."""
    clean = str(tool_name or "").strip().lower()
    if clean not in BREW_UPGRADABLE_TOOLS:
        raise ValueError(f"Unsupported tool: {tool_name}")
    brew_bin = _find_brew()
    if not brew_bin:
        raise RuntimeError("Homebrew (brew) が見つかりません。")
    tool_dirs = ("/opt/homebrew/bin", "/usr/local/bin")
    already_installed = bool(
        next((f"{d}/{clean}" for d in tool_dirs if Path(f"{d}/{clean}").exists()), "")
        or shutil.which(clean)
    )
    action = "upgrade" if already_installed else "install"
    env = dict(os.environ)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"
    proc = subprocess.run(
        [brew_bin, action, clean],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        check=False,
    )
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
    if proc.returncode != 0:
        raise RuntimeError(f"brew {action} {clean} に失敗しました: {output[:500]}")
    return {
        "ok": True,
        "tool": clean,
        "action": action,
        "log": output[-1500:] if output else f"brew {action} {clean} completed.",
        "diagnostics": get_runtime_diagnostics(),
    }


def get_runtime_diagnostics() -> Dict[str, Any]:
    """Return runtime environment diagnostics for the System / Update view."""
    copilot_status = copilot_bridge.get_copilot_runtime_status()
    gemini_cli_status = gemini_cli_bridge.get_gemini_cli_runtime_status()
    gh_bin = shutil.which("gh") or ""
    outdated = _probe_brew_outdated()
    gh_latest = outdated.get("gh", "")
    copilot_cur = str(copilot_status.get("sdk_version") or "").strip()
    copilot_latest = _probe_pypi_latest("github-copilot-sdk") if copilot_status.get("sdk_installed") else ""
    copilot_update_available = bool(copilot_cur and copilot_latest and copilot_cur != copilot_latest)
    repo_info: Dict[str, Any] = {"ok": False, "repo_dir": "", "local_commit": "", "dirty": False}
    try:
        repo_dir = find_repo_dir()
        repo_info = {
            "ok": True,
            "repo_dir": str(repo_dir),
            "local_commit": _git(repo_dir, "rev-parse", "--short", "HEAD").stdout.strip(),
            "dirty": bool(_git(repo_dir, "status", "--porcelain").stdout.strip()),
        }
    except Exception as exc:
        repo_info["error"] = str(exc)

    return {
        "ok": True,
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "gh_path": gh_bin,
        "gh_authenticated": copilot_status.get("gh_authenticated", False),
        "gh_update_available": bool(gh_bin and gh_latest),
        "gh_latest_version": gh_latest,
        "copilot_sdk_installed": copilot_status.get("sdk_installed", False),
        "copilot_sdk_version": copilot_cur,
        "copilot_sdk_update_available": copilot_update_available,
        "copilot_sdk_latest_version": copilot_latest,
        "gemini_cli_installed": gemini_cli_status.get("installed", False),
        "gemini_cli_version": gemini_cli_status.get("version", ""),
        "gemini_cli_path": gemini_cli_status.get("path", ""),
        "gemini_cli_authenticated": gemini_cli_status.get("authenticated", False),
        "repo": repo_info,
        "scanners": _probe_cli_scanners(outdated),
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
