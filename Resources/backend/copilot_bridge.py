"""GitHub Copilot SDK & Coding Agent bridge for RepoAUDT Mac."""

from __future__ import annotations

import asyncio
import concurrent.futures
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional

_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/(?!\.{1,2}$)[A-Za-z0-9_.-]+$")
_GITHUB_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+?)(?:\.git|/)?$")


def is_copilot_sdk_installed() -> bool:
    """Return True if the official github-copilot-sdk package is importable."""
    try:
        import copilot  # noqa: F401
        return True
    except ImportError:
        return False


def resolve_github_token(explicit_token: str = "") -> str:
    """Resolve a GitHub token from explicit input, environment variables, or gh CLI."""
    token = (explicit_token or "").strip()
    if token:
        return token
    for env_key in ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            return val
    gh_bin = shutil.which("gh")
    if gh_bin:
        try:
            proc = subprocess.run(
                [gh_bin, "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
    return ""


def is_copilot_ready(explicit_token: str = "") -> bool:
    """Return True if github-copilot-sdk is installed and a GitHub credential is available."""
    return is_copilot_sdk_installed() and bool(resolve_github_token(explicit_token))


def get_copilot_sdk_version() -> str:
    """Return the installed github-copilot-sdk version string, or empty string if missing."""
    try:
        return importlib.metadata.version("github-copilot-sdk")
    except importlib.metadata.PackageNotFoundError:
        return ""
    except Exception:
        return ""


def get_copilot_runtime_status(explicit_token: str = "") -> Dict[str, Any]:
    """Return installation and credential status for github-copilot-sdk under sys.executable."""
    installed = is_copilot_sdk_installed()
    version = get_copilot_sdk_version() if installed else ""
    return {
        "ok": True,
        "sdk_installed": installed,
        "sdk_version": version,
        "python_executable": sys.executable,
        "gh_authenticated": bool(resolve_github_token(explicit_token)),
    }


def _run_pip_install(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pip", "install", *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def install_or_update_copilot_sdk() -> Dict[str, Any]:
    """Install or upgrade github-copilot-sdk and download its runtime under sys.executable."""
    previous_version = get_copilot_sdk_version()

    proc = _run_pip_install(["--upgrade", "github-copilot-sdk"])
    if proc.returncode != 0:
        combined = f"{proc.stdout}\n{proc.stderr}".lower()
        if "externally-managed-environment" in combined:
            proc = _run_pip_install(["--upgrade", "--break-system-packages", "github-copilot-sdk"])
        elif "permission denied" in combined:
            proc = _run_pip_install(["--upgrade", "--user", "github-copilot-sdk"])

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "pip install failed").strip()
        raise RuntimeError(f"github-copilot-sdk のインストールに失敗しました: {err}")

    runtime_proc = subprocess.run(
        [sys.executable, "-m", "copilot", "download-runtime"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if runtime_proc.returncode != 0:
        err = (runtime_proc.stderr or runtime_proc.stdout or "download-runtime failed").strip()
        raise RuntimeError(f"Copilot ランタイムのダウンロードに失敗しました: {err}")

    new_version = get_copilot_sdk_version()
    return {
        "ok": True,
        "sdk_installed": is_copilot_sdk_installed(),
        "previous_version": previous_version,
        "sdk_version": new_version,
        "updated": bool(previous_version and new_version and previous_version != new_version),
        "python_executable": sys.executable,
    }


def _extract_event_text(event: Any) -> str:
    """Extract text content from a Copilot SDK SessionEvent."""
    if event is None:
        return ""
    data = getattr(event, "data", None)
    if data is not None:
        for attr in ("content", "message", "text"):
            val = getattr(data, attr, None)
            if isinstance(val, str) and val.strip():
                return val.strip()
    if isinstance(event, dict):
        d = event.get("data") or event
        if isinstance(d, dict):
            for key in ("content", "message", "text"):
                val = d.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return ""


async def _run_copilot_session(
    model: str,
    system_prompt: str,
    user_prompt: str,
    github_token: str = "",
    working_directory: Optional[str] = None,
    timeout: float = 90.0,
) -> str:
    from copilot import CopilotClient  # type: ignore

    token = resolve_github_token(github_token)
    client_kwargs: Dict[str, Any] = {"log_level": "warning"}
    if token:
        client_kwargs["github_token"] = token
    else:
        client_kwargs["use_logged_in_user"] = True
    if working_directory:
        client_kwargs["working_directory"] = working_directory

    client = CopilotClient(**client_kwargs)
    await client.start()
    try:
        clean_model = (model or "").strip()
        session_kwargs: Dict[str, Any] = {}
        if clean_model and clean_model.lower() != "auto":
            session_kwargs["model"] = clean_model
        if system_prompt:
            session_kwargs["system_message"] = {
                "mode": "append",
                "content": system_prompt,
            }
        if token:
            session_kwargs["github_token"] = token
        if working_directory:
            session_kwargs["working_directory"] = working_directory

        session = await client.create_session(**session_kwargs)
        try:
            event = await session.send_and_wait(user_prompt, timeout=timeout)
            text = _extract_event_text(event)
            if not text:
                raise RuntimeError("GitHub Copilot returned an empty response.")
            return text
        finally:
            try:
                await session.destroy()
            except Exception:
                pass
    finally:
        try:
            await client.stop()
        except Exception:
            pass


def call_copilot_sync(
    model: str,
    system_prompt: str,
    user_prompt: str,
    github_token: str = "",
    working_directory: Optional[str] = None,
    timeout: float = 90.0,
) -> str:
    """Synchronously invoke GitHub Copilot SDK from RepoAUDT's threaded HTTP server."""
    if not is_copilot_sdk_installed():
        raise RuntimeError(
            "github-copilot-sdk がインストールされていません。`python3 -m pip install github-copilot-sdk` を実行してください。"
        )

    coro = _run_copilot_session(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        github_token=github_token,
        working_directory=working_directory,
        timeout=timeout,
    )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # Run in a dedicated worker thread if the caller already has a running event loop.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=timeout + 15)


def extract_owner_repo(github_url: str) -> str:
    """Extract 'owner/repo' from a GitHub HTTPS URL or 'owner/repo' string."""
    raw = (github_url or "").strip()
    match = _GITHUB_URL_RE.match(raw)
    slug = match.group(1) if match else raw
    if not _OWNER_REPO_RE.match(slug):
        raise ValueError("Invalid GitHub repository reference.")
    return slug


def create_copilot_issue(
    github_url: str,
    title: str,
    body: str,
    assign_copilot: bool = True,
) -> Dict[str, Any]:
    """Create a GitHub Issue and optionally assign it to GitHub Copilot Coding Agent."""
    gh_bin = shutil.which("gh")
    if not gh_bin:
        raise RuntimeError("GitHub CLI (`gh`) is not installed.")

    owner_repo = extract_owner_repo(github_url)
    clean_title = (title or "").strip()[:240]
    clean_body = (body or "").strip()[:16000]
    if not clean_title:
        raise ValueError("Issue title is required.")

    base_cmd = [
        gh_bin,
        "issue",
        "create",
        "--repo",
        owner_repo,
        "--title",
        clean_title,
        "--body",
        clean_body,
    ]

    copilot_assigned = False
    warning = ""

    if assign_copilot:
        proc = subprocess.run(
            [*base_cmd, "--assignee", "@copilot"],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        if proc.returncode == 0:
            copilot_assigned = True
        else:
            warning = (proc.stderr or proc.stdout or "").strip()
            proc = subprocess.run(
                base_cmd,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
    else:
        proc = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "Failed to create GitHub issue.").strip()
        raise RuntimeError(err)

    issue_url = proc.stdout.strip().splitlines()[-1].strip() if proc.stdout.strip() else ""
    number_match = re.search(r"/issues/(\d+)$", issue_url)
    issue_number = int(number_match.group(1)) if number_match else None

    result: Dict[str, Any] = {
        "ok": True,
        "repository": owner_repo,
        "issue_url": issue_url,
        "issue_number": issue_number,
        "copilot_assigned": copilot_assigned,
    }
    if warning and not copilot_assigned:
        result["warning"] = warning
    return result
