"""Gemini CLI (@google/gemini-cli) bridge for RepoAUDT Mac.

Allows using Google Gemini via the locally installed `gemini` CLI in headless
read-only mode (`-p "" -o json --approval-mode plan`) using Google account login
(no API key required) or an optional GEMINI_API_KEY.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


def find_gemini_cli() -> str:
    """Locate the installed `gemini` CLI binary."""
    candidates = [
        "/opt/homebrew/bin/gemini",
        "/usr/local/bin/gemini",
        str(Path.home() / ".npm-global" / "bin" / "gemini"),
        str(Path.home() / ".volta" / "bin" / "gemini"),
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return shutil.which("gemini") or ""


def is_gemini_cli_authenticated() -> tuple[bool, str]:
    """Check whether Gemini CLI has local Google OAuth credentials or GEMINI_API_KEY."""
    if (os.environ.get("GEMINI_API_KEY") or "").strip():
        return True, "env:GEMINI_API_KEY"
    gemini_dir = Path.home() / ".gemini"
    for fname, label in (
        ("oauth_creds.json", "Google OAuth"),
        ("google_accounts.json", "Google Account"),
        ("settings.json", "Gemini CLI settings"),
    ):
        fpath = gemini_dir / fname
        if fpath.is_file() and fpath.stat().st_size > 2:
            if fname == "settings.json":
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                    auth_type = str(
                        ((data.get("security") or {}).get("auth") or {}).get("selectedType")
                        or data.get("selectedAuthType")
                        or ""
                    ).strip()
                    if auth_type:
                        return True, auth_type
                except Exception:
                    continue
            else:
                return True, label
    return False, ""


def get_gemini_cli_version(gemini_bin: Optional[str] = None) -> str:
    """Return installed Gemini CLI version string, or empty string."""
    binary = gemini_bin or find_gemini_cli()
    if not binary:
        return ""
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        return out[0].strip()[:40] if out else ""
    except Exception:
        return ""


def get_gemini_cli_runtime_status() -> Dict[str, Any]:
    """Return runtime status for AI Connections & System Diagnostics views."""
    binary = find_gemini_cli()
    version = get_gemini_cli_version(binary) if binary else ""
    authed, auth_method = is_gemini_cli_authenticated()
    return {
        "ok": True,
        "installed": bool(binary),
        "path": binary,
        "version": version,
        "authenticated": authed,
        "auth_method": auth_method,
    }


def is_gemini_cli_ready() -> bool:
    """True when the `gemini` binary is installed."""
    return bool(find_gemini_cli())


def install_or_update_gemini_cli() -> Dict[str, Any]:
    """Install or update `@google/gemini-cli` globally via npm."""
    npm_bin = next(
        (p for p in ("/opt/homebrew/bin/npm", "/usr/local/bin/npm") if Path(p).exists()),
        "",
    ) or (shutil.which("npm") or "")
    if not npm_bin:
        raise RuntimeError("npm が見つかりません。Node.js をインストールしてから再試行してください。")

    proc = subprocess.run(
        [npm_bin, "install", "-g", "@google/gemini-cli@latest"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "npm install -g @google/gemini-cli failed").strip()
        raise RuntimeError(f"Gemini CLI のインストール/更新に失敗しました: {err[:400]}")

    status = get_gemini_cli_runtime_status()
    return {
        **status,
        "message": f"@google/gemini-cli {status.get('version') or ''} ready.",
    }


def _extract_response_text(stdout: str) -> str:
    """Extract assistant text from `gemini -o json` output or plain text."""
    raw = (stdout or "").strip()
    if not raw:
        return ""
    # Gemini CLI may emit warning lines before/after the JSON payload
    for candidate in (raw, raw[raw.find("{"):] if "{" in raw else ""):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                for key in ("response", "text", "output", "content"):
                    val = parsed.get(key)
                    if isinstance(val, str) and val.strip():
                        return val.strip()
                if isinstance(parsed.get("error"), dict):
                    msg = str(parsed["error"].get("message") or parsed["error"])
                    raise RuntimeError(f"Gemini CLI error: {msg}")
        except json.JSONDecodeError:
            continue
    return raw


def call_gemini_cli_sync(
    *,
    model: str = "",
    system_prompt: str = "",
    user_prompt: str = "",
    api_key: str = "",
    timeout: int = 120,
) -> str:
    """Invoke `gemini` CLI in headless read-only mode and return the text response."""
    binary = find_gemini_cli()
    if not binary:
        raise RuntimeError(
            "Gemini CLI (`gemini`) がインストールされていません。「AI 接続」または「実行環境・更新」からインストールしてください。"
        )

    cmd = [binary, "-p", "", "-o", "json", "--approval-mode", "plan"]
    clean_model = (model or "").strip()
    if clean_model and clean_model.lower() != "auto":
        cmd.extend(["-m", clean_model])

    combined_parts = []
    if system_prompt and system_prompt.strip():
        combined_parts.append(f"[System Instructions]\n{system_prompt.strip()}")
    if user_prompt and user_prompt.strip():
        combined_parts.append(f"[User Request]\n{user_prompt.strip()}")
    stdin_payload = "\n\n".join(combined_parts) or "Hello"

    env = dict(os.environ)
    clean_key = (api_key or "").strip()
    if clean_key:
        env["GEMINI_API_KEY"] = clean_key

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Gemini CLI がタイムアウトしました ({timeout}s)。") from exc

    if proc.returncode != 0:
        err_blob = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
        low = err_blob.lower()
        if any(tok in low for tok in ("login", "auth", "credentials", "unauthenticated", "api key", "oauth")):
            raise RuntimeError(
                "Gemini CLI が未ログインです。ターミナルで `gemini` を 1 回実行して Google アカウントでログインしてから再試行してください。"
            )
        raise RuntimeError(f"Gemini CLI 実行エラー (exit {proc.returncode}): {err_blob[:400]}")

    text = _extract_response_text(proc.stdout)
    if not text:
        raise RuntimeError("Gemini CLI から空の応答が返りました。")
    return text
