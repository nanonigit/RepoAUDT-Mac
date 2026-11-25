"""Antigravity CLI (`agy`) / Gemini CLI bridge for RepoAUDT Mac.

Prefers Google's official Antigravity CLI (`agy`, installed via
`brew install --cask antigravity-cli`) in read-only headless print mode
(`agy --output-format json --mode plan --print <prompt>`), with fallback to
legacy `gemini` CLI if `agy` is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def find_cli_binary() -> Tuple[str, str]:
    """Locate `agy` (preferred) or legacy `gemini`. Returns (path, kind)."""
    agy_candidates = [
        "/opt/homebrew/bin/agy",
        "/usr/local/bin/agy",
    ]
    for path in agy_candidates:
        if Path(path).exists():
            return path, "agy"
    agy_which = shutil.which("agy") or ""
    if agy_which:
        return agy_which, "agy"

    gemini_candidates = [
        "/opt/homebrew/bin/gemini",
        "/usr/local/bin/gemini",
        str(Path.home() / ".npm-global" / "bin" / "gemini"),
        str(Path.home() / ".volta" / "bin" / "gemini"),
    ]
    for path in gemini_candidates:
        if Path(path).exists():
            return path, "gemini"
    gem_which = shutil.which("gemini") or ""
    if gem_which:
        return gem_which, "gemini"
    return "", ""


def find_gemini_cli() -> str:
    """Return path to `agy` (preferred) or `gemini`."""
    path, _ = find_cli_binary()
    return path


def is_gemini_cli_authenticated(kind: str = "") -> Tuple[bool, str]:
    """Check whether Antigravity CLI (`agy`) or Gemini CLI has local credentials."""
    if not kind:
        _, kind = find_cli_binary()
    if kind == "agy":
        agy_dir = Path.home() / ".gemini" / "antigravity"
        if agy_dir.is_dir():
            return True, "Antigravity Google Account"
        if (os.environ.get("GEMINI_API_KEY") or "").strip():
            return True, "env:GEMINI_API_KEY"
        return False, ""

    if (os.environ.get("GEMINI_API_KEY") or "").strip():
        return True, "env:GEMINI_API_KEY"
    gemini_dir = Path.home() / ".gemini"
    for fname, label in (
        ("oauth_creds.json", "Google OAuth"),
        ("google_accounts.json", "Google Account"),
    ):
        fpath = gemini_dir / fname
        if fpath.is_file() and fpath.stat().st_size > 2:
            return True, label
    return False, ""


def get_gemini_cli_version(binary: Optional[str] = None) -> str:
    """Return installed CLI version string, or empty string."""
    bin_path = binary or find_gemini_cli()
    if not bin_path:
        return ""
    try:
        proc = subprocess.run(
            [bin_path, "--version"],
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
    binary, kind = find_cli_binary()
    version = get_gemini_cli_version(binary) if binary else ""
    authed, auth_method = is_gemini_cli_authenticated(kind)
    return {
        "ok": True,
        "installed": bool(binary),
        "cli_kind": kind,
        "cli_label": "Antigravity CLI (agy)" if kind == "agy" else ("Gemini CLI (gemini)" if kind == "gemini" else "Antigravity CLI (agy)"),
        "path": binary,
        "version": version,
        "authenticated": authed,
        "auth_method": auth_method,
    }


def is_gemini_cli_ready() -> bool:
    """True when `agy` or `gemini` is installed."""
    return bool(find_gemini_cli())


def install_or_update_gemini_cli() -> Dict[str, Any]:
    """Install or update Google Antigravity CLI (`antigravity-cli`) via Homebrew."""
    brew_bin = next(
        (p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if Path(p).exists()),
        "",
    ) or (shutil.which("brew") or "")
    if not brew_bin:
        raise RuntimeError("Homebrew (`brew`) が見つかりません。Homebrew を導入してから再試行してください。")

    binary, kind = find_cli_binary()
    action = "upgrade" if kind == "agy" and binary else "install"
    env = dict(os.environ)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"
    proc = subprocess.run(
        [brew_bin, action, "--cask", "antigravity-cli"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"brew {action} --cask antigravity-cli failed").strip()
        if "already installed" not in err.lower() and "already up-to-date" not in err.lower():
            raise RuntimeError(f"Antigravity CLI の{action}に失敗しました: {err[:400]}")

    status = get_gemini_cli_runtime_status()
    return {
        **status,
        "message": f"Antigravity CLI ({status.get('version') or 'ready'}) ready.",
    }


def _extract_response_text(stdout: str) -> str:
    """Extract assistant text from JSON output (`agy` or `gemini`) or plain text."""
    raw = (stdout or "").strip()
    if not raw:
        return ""
    candidates = [raw]
    if "{" in raw:
        candidates.append(raw[raw.find("{"):])
    for line in reversed(raw.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            candidates.insert(0, stripped)
    for candidate in candidates:
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
                    raise RuntimeError(f"CLI error: {msg}")
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
    """Invoke `agy` (preferred) or `gemini` in read-only headless mode and return response."""
    binary, kind = find_cli_binary()
    if not binary:
        raise RuntimeError(
            "Antigravity CLI (`agy`) がインストールされていません。「AI 接続」からインストールしてください。"
        )

    combined_parts = []
    if system_prompt and system_prompt.strip():
        combined_parts.append(f"[System Instructions]\n{system_prompt.strip()}")
    if user_prompt and user_prompt.strip():
        combined_parts.append(f"[User Request]\n{user_prompt.strip()}")
    full_prompt = "\n\n".join(combined_parts) or "Hello"

    clean_model = (model or "").strip()
    env = dict(os.environ)
    clean_key = (api_key or "").strip()
    if clean_key:
        env["GEMINI_API_KEY"] = clean_key

    if kind == "agy":
        cmd = [
            binary,
            "--output-format", "json",
            "--mode", "plan",
            "--print-timeout", f"{timeout}s",
        ]
        if clean_model and clean_model.lower() != "auto":
            cmd.extend(["--model", clean_model])
        cmd.append(f"--print={full_prompt}")
        stdin_input = None
    else:
        cmd = [binary, "-p", "", "-o", "json", "--approval-mode", "plan"]
        if clean_model and clean_model.lower() != "auto":
            cmd.extend(["-m", clean_model])
        stdin_input = full_prompt

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout + 15,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Antigravity CLI がタイムアウトしました ({timeout}s)。") from exc

    if proc.returncode != 0:
        err_blob = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
        low = err_blob.lower()
        if any(tok in low for tok in ("login", "auth", "credentials", "unauthenticated", "oauth", "sign in")):
            raise RuntimeError(
                "Antigravity CLI が未ログインです。「ターミナルで Google ログインを開く」からログインしてください。"
            )
        raise RuntimeError(f"Antigravity CLI 実行エラー (exit {proc.returncode}): {err_blob[:400]}")

    text = _extract_response_text(proc.stdout)
    if not text:
        raise RuntimeError("Antigravity CLI から空の応答が返りました。")
    return text
