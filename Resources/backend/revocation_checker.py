"""Git history persistence check (local read-only) and explicit opt-in provider revocation check."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


_AKIA_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_OPENAI_RE = re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{24,})\b")
_GH_TOKEN_RE = re.compile(r"\b((?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_AWS_SECRET_KEY_JSON_RE = re.compile(
    r"""(?:secretAccessKey|secret_access_key|aws_secret_access_key|Secret\s*access\s*key)["'\s:=,]+([A-Za-z0-9/+=]{40})""",
    re.IGNORECASE,
)


def _normalize_rel_file(raw_file: str) -> str:
    base = str(raw_file or "").split(" (Target:", 1)[0].strip()
    if ":" in base:
        left, right = base.rsplit(":", 1)
        if right.isdigit():
            base = left.strip()
    return base[2:] if base.startswith("./") else base


def check_git_history_persistence(repo_dir: Optional[Path], raw_file: str) -> Dict[str, Any]:
    """Check locally whether a secret file is still in HEAD, removed from HEAD but in Git history, or purged."""
    rel_path = _normalize_rel_file(raw_file)
    if not repo_dir or not repo_dir.exists() or not (repo_dir / ".git").exists() or not rel_path:
        return {"status": "unavailable", "commit_count": 0, "last_commit": ""}

    try:
        in_head_proc = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", f"HEAD:{rel_path}"],
            capture_output=True,
            timeout=5,
        )
        in_head = in_head_proc.returncode == 0
    except Exception:
        in_head = (repo_dir / rel_path).exists()

    try:
        log_proc = subprocess.run(
            ["git", "-C", str(repo_dir), "log", "--all", "--format=%h", "-n", "50", "--", rel_path],
            capture_output=True,
            text=True,
            timeout=8,
        )
        commits = [ln.strip() for ln in (log_proc.stdout or "").splitlines() if ln.strip()]
    except Exception:
        commits = []

    if in_head:
        return {
            "status": "still_in_head",
            "commit_count": len(commits),
            "last_commit": commits[0] if commits else "",
        }
    if commits:
        return {
            "status": "head_removed_in_history",
            "commit_count": len(commits),
            "last_commit": commits[0],
        }
    return {"status": "purged_from_history", "commit_count": 0, "last_commit": ""}


def _read_last_blob_from_git(repo_dir: Path, rel_path: str) -> str:
    """Read the last committed content of rel_path from Git history (in memory only)."""
    log_proc = subprocess.run(
        ["git", "-C", str(repo_dir), "log", "--all", "-n", "1", "--format=%H", "--", rel_path],
        capture_output=True,
        text=True,
        timeout=8,
    )
    sha = (log_proc.stdout or "").strip().splitlines()[0].strip() if (log_proc.stdout or "").strip() else ""
    if not sha:
        return ""
    show_proc = subprocess.run(
        ["git", "-C", str(repo_dir), "show", f"{sha}:{rel_path}"],
        capture_output=True,
        text=True,
        errors="ignore",
        timeout=8,
    )
    return show_proc.stdout or ""


def _extract_aws_pair(blob_text: str) -> Optional[Tuple[str, str]]:
    ak_m = _AKIA_RE.search(blob_text)
    if not ak_m:
        return None
    access_key = ak_m.group(1)
    sk_m = _AWS_SECRET_KEY_JSON_RE.search(blob_text)
    if sk_m:
        return access_key, sk_m.group(1)
    # CSV fallback: line containing AKIA...,<40-char secret>
    for line in blob_text.splitlines():
        if access_key in line:
            parts = [p.strip().strip('"').strip("'") for p in line.split(",")]
            for part in parts:
                if part != access_key and re.fullmatch(r"[A-Za-z0-9/+=]{40}", part):
                    return access_key, part
    return None


def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _check_aws_sts_revocation(access_key: str, secret_key: str) -> Dict[str, Any]:
    """Read-only AWS STS GetCallerIdentity check using SigV4 (pure stdlib)."""
    host = "sts.amazonaws.com"
    region = "us-east-1"
    service = "sts"
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    k_date = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    k_signing = _sigv4_sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    req = urllib.request.Request(
        f"https://{host}/",
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": host,
            "X-Amz-Date": amz_date,
            "Authorization": auth_header,
            "User-Agent": "RepoAUDT-Mac/1.2",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                return {
                    "live_status": "active",
                    "provider": "aws",
                    "message": "⚠️ まだ有効です！AWS STS GetCallerIdentity が成功しました。直ちに AWS IAM で無効化してください。",
                }
    except urllib.error.HTTPError as he:
        err_body = he.read().decode("utf-8", errors="ignore")
        if he.code == 403 and any(
            code in err_body for code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException")
        ):
            return {
                "live_status": "revoked",
                "provider": "aws",
                "message": "✅ 無効化済み（AWS STS がキーを拒否: InvalidClientTokenId）",
            }
        return {
            "live_status": "error",
            "provider": "aws",
            "message": f"AWS STS 確認エラー (HTTP {he.code})",
        }
    except Exception as exc:
        return {"live_status": "error", "provider": "aws", "message": f"AWS STS 通信エラー: {str(exc)[:100]}"}
    return {"live_status": "error", "provider": "aws", "message": "AWS STS の応答を判定できませんでした"}


def _check_openai_revocation(api_key: str) -> Dict[str, Any]:
    req = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {api_key}", "User-Agent": "RepoAUDT-Mac/1.2"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                return {
                    "live_status": "active",
                    "provider": "openai",
                    "message": "⚠️ まだ有効です！OpenAI API が HTTP 200 を返しました。直ちに無効化してください。",
                }
    except urllib.error.HTTPError as he:
        if he.code == 401:
            return {
                "live_status": "revoked",
                "provider": "openai",
                "message": "✅ 無効化済み（OpenAI API が HTTP 401 で拒否）",
            }
        return {"live_status": "error", "provider": "openai", "message": f"OpenAI API 確認エラー (HTTP {he.code})"}
    except Exception as exc:
        return {"live_status": "error", "provider": "openai", "message": f"OpenAI 通信エラー: {str(exc)[:100]}"}
    return {"live_status": "error", "provider": "openai", "message": "OpenAI の応答を判定できませんでした"}


def _check_github_token_revocation(token: str) -> Dict[str, Any]:
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"Authorization": f"token {token}", "User-Agent": "RepoAUDT-Mac/1.2"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                return {
                    "live_status": "active",
                    "provider": "github",
                    "message": "⚠️ まだ有効です！GitHub API が HTTP 200 を返しました。直ちに無効化してください。",
                }
    except urllib.error.HTTPError as he:
        if he.code == 401:
            return {
                "live_status": "revoked",
                "provider": "github",
                "message": "✅ 無効化済み（GitHub API が HTTP 401 で拒否）",
            }
        return {"live_status": "error", "provider": "github", "message": f"GitHub API 確認エラー (HTTP {he.code})"}
    except Exception as exc:
        return {"live_status": "error", "provider": "github", "message": f"GitHub 通信エラー: {str(exc)[:100]}"}
    return {"live_status": "error", "provider": "github", "message": "GitHub の応答を判定できませんでした"}


def check_live_revocation(repo_dir: Optional[Path], raw_file: str, title: str = "") -> Dict[str, Any]:
    """Explicit opt-in read-only revocation check for AWS / OpenAI / GitHub keys in Git history."""
    rel_path = _normalize_rel_file(raw_file)
    history = check_git_history_persistence(repo_dir, raw_file)
    if not repo_dir or not repo_dir.exists() or not (repo_dir / ".git").exists() or not rel_path:
        return {
            "history": history,
            "live_status": "unavailable",
            "provider": "",
            "message": "ローカルリポジトリが見つからないため自動確認できませんでした。",
        }
    if history["status"] == "purged_from_history":
        return {
            "history": history,
            "live_status": "purged",
            "provider": "",
            "message": "Git 履歴からも完全に削除されているため、過去キーの照合対象がありません。",
        }

    blob_text = _read_last_blob_from_git(repo_dir, rel_path)
    if not blob_text:
        return {
            "history": history,
            "live_status": "unavailable",
            "provider": "",
            "message": "過去コミットから対象ファイルを取得できませんでした。",
        }

    aws_pair = _extract_aws_pair(blob_text)
    if aws_pair:
        res = _check_aws_sts_revocation(aws_pair[0], aws_pair[1])
        return {"history": history, **res}

    openai_m = _OPENAI_RE.search(blob_text)
    if openai_m:
        res = _check_openai_revocation(openai_m.group(1))
        return {"history": history, **res}

    gh_m = _GH_TOKEN_RE.search(blob_text)
    if gh_m:
        res = _check_github_token_revocation(gh_m.group(1))
        return {"history": history, **res}

    return {
        "history": history,
        "live_status": "unsupported",
        "provider": "",
        "message": "この形式（ペアのないキー・秘密鍵・汎用パスワード等）は外部 API での自動失効確認に非対応です。プロバイダ管理画面で手動確認してください。",
    }
