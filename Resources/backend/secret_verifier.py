"""Opt-in, read-only secret liveness verifier (never invoked during automatic scans)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_TIMEOUT_SEC = 10

_OPENAI_RE = re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b")
_GITHUB_RE = re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_SLACK_RE = re.compile(r"\b(xox[bp]-[A-Za-z0-9-]{10,})\b")
_AWS_AKIA_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_AWS_SECRET_RE = re.compile(
    r"""(?i)(?:aws_secret_access_key|secret_access_key|aws_secret|secret_key|secretkey)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
)


def mask_secret(secret: str) -> str:
    """Return a safely masked identifier for UI/logs; never expose the full secret."""
    s = str(secret or "").strip()
    if len(s) <= 8:
        return "****"
    if s.startswith(("sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-")):
        return f"{s[:7]}****...{s[-4:]}"
    if s.startswith("AKIA"):
        return f"{s[:6]}****...{s[-4:]}"
    return f"{s[:4]}****...{s[-4:]}"


def _scrub_secret(text: str, *secrets: str) -> str:
    cleaned = str(text or "")
    for sec in secrets:
        if sec and len(sec) >= 6:
            cleaned = cleaned.replace(sec, "[REDACTED]")
    return cleaned


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SEC) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200)), body
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return int(exc.code), body


def _verify_openai(api_key: str) -> Dict[str, Any]:
    try:
        code, _ = _http_request(
            "https://api.openai.com/v1/models",
            method="GET",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        if code == 200:
            return {"status": "active", "message": "OpenAI API key is active (HTTP 200)."}
        if code == 401:
            return {"status": "revoked", "message": "OpenAI API key is revoked or invalid (HTTP 401)."}
        return {"status": "unknown", "message": f"OpenAI verification inconclusive (HTTP {code})."}
    except Exception as exc:
        return {"status": "unknown", "message": _scrub_secret(f"OpenAI check failed: {type(exc).__name__}", api_key)}


def _verify_github(token: str) -> Dict[str, Any]:
    try:
        code, _ = _http_request(
            "https://api.github.com/user",
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "RepoAUDT-Mac",
            },
        )
        if code == 200:
            return {"status": "active", "message": "GitHub token is active (HTTP 200)."}
        if code == 401:
            return {"status": "revoked", "message": "GitHub token is revoked or invalid (HTTP 401)."}
        return {"status": "unknown", "message": f"GitHub verification inconclusive (HTTP {code})."}
    except Exception as exc:
        return {"status": "unknown", "message": _scrub_secret(f"GitHub check failed: {type(exc).__name__}", token)}


def _verify_slack(token: str) -> Dict[str, Any]:
    try:
        code, body = _http_request(
            "https://slack.com/api/auth.test",
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=b"",
        )
        parsed = json.loads(body) if body else {}
        if parsed.get("ok") is True:
            return {"status": "active", "message": "Slack token is active (auth.test ok: true)."}
        err = str(parsed.get("error") or "")
        if err in {"invalid_auth", "token_revoked", "account_inactive", "not_authed"} or code == 401:
            return {"status": "revoked", "message": f"Slack token is revoked ({err or f'HTTP {code}'})."}
        return {"status": "unknown", "message": f"Slack verification inconclusive ({err or f'HTTP {code}'})."}
    except Exception as exc:
        return {"status": "unknown", "message": _scrub_secret(f"Slack check failed: {type(exc).__name__}", token)}


def _sign_v4(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _aws_sigv4_headers(access_key: str, secret_key: str, payload: bytes) -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    region = "us-east-1"
    service = "sts"
    host = "sts.amazonaws.com"
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    k_date = _sign_v4(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign_v4(k_date, region)
    k_service = _sign_v4(k_region, service)
    k_signing = _sign_v4(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": auth_header,
    }


def _verify_aws_sts(access_key: str, secret_key: str) -> Dict[str, Any]:
    payload = b"Action=GetCallerIdentity&Version=2011-06-15"
    try:
        headers = _aws_sigv4_headers(access_key, secret_key, payload)
        code, body = _http_request(
            "https://sts.amazonaws.com/",
            method="POST",
            headers=headers,
            data=payload,
        )
        if code == 200:
            m_acct = re.search(r"<Account>(\d{12})</Account>", body or "")
            acct = m_acct.group(1) if m_acct else None
            msg = f"AWS IAM key is active (Account: {acct})." if acct else "AWS IAM key is active (HTTP 200)."
            return {"status": "active", "account_id": acct, "message": msg}
        if any(tok in (body or "") for tok in ("InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken")) or code == 401:
            return {"status": "revoked", "message": "AWS IAM key is revoked or invalid (STS rejected credentials)."}
        return {"status": "unknown", "message": f"AWS STS verification inconclusive (HTTP {code})."}
    except Exception as exc:
        return {
            "status": "unknown",
            "message": _scrub_secret(f"AWS STS check failed: {type(exc).__name__}", access_key, secret_key),
        }


def _extract_secret_target(content: str, line_hint: Optional[int] = None) -> Tuple[str, str, str]:
    """Return (provider, primary_secret, secondary_secret) from file content."""
    lines = content.splitlines()
    search_order: list[str] = []
    if line_hint and 1 <= line_hint <= len(lines):
        search_order.append(lines[line_hint - 1])
    search_order.append(content)

    for chunk in search_order:
        m_oai = _OPENAI_RE.search(chunk)
        if m_oai:
            return ("openai", m_oai.group(1), "")
        m_gh = _GITHUB_RE.search(chunk)
        if m_gh:
            return ("github", m_gh.group(1), "")
        m_slk = _SLACK_RE.search(chunk)
        if m_slk:
            return ("slack", m_slk.group(1), "")
        m_aws = _AWS_AKIA_RE.search(chunk)
        if m_aws:
            m_sec = _AWS_SECRET_RE.search(content)
            return ("aws", m_aws.group(1), m_sec.group(1) if m_sec else "")

    return ("unknown", "", "")


def verify_secret_in_file(
    repo_dir: Path,
    rel_path: str,
    line_hint: Optional[int] = None,
) -> Dict[str, Any]:
    """Read target file on disk, verify secret liveness in memory, and return masked status only."""
    checked_at = _now_iso()
    try:
        root = Path(repo_dir).resolve()
        clean_rel = str(rel_path or "").split(" (", 1)[0].split(":", 1)[0].strip()
        if not clean_rel:
            return {
                "status": "unknown",
                "provider": "unknown",
                "masked_id": "****",
                "checked_at": checked_at,
                "message": "Target file path is missing.",
            }
        target = (root / clean_rel).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return {
                "status": "unknown",
                "provider": "unknown",
                "masked_id": "****",
                "checked_at": checked_at,
                "message": "Target file not found in local repository workspace.",
            }
        content = target.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return {
            "status": "unknown",
            "provider": "unknown",
            "masked_id": "****",
            "checked_at": checked_at,
            "message": f"Failed to read target file: {type(exc).__name__}",
        }

    provider, primary, secondary = _extract_secret_target(content, line_hint=line_hint)
    if provider == "unknown" or not primary:
        return {
            "status": "unknown",
            "provider": "unknown",
            "masked_id": "****",
            "checked_at": checked_at,
            "message": "No supported verifiable key (OpenAI / GitHub / Slack / AWS) found in file.",
        }

    masked = mask_secret(primary)
    if provider == "openai":
        res = _verify_openai(primary)
    elif provider == "github":
        res = _verify_github(primary)
    elif provider == "slack":
        res = _verify_slack(primary)
    elif provider == "aws":
        if not secondary:
            res = {
                "status": "unknown",
                "message": "AWS Access Key found, but no paired AWS Secret Access Key found in the same file.",
            }
        else:
            res = _verify_aws_sts(primary, secondary)
    else:
        res = {"status": "unknown", "message": "Unsupported secret provider."}

    out: Dict[str, Any] = {
        "status": res.get("status", "unknown"),
        "provider": provider,
        "masked_id": masked,
        "checked_at": checked_at,
        "message": _scrub_secret(str(res.get("message") or ""), primary, secondary),
    }
    if res.get("account_id"):
        out["account_id"] = str(res["account_id"])
    return out
