"""Priority triage (P0-P3), CISA KEV lookup, reachability annotation, output validation gate, and fingerprinting."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL_SECONDS = 24 * 3600
KEV_TIMEOUT_SECONDS = 2.5

TIER_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}

_P1_KEYWORDS = (
    "remote code execution",
    "rce",
    "authentication bypass",
    "middleware bypass",
    "authorization bypass",
    "ssrf",
    "server-side request forgery",
    "sql injection",
    "arbitrary file read",
    "prototype pollution",
    "improper categorization in ispublic",
)
_P3_LOW_IMPACT_PACKAGES = {"postcss", "source-map-js", "nanoid", "brace-expansion", "picomatch"}
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_PRERELEASE_VER_RE = re.compile(r"-(?:rc|alpha|beta|dev|canary|preview|next|pre)(?:[.\-\d]|$)", re.IGNORECASE)

_KEV_MEM_CACHE: Dict[str, Any] = {"ts": 0.0, "cves": set()}


def _kev_cache_path() -> Path:
    override = os.environ.get("REPOAUDT_KEV_CACHE_FILE", "").strip()
    if override:
        return Path(override)
    return Path(tempfile.gettempdir()) / "repoaudt_cisa_kev.json"


def fetch_cisa_kev_set(
    *,
    fetcher: Optional[Callable[[str, float], Any]] = None,
    use_cache: bool = True,
) -> Set[str]:
    """Return a set of CVE IDs in the CISA KEV catalog (24h cached, offline-safe)."""
    now = time.time()
    if use_cache and _KEV_MEM_CACHE["cves"] and now - float(_KEV_MEM_CACHE["ts"]) < KEV_CACHE_TTL_SECONDS:
        return set(_KEV_MEM_CACHE["cves"])

    cache_path = _kev_cache_path()
    stale_cves: Set[str] = set()
    if use_cache and cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("cves"), list):
                stale_cves = {str(c).upper() for c in payload["cves"]}
                if now - float(payload.get("ts", 0)) < KEV_CACHE_TTL_SECONDS:
                    _KEV_MEM_CACHE["ts"] = float(payload["ts"])
                    _KEV_MEM_CACHE["cves"] = stale_cves
                    return set(stale_cves)
        except Exception:
            pass

    def _default_fetch(url: str, timeout: float) -> Any:
        req = urllib.request.Request(url, headers={"User-Agent": "RepoAUDT-Mac/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    fetch_fn = fetcher or _default_fetch
    try:
        data = fetch_fn(CISA_KEV_URL, KEV_TIMEOUT_SECONDS)
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if isinstance(vulns, list):
            cves = {
                str(v.get("cveID") or "").strip().upper()
                for v in vulns
                if isinstance(v, dict) and v.get("cveID")
            }
            if use_cache:
                _KEV_MEM_CACHE["ts"] = now
                _KEV_MEM_CACHE["cves"] = cves
                try:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps({"ts": now, "cves": sorted(cves)}), encoding="utf-8")
                except Exception:
                    pass
            return cves
    except Exception:
        pass

    return stale_cves


def _extract_cves(item: Dict[str, Any]) -> List[str]:
    blob = " ".join(
        str(item.get(k) or "") for k in ("cve", "title", "desc", "summary")
    )
    return sorted({m.group(1).upper() for m in _CVE_RE.finditer(blob)})


def detect_linux_container_repo(repo_dir: Optional[Path]) -> bool:
    """Return True if the repository targets Linux containers (Dockerfile / ECS)."""
    if not repo_dir or not repo_dir.exists():
        return False
    for df in repo_dir.rglob("Dockerfile*"):
        if not df.is_file():
            continue
        try:
            text = df.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if "from " in text and "mcr.microsoft.com/windows" not in text and "nanoserver" not in text:
            return True
    return False


def annotate_windows_cve_reachability(item: Dict[str, Any], is_linux_repo: bool) -> None:
    if not is_linux_repo:
        return
    blob = f"{item.get('title', '')} {item.get('desc', '')}".lower()
    if any(tok in blob for tok in ("windows-hosted", "windows servers only", "on windows")):
        item["reachability"] = "unlikely"
        if "Linux環境" not in str(item.get("desc") or ""):
            item["desc"] = str(item.get("desc") or "") + " [Reachability: unlikely (Linuxベース構成のため影響限定的)]"


def classify_category(item: Dict[str, Any]) -> str:
    """Classify finding into Secrets, Dependencies (SCA), CI/CD, IaC, or SAST."""
    title = str(item.get("title") or "").lower()
    scanner = str(item.get("scanner") or "").lower()
    file_loc = str(item.get("file") or "").lower()
    if (
        "シークレット" in title
        or scanner == "gitleaks"
        or str(item.get("rule_id") or "").lower() in ("aws-access-token", "openai-api-key", "private-key", "generic-api-key")
    ):
        return "Secrets"
    if (
        scanner in ("zizmor", "actionlint")
        or ".github/workflows/" in file_loc
        or "[zizmor]" in title
    ):
        return "CI/CD"
    if (
        item.get("package_name")
        or "[osv" in title
        or "[trivy]" in title and any(m in file_loc for m in ("package.json", "package-lock.json", "requirements.txt", "go.mod", "composer.json", "cargo.toml"))
        or "[依存関係脆弱性集約]" in title
    ):
        return "Dependencies (SCA)"
    if (
        scanner == "trivy"
        or ".tf" in file_loc
        or "dockerfile" in file_loc
        or "cloudformation" in file_loc
        or "yaml" in file_loc
    ):
        return "IaC"
    return "SAST"


def classify_update_type(item: Dict[str, Any]) -> Optional[str]:
    """Return 'Safe Patch/Minor' or 'Breaking Major' when a dependency diff/upgrade is present."""
    diff_val = str(item.get("diff") or "")
    if not diff_val:
        return None
    m_old = re.search(r'^-\s*"?([^":\s]+)"?\s*[:=]\s*"?[\^~v=]*([^"\s]+)"?', diff_val, re.MULTILINE)
    m_new = re.search(r'^\+\s*"?([^":\s]+)"?\s*[:=]\s*"?[\^~v=]*([^"\s]+)"?', diff_val, re.MULTILINE)
    if not (m_old and m_new):
        return None
    old_t, new_t = _parse_ver(m_old.group(2)), _parse_ver(m_new.group(2))
    if not (old_t and new_t):
        return None
    if new_t[0] > old_t[0]:
        return "Breaking Major"
    return "Safe Patch/Minor"


def classify_priority_tier(item: Dict[str, Any], kev_set: Optional[Set[str]] = None) -> Tuple[str, str]:
    """Assign (priority_tier, priority_reason) for P0-P3 automated triage."""
    title = str(item.get("title") or "")
    low_title = title.lower()
    desc = str(item.get("desc") or "")
    low_blob = f"{title} {desc}".lower()
    scanner = str(item.get("scanner") or "").lower()
    rule_id = str(item.get("rule_id") or "").lower()
    sev = str(item.get("severity") or "medium").lower()
    reachability = str(item.get("reachability") or "").lower()

    cves = _extract_cves(item)
    in_kev = bool(item.get("in_cisa_kev")) or bool(kev_set and any(c in kev_set for c in cves))
    if in_kev:
        item["in_cisa_kev"] = True

    # P0: Real secret leaks or committed .env files
    if (
        "シークレット設定ファイル漏洩" in title
        or "シークレット漏洩検知" in title
        or scanner == "gitleaks"
        or rule_id in ("aws-access-token", "openai-api-key", "private-key")
    ):
        return "P0", "実シークレット漏洩 / 認証ファイル露出（即時無効化が必要）"

    # P1: KEV, high EPSS (>= 0.10), or high-impact RCE/Auth/SSRF/SQLi dependency CVEs
    epss = item.get("epss_score")
    try:
        epss_val = float(epss) if epss is not None else 0.0
    except (TypeError, ValueError):
        epss_val = 0.0

    if in_kev:
        return "P1", "CISA KEV 登録済み（実環境での悪用確認済みCVE）"
    if epss_val >= 0.10:
        return "P1", f"EPSS 悪用確率が高い脆弱性 ({epss_val:.0%})"
    if reachability not in ("unlikely", "mitigated") and any(kw in low_blob for kw in _P1_KEYWORDS):
        if any(pkg in low_title for pkg in _P3_LOW_IMPACT_PACKAGES) and "rce" not in low_blob:
            return "P3", "ビルドツール/間接依存の軽微な影響"
        return "P1", "RCE・認証/認可バイパス・SSRF等の重大脆弱性"

    # P3: Build/dev-tool minor DoS, zizmor unpinned-uses, unlikely/mitigated, low/info
    if reachability in ("unlikely", "mitigated"):
        return "P3", f"到達可能性が低い/緩和済み ({reachability})"
    if rule_id in ("unpinned-uses", "excessive-permissions"):
        return "P3", "CI/CD ガードレール強化（計画的対応）"
    if any(pkg in low_title for pkg in _P3_LOW_IMPACT_PACKAGES) and "remote code execution" not in low_blob:
        return "P3", "ビルドツール/間接依存の軽微なDoS"
    if sev in ("low", "info"):
        return "P3", "低リスク / 情報レベルの改善推奨"

    # P2: CI/CD template-injection / dangerous-triggers, IaC, medium/high remaining
    if scanner in ("zizmor", "actionlint") or rule_id in ("template-injection", "dangerous-triggers"):
        return "P2", "CI/CD ワークフローのセキュリティ強化"
    if "trivy" in low_title or scanner == "trivy":
        if ".tf" in low_blob or ".yaml" in low_blob or ".yml" in low_blob or "dockerfile" in low_blob:
            return "P2", "IaC / コンテナ設定のセキュリティ強化"
    return "P2", "計画的なアップデート・修正推奨"


def _parse_ver(raw: str) -> Optional[Tuple[int, ...]]:
    m = re.search(r"(\d+(?:\.\d+)*)", str(raw or "").strip())
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def validate_and_sanitize_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    """Final output validator gate: block downgrades, prereleases, broken fix_cmd, and secret leaks."""
    if not isinstance(item, dict):
        return item

    # 1. Secret leak safety check
    title = str(item.get("title") or "")
    diff_val = str(item.get("diff") or "")
    if "シークレット漏洩検知" in title and diff_val:
        safe_lines = []
        for ln in diff_val.splitlines():
            if ln.startswith("- ") and ln != "- [REDACTED SECRET LINE]" and not re.match(
                r"^- [A-Za-z_][A-Za-z0-9_.-]{1,60}\s*[:=]\s*\[REDACTED\]$", ln
            ):
                safe_lines.append("- [REDACTED SECRET LINE]")
            else:
                safe_lines.append(ln)
        item["diff"] = "\n".join(safe_lines)

    # 2. Validate fix_cmd (no ecosystem parens, no comma-separated versions, no prereleases)
    fix_cmd = str(item.get("fix_cmd") or "")
    if fix_cmd:
        fix_cmd = re.sub(r"\s*\((?:npm|PyPI|Go|Packagist|crates\.io)\)@", "@", fix_cmd)
        if "," in fix_cmd and ("npm install" in fix_cmd or "go get" in fix_cmd or "pip install" in fix_cmd):
            fix_cmd = re.sub(r"@\^?[^\s]+,\s*[^\s]+", "@latest", fix_cmd)
        if _PRERELEASE_VER_RE.search(fix_cmd) and "npm install " in fix_cmd:
            fix_cmd = re.sub(r"@[^\s]+", "@latest", fix_cmd)
        item["fix_cmd"] = fix_cmd

    # 3. Validate dependency diff for downgrades or prereleases
    if diff_val and ('- "' in diff_val or "- " in diff_val):
        m_old = re.search(r'^-\s*"?([^":\s]+)"?\s*[:=]\s*"?[\^~v=]*([^"\s]+)"?', diff_val, re.MULTILINE)
        m_new = re.search(r'^\+\s*"?([^":\s]+)"?\s*[:=]\s*"?[\^~v=]*([^"\s]+)"?', diff_val, re.MULTILINE)
        if m_old and m_new and m_old.group(1) == m_new.group(1):
            old_v, new_v = m_old.group(2), m_new.group(2)
            old_t, new_t = _parse_ver(old_v), _parse_ver(new_v)
            if _PRERELEASE_VER_RE.search(new_v) or (old_t and new_t and new_t <= old_t):
                item["diff"] = ""
                if "npm install " in str(item.get("fix_cmd") or ""):
                    pkg = m_old.group(1)
                    item["fix_cmd"] = f"npm install {pkg}@latest"

    return item


def compute_finding_fingerprint(repo_id: str, item: Dict[str, Any]) -> str:
    """Compute a deterministic 16-char SHA-256 fingerprint for suppression & diffing."""
    file_base = str(item.get("file") or "").split(" (Target:", 1)[0].split(":", 1)[0].strip().lower()
    rule_or_pkg = str(item.get("rule_id") or item.get("package_name") or "").strip().lower()
    title_norm = re.sub(r"\s+", " ", str(item.get("title") or "").strip().lower())
    raw = f"{repo_id}|{file_base}|{rule_or_pkg}|{title_norm}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def triage_and_validate_findings(
    items: List[Dict[str, Any]],
    *,
    repo_id: str = "",
    repo_dir: Optional[Path] = None,
    kev_set: Optional[Set[str]] = None,
    previous_fingerprints: Optional[Iterable[str]] = None,
    suppressed_map: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Run reachability annotation, P0-P3 triage, output validation, fingerprinting, and sorting."""
    is_linux = detect_linux_container_repo(repo_dir)
    prev_fps = set(previous_fingerprints or ())
    supp = suppressed_map or {}
    has_prev = bool(prev_fps)

    processed: List[Dict[str, Any]] = []
    for raw_item in items:
        if not isinstance(raw_item, dict):
            continue
        item = dict(raw_item)
        annotate_windows_cve_reachability(item, is_linux)
        tier, reason = classify_priority_tier(item, kev_set=kev_set)
        item["priority_tier"] = tier
        item["priority_reason"] = reason
        item["category"] = item.get("category") or classify_category(item)
        validate_and_sanitize_finding(item)
        upd_type = classify_update_type(item)
        if upd_type:
            item["update_type"] = upd_type
        fp = compute_finding_fingerprint(repo_id, item)
        item["fingerprint"] = fp
        if has_prev:
            item["is_new"] = fp not in prev_fps
        if fp in supp:
            entry = supp[fp]
            item["suppressed"] = True
            item["suppression_status"] = entry.get("status", "ignored") if isinstance(entry, dict) else "ignored"
            item["suppressed_reason"] = entry.get("reason", "") if isinstance(entry, dict) else ""
            item["suppressed_note"] = entry.get("note", "") if isinstance(entry, dict) else ""
            item["snooze_expires_at"] = entry.get("expires_at") if isinstance(entry, dict) else None
        else:
            item["suppressed"] = False
        processed.append(item)

    processed.sort(
        key=lambda x: (
            TIER_ORDER.get(str(x.get("priority_tier") or "P2"), 2),
            SEV_ORDER.get(str(x.get("severity") or "medium").lower(), 2),
            str(x.get("title") or ""),
        )
    )
    return processed
