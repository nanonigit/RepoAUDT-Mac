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

_P1_PHRASES = (
    "remote code execution",
    "execute arbitrary code",
    "arbitrary code execution",
    "auth bypass",
    "authentication bypass",
    "middleware bypass",
    "authorization bypass",
    "oauth",
    "ip spoofing",
    "server-side request forgery",
    "sql injection",
    "arbitrary file read",
    "improper categorization in ispublic",
)
_P1_WORD_RE = re.compile(r"\b(?:rce|ssrf|sqli|xss)\b", re.IGNORECASE)
_P1_CWE_ALWAYS = {
    "CWE-77", "CWE-78", "CWE-94", "CWE-502",
    "CWE-287", "CWE-306", "CWE-639", "CWE-863",
    "CWE-918", "CWE-89", "CWE-22",
}
_P1_CWE_HIGH_CRIT = {"CWE-290", "CWE-1321"}
_CWE_RE = re.compile(r"\b(CWE-\d{1,5})\b", re.IGNORECASE)
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
    """Classify finding into malware, eol, Secrets, Dependencies (SCA), CI/CD, IaC, or SAST."""
    title = str(item.get("title") or "").lower()
    explicit_cat = str(item.get("category") or "").strip().lower()
    if item.get("is_malware") or explicit_cat == "malware" or "マルウェアパッケージ検出" in title:
        return "malware"
    if explicit_cat == "eol" or "[eol検出]" in title:
        return "eol"
    if explicit_cat == "license" or "[ossライセンス監査]" in title:
        return "license"
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


def _extract_cwe_ids(item: Dict[str, Any]) -> List[str]:
    cwes: List[str] = []
    seen: Set[str] = set()
    for raw in list(item.get("cwe_ids") or []):
        c = str(raw).strip().upper()
        if c and c not in seen:
            seen.add(c)
            cwes.append(c)
    blob = f"{item.get('title') or ''} {item.get('desc') or ''} {item.get('summary') or ''}"
    for m in _CWE_RE.finditer(blob):
        c = m.group(1).upper()
        if c not in seen:
            seen.add(c)
            cwes.append(c)
    return cwes


def _load_package_json_deps(repo_dir: Optional[Path]) -> Tuple[Set[str], Set[str]]:
    if not repo_dir:
        return set(), set()
    pkg_json = Path(repo_dir) / "package.json"
    if not pkg_json.is_file():
        return set(), set()
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
        prod = {str(k).lower() for k in (data.get("dependencies") or {}).keys()}
        dev = {str(k).lower() for k in (data.get("devDependencies") or {}).keys()} - prod
        return prod, dev
    except Exception:
        return set(), set()


def classify_priority_ssvc(item: Dict[str, Any], kev_set: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Single Source of Truth SSVC-based deterministic P0-P3 classifier with evidence & confidence."""
    title = str(item.get("title") or "")
    low_title = title.lower()
    desc = str(item.get("desc") or "")
    low_blob = f"{title} {desc}".lower()
    scanner = str(item.get("scanner") or "").lower()
    rule_id = str(item.get("rule_id") or "").lower()
    sev = str(item.get("severity") or "medium").lower()
    reachability = str(item.get("reachability") or "").lower()
    dep_scope = str(item.get("dep_scope") or "").lower()
    ver_status = str(
        item.get("verification_status")
        or ((item.get("secret_liveness") or {}).get("status") if isinstance(item.get("secret_liveness"), dict) else "")
        or ""
    ).lower()

    evidence: List[str] = []
    cves = _extract_cves(item)
    cwes = _extract_cwe_ids(item)
    in_kev = bool(item.get("in_cisa_kev")) or bool(kev_set and any(c in kev_set for c in cves))
    if in_kev:
        item["in_cisa_kev"] = True
        evidence.append("CISA KEV")

    epss = item.get("epss_score")
    try:
        epss_val = float(epss) if epss is not None else 0.0
    except (TypeError, ValueError):
        epss_val = 0.0
    if epss_val >= 0.10:
        evidence.append(f"EPSS {epss_val:.1%}")

    if dep_scope == "prod":
        evidence.append("Prod Dependency")
    elif dep_scope == "dev":
        evidence.append("devDependencies のみ")
    elif dep_scope == "transitive":
        evidence.append("Transitive Dependency")

    def _finish(tier: str, reason: str, confidence: str) -> Dict[str, Any]:
        # Automatic 1-tier downgrade for devDependencies-only packages (unless CISA KEV)
        if dep_scope == "dev" and not in_kev and tier in ("P1", "P2"):
            tier = "P2" if tier == "P1" else "P3"
            if "devDependencies のみ" not in reason:
                reason = f"{reason}（devDependencies のみの為1段階降格）"
        dedup_ev: List[str] = []
        for ev in evidence:
            if ev and ev not in dedup_ev:
                dedup_ev.append(ev)
        item["priority_tier"] = tier
        item["priority_reason"] = reason
        item["priority_evidence"] = dedup_ev
        item["confidence"] = confidence
        return {
            "priority_tier": tier,
            "priority_reason": reason,
            "priority_evidence": dedup_ev,
            "confidence": confidence,
        }

    # (A) P0: Malware, verified active secrets, provider-specific secrets, generic gitleaks
    if item.get("is_malware") or str(item.get("category") or "").lower() == "malware" or "マルウェアパッケージ検出" in title:
        evidence.append("OpenSSF MAL-*")
        return _finish("P0", "OpenSSF Malicious Package (MAL-*) — 即時アンインストール・侵害調査が必要", "high")

    if ver_status == "revoked":
        evidence.append("Revoked Secret")
        return _finish("P3", "失効済みキー（履歴削除のみ推奨）", "high")

    if ver_status == "active":
        evidence.append("Active Verified Secret")
        return _finish("P0", "有効なシークレットキー（即時失効必須）", "high")

    if "環境設定ファイルコミット" in title:
        evidence.append("Non-Secret .env Config")
        return _finish("P2", "環境設定ファイルのGit管理（機密値未検出・.gitignore追加推奨）", "high")

    if scanner == "gitleaks" and rule_id == "generic-api-key":
        evidence.extend(["Gitleaks generic-api-key", "Manual Verification Recommended"])
        return _finish("P0", "汎用APIキー候補（プロバイダ固有形式ではないため要目視確認）", "medium")

    if (
        str(item.get("category") or "").lower() == "secrets"
        or "シークレット設定ファイル漏洩" in title
        or "シークレット漏洩検知" in title
        or scanner == "gitleaks"
        or rule_id in ("aws-access-token", "openai-api-key", "github-pat", "private-key", "slack-access-token")
    ):
        evidence.append("Provider-Specific Secret / Credential File")
        return _finish("P0", "実シークレット漏洩 / 認証ファイル露出（即時無効化が必要）", "high")

    # (B) P1: KEV, high EPSS, official dangerous CWE, critical dependency, run: shell injection
    if in_kev:
        return _finish("P1", "CISA KEV 登録済み（実環境での悪用確認済みCVE）", "high")

    if epss_val >= 0.10 and sev in ("critical", "high"):
        return _finish("P1", f"EPSS 悪用確率が高い脆弱性 ({epss_val:.0%})", "high")

    matched_cwes = [c for c in cwes if c in _P1_CWE_ALWAYS or (c in _P1_CWE_HIGH_CRIT and sev in ("critical", "high"))]
    if matched_cwes and reachability not in ("unlikely", "mitigated"):
        evidence.extend(matched_cwes)
        return _finish("P1", f"重大 CWE 該当 ({', '.join(matched_cwes[:3])})", "high")

    if reachability in ("unlikely", "mitigated"):
        evidence.append(f"Reachability: {reachability}")
        return _finish("P3", f"到達可能性が低い/緩和済み ({reachability})", "high")

    is_run_shell_inj = rule_id == "run-shell-injection" or (
        scanner in ("zizmor", "actionlint") and "run:" in low_blob and "injection" in low_blob
    )
    if is_run_shell_inj:
        evidence.append("GitHub Actions run: Shell Injection")
        return _finish("P1", "GitHub Actions run: ブロック内のシェルインジェクション", "high")

    is_dependency_vuln = bool(
        item.get("package_name")
        or item.get("pkg")
        or cves
        or "[依存関係脆弱性集約]" in title
        or str(item.get("category") or "").lower() == "sca"
    )
    if is_dependency_vuln and sev == "critical":
        evidence.append("CRITICAL Severity Dependency")
        return _finish("P1", "CRITICAL 重要度の依存関係脆弱性", "high")

    # Preserve highest inherited P1 on aggregated dependency findings
    existing_tier = str(item.get("priority_tier") or "").upper()
    if ("[依存関係脆弱性集約]" in title or item.get("aggregated")) and existing_tier == "P1":
        evidence.append("Aggregated P1 Signal")
        return _finish("P1", str(item.get("priority_reason") or "集約CVE内の最高優先度を引き継ぎ"), "high")

    has_p1_keyword = (
        bool(_P1_WORD_RE.search(low_blob))
        or any(kw in low_blob for kw in _P1_PHRASES)
        or ("prototype pollution" in low_blob and sev in ("critical", "high"))
    )
    if has_p1_keyword:
        if any(pkg in low_title for pkg in _P3_LOW_IMPACT_PACKAGES) and not _P1_WORD_RE.search(low_blob):
            evidence.append("Build/Dev-Tool Minor Impact")
            return _finish("P3", "ビルドツール/間接依存の軽微な影響", "medium")
        evidence.append("High-Impact Exploit Keyword")
        return _finish("P1", "RCE・認証/認可バイパス・SSRF等の重大脆弱性", "medium")

    # (D) P3 / P2
    if rule_id in ("unpinned-uses", "excessive-permissions"):
        evidence.append(f"zizmor: {rule_id}")
        return _finish("P3", "CI/CD ガードレール強化（計画的対応）", "high")
    if any(pkg in low_title for pkg in _P3_LOW_IMPACT_PACKAGES):
        evidence.append("Build/Dev-Tool DoS")
        return _finish("P3", "ビルドツール/間接依存の軽微なDoS", "high")
    if sev in ("low", "info"):
        return _finish("P3", "低リスク / 情報レベルの改善推奨", "medium")

    if scanner in ("zizmor", "actionlint") or rule_id in ("template-injection", "dangerous-triggers"):
        evidence.append("CI/CD Hardening")
        return _finish("P2", "CI/CD ワークフローのセキュリティ強化", "high")
    low_file = str(item.get("file") or item.get("path") or "").lower()
    is_pkg_vuln = bool(
        item.get("pkg")
        or item.get("package_name")
        or item.get("cve")
        or any(
            lf in low_file
            for lf in (
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                "requirements.txt",
                "poetry.lock",
                "pyproject.toml",
                "go.mod",
                "cargo.lock",
                "composer.lock",
                "gemfile.lock",
            )
        )
    )
    if (not is_pkg_vuln) and (
        "trivy" in low_title
        or scanner == "trivy"
        or any(k in low_blob for k in (".tf", "terraform", "cloudformation", "dockerfile"))
    ):
        evidence.append("IaC / Container")
        return _finish("P2", "IaC / コンテナ設定のセキュリティ強化", "high")
    if "eol" in low_blob or str(item.get("category") or "").lower() == "eol":
        evidence.append("EOL Runtime/Framework")
        return _finish("P2", "サポート終了（EOL）ランタイム・フレームワークの更新推奨", "high")

    if not evidence:
        evidence.append(f"Severity: {sev.upper()}")
    return _finish("P2", "計画的なアップデート・修正推奨", "medium")


def classify_priority_tier(item: Dict[str, Any], kev_set: Optional[Set[str]] = None) -> Tuple[str, str]:
    """Assign (priority_tier, priority_reason) for P0-P3 automated triage via SSVC engine."""
    res = classify_priority_ssvc(item, kev_set=kev_set)
    return res["priority_tier"], res["priority_reason"]


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
    prod_deps, dev_deps = _load_package_json_deps(repo_dir)
    prev_fps = set(previous_fingerprints or ())
    supp = suppressed_map or {}
    has_prev = bool(prev_fps)

    processed: List[Dict[str, Any]] = []
    for raw_item in items:
        if not isinstance(raw_item, dict):
            continue
        item = dict(raw_item)
        pkg_name = str(item.get("package_name") or item.get("pkg") or "").strip().lower()
        if pkg_name and not item.get("dep_scope") and (prod_deps or dev_deps):
            if pkg_name in prod_deps:
                item["dep_scope"] = "prod"
            elif pkg_name in dev_deps:
                item["dep_scope"] = "dev"
            else:
                item["dep_scope"] = "transitive"
        annotate_windows_cve_reachability(item, is_linux)
        classify_priority_ssvc(item, kev_set=kev_set)
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


def build_dependency_batch_plan(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Group active SCA dependency findings into:
      - safe_patch_minor: Patch/Minor upgrades safe for a single combined install command
      - breaking_major: Major upgrades or unknown-version items requiring manual review
    Never includes downgrades or prerelease versions.
    """
    safe_items: List[Dict[str, Any]] = []
    major_items: List[Dict[str, Any]] = []
    npm_safe_specs: List[str] = []
    seen_specs: Set[str] = set()

    for raw in items:
        if not isinstance(raw, dict) or raw.get("suppressed"):
            continue
        item = validate_and_sanitize_finding(dict(raw))
        cat = item.get("category") or classify_category(item)
        if cat != "Dependencies (SCA)":
            continue
        upd = item.get("update_type") or classify_update_type(item)
        fix_cmd = str(item.get("fix_cmd") or "").strip()
        if not fix_cmd or _PRERELEASE_VER_RE.search(fix_cmd) or "@latest" in fix_cmd:
            major_items.append(item)
            continue

        if upd == "Safe Patch/Minor":
            safe_items.append(item)
            m_npm = re.match(r"^npm install\s+([^\s]+)$", fix_cmd)
            if m_npm:
                spec = m_npm.group(1)
                if spec not in seen_specs:
                    seen_specs.add(spec)
                    npm_safe_specs.append(spec)
        else:
            major_items.append(item)

    combined_npm_cmd = f"npm install {' '.join(npm_safe_specs)}" if npm_safe_specs else ""
    return {
        "safe_patch_minor": safe_items,
        "breaking_major": major_items,
        "combined_npm_command": combined_npm_cmd,
    }


def _sanitize_slack_text(text: str) -> str:
    """Strip any accidental raw secret tokens and escape Slack-breaking chars."""
    s = str(text or "").strip()
    s = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", s)
    s = re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED_API_KEY]", s)
    s = re.sub(r"ghp_[A-Za-z0-9]{20,}", "[REDACTED_GH_TOKEN]", s)
    return s


def build_slack_digest(diagrams: List[Dict[str, Any]], *, lang: str = "ja") -> str:
    """Build a Slack mrkdwn summary of P0/P1 findings without ever exposing raw secrets."""
    lines: List[str] = []
    is_en = lang == "en"
    is_both = lang == "both"

    if is_both:
        lines.append("*🛡️ RepoAUDT Mac セキュリティ監査ダイジェスト / Security Audit Digest*")
    elif is_en:
        lines.append("*🛡️ RepoAUDT Mac Security Audit Digest (P0 / P1)*")
    else:
        lines.append("*🛡️ RepoAUDT Mac セキュリティ監査ダイジェスト（P0 / P1）*")

    total_p0 = 0
    total_p1 = 0
    repo_blocks: List[str] = []

    for d in diagrams:
        if not isinstance(d, dict) or d.get("is_root"):
            continue
        repo_name = str(d.get("repo") or d.get("github_url") or "Repository").strip()
        cr = d.get("coderabbit") or {}
        items = [
            it for it in (list(cr.get("action_items") or []) + list(cr.get("findings") or []))
            if isinstance(it, dict) and not it.get("suppressed")
        ]
        seen = set()
        priority_items = []
        for it in items:
            tier = str(it.get("priority_tier") or "").upper()
            sev = str(it.get("severity") or "").lower()
            if tier not in ("P0", "P1") and sev not in ("critical", "high"):
                continue
            key = f"{it.get('title', '')}|{it.get('file', '')}"
            if key in seen:
                continue
            seen.add(key)
            eff_tier = tier if tier in ("P0", "P1") else ("P0" if sev == "critical" else "P1")
            if eff_tier == "P0":
                total_p0 += 1
            else:
                total_p1 += 1
            priority_items.append((eff_tier, it))

        if not priority_items:
            continue
        priority_items.sort(key=lambda pair: 0 if pair[0] == "P0" else 1)
        block = [f"\n*• {repo_name}* (`{len(priority_items)}`件)"]
        for eff_tier, it in priority_items[:6]:
            title = _sanitize_slack_text(str(it.get("title") or "Finding"))
            file_loc = _sanitize_slack_text(str(it.get("file") or "").split(" (Target:", 1)[0].strip())
            kev = " 🔥KEV" if it.get("in_cisa_kev") else ""
            fix_cmd = _sanitize_slack_text(str(it.get("fix_cmd") or "").splitlines()[0] if it.get("fix_cmd") else "")
            line = f"  - `[{eff_tier}]`{kev} {title}"
            if file_loc:
                line += f" (`{file_loc}`)"
            if fix_cmd and not fix_cmd.startswith("sed -n"):
                line += f" → `{fix_cmd}`"
            block.append(line)
        if len(priority_items) > 6:
            block.append(f"  - _…ほか {len(priority_items) - 6} 件_")
        repo_blocks.append("\n".join(block))

    if is_both:
        lines.append(f"• *P0 (緊急 / Critical)*: `{total_p0}` | *P1 (高リスク / High)*: `{total_p1}`")
    elif is_en:
        lines.append(f"• *P0 (Critical)*: `{total_p0}` | *P1 (High)*: `{total_p1}`")
    else:
        lines.append(f"• *P0（緊急）*: `{total_p0}件` | *P1（高リスク）*: `{total_p1}件`")

    if block_lines := repo_blocks:
        lines.extend(block_lines)
    else:
        lines.append("• ✅ P0 / P1 の要対応指摘はありません。" if not is_en else "• ✅ No P0 / P1 actionable findings.")
    return "\n".join(lines)


def build_pdf_audit_html(diagrams: List[Dict[str, Any]], *, lang: str = "ja") -> str:
    """Build a print/PDF-optimized HTML audit report (white background, no raw secrets)."""
    from html import escape
    from datetime import datetime, timezone

    is_en = lang == "en"
    now_str = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M UTC")
    target_repos = [d for d in diagrams if isinstance(d, dict) and not d.get("is_root")]

    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    new_cnt = 0
    repo_sections: List[str] = []
    cross_rows: List[Tuple[int, str, str, str, str, str]] = []

    for d in target_repos:
        repo_name = str(d.get("repo") or d.get("github_url") or "Repository")
        commit_sha = str((d.get("source_revision") or {}).get("commit_sha") or d.get("commit_hash") or "HEAD")
        posture = d.get("github_posture") or {}
        lic_summary = (d.get("deps") or {}).get("license_summary") or {}
        cr = d.get("coderabbit") or {}
        items = [
            it for it in (list(cr.get("action_items") or []) + list(cr.get("findings") or []))
            if isinstance(it, dict) and not it.get("suppressed")
        ]
        seen = set()
        deduped = []
        for it in items:
            k = f"{it.get('title', '')}|{it.get('file', '')}"
            if k not in seen:
                seen.add(k)
                deduped.append(it)
                t = str(it.get("priority_tier") or "P2").upper()
                if t in counts:
                    counts[t] += 1
                if it.get("is_new"):
                    new_cnt += 1

        p0_p1 = [it for it in deduped if str(it.get("priority_tier") or "").upper() in ("P0", "P1")]
        p0_p1.sort(key=lambda x: 0 if str(x.get("priority_tier") or "").upper() == "P0" else 1)
        for it in p0_p1:
            t_str = str(it.get("priority_tier") or "P1").upper()
            short_file = str(it.get("file") or "").split(" (Target:", 1)[0].strip()
            short_act = _sanitize_slack_text(str(it.get("fix_cmd") or it.get("priority_reason") or ("即時無効化" if t_str == "P0" else "安全版へ更新")))
            cross_rows.append((
                0 if t_str == "P0" else 1,
                t_str,
                repo_name,
                _sanitize_slack_text(str(it.get("title") or "")),
                short_file,
                short_act,
            ))
        posture_str = (
            f"Visibility: {posture.get('visibility', 'unknown')} · "
            f"Branch Protected: {posture.get('default_branch_protected', 'unknown')}"
        )
        lic_str = (
            f"MIT: {lic_summary.get('MIT', 0)} / Apache-2.0: {lic_summary.get('Apache-2.0', 0)} / "
            f"BSD: {lic_summary.get('BSD', 0)} / Copyleft Risk: {lic_summary.get('copyleft_risk', 0)}"
            if lic_summary else ("No license summary recorded" if is_en else "ライセンスサマリー未記録")
        )

        rows_html = "".join(
            f"""<div class="finding-card">
              <div class="finding-head">
                <span class="badge badge-{escape(str(it.get('priority_tier') or 'P2').lower())}">{escape(str(it.get('priority_tier') or 'P2'))}</span>
                <span class="meta">(Confidence: {escape(str(it.get('confidence') or 'medium').capitalize())})</span>
                <strong>{escape(_sanitize_slack_text(str(it.get('title') or '')))}</strong>
              </div>
              {f"<div class='meta'>Evidence: {' · '.join(escape(str(e)) for e in (it.get('priority_evidence') or []))}</div>" if it.get('priority_evidence') else ""}
              <div class="meta">{escape(str(it.get('file') or ''))}</div>
              <p>{escape(_sanitize_slack_text(str(it.get('desc') or it.get('comment') or '')))}</p>
              {f"<pre>{escape(_sanitize_slack_text(str(it.get('fix_cmd') or '')))}</pre>" if it.get('fix_cmd') else ""}
              {f"<div class='ref'>Ref: {escape(str(it.get('official_source')))}</div>" if it.get('official_source') else ""}
            </div>"""
            for it in p0_p1[:25]
        ) or f"<p class='clean'>{escape('No P0/P1 actionable findings.' if is_en else 'P0 / P1 の要対応指摘はありません。')}</p>"

        repo_sections.append(
            f"""<section class="repo-section">
              <h2>{escape(repo_name)}</h2>
              <div class="repo-meta">
                <span>Commit: <code>{escape(commit_sha[:12])}</code></span> ·
                <span>{escape(posture_str)}</span><br/>
                <span>OSS Licenses: {escape(lic_str)}</span>
              </div>
              {rows_html}
            </section>"""
        )

    title_txt = "RepoAUDT Mac Security Audit Report" if is_en else "RepoAUDT Mac セキュリティ監査報告書"
    return f"""<!DOCTYPE html>
<html lang="{ 'en' if is_en else 'ja' }">
<head>
<meta charset="utf-8"/>
<title>{escape(title_txt)}</title>
<style>
  @page {{ size: A4; margin: 16mm; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Hiragino Sans", "Helvetica Neue", sans-serif; background: #ffffff; color: #0f172a; margin: 0; padding: 20px; line-height: 1.5; }}
  h1 {{ font-size: 20px; margin: 0 0 6px; border-bottom: 2px solid #0284c7; padding-bottom: 6px; }}
  h2 {{ font-size: 16px; margin: 18px 0 6px; color: #0f172a; border-left: 4px solid #0284c7; padding-left: 8px; }}
  .header-meta {{ font-size: 12px; color: #475569; margin-bottom: 14px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 18px; }}
  .kpi {{ border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: #f8fafc; }}
  .kpi span {{ display: block; font-size: 11px; color: #475569; font-weight: 600; }}
  .kpi strong {{ font-size: 18px; }}
  .repo-section {{ margin-bottom: 20px; }}
  .repo-meta {{ font-size: 11.5px; color: #475569; margin-bottom: 10px; }}
  .finding-card {{ border: 1px solid #cbd5e1; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px; page-break-inside: avoid; break-inside: avoid; }}
  .finding-head {{ display: flex; gap: 8px; align-items: center; margin-bottom: 4px; font-size: 13px; }}
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }}
  .badge-p0 {{ background: #dc2626; }}
  .badge-p1 {{ background: #ea580c; }}
  .badge-p2 {{ background: #ca8a04; }}
  .badge-p3 {{ background: #2563eb; }}
  .meta, .ref {{ font-size: 11px; color: #475569; }}
  p {{ margin: 4px 0; font-size: 12px; }}
  pre {{ background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px 8px; font-size: 11px; white-space: pre-wrap; word-break: break-all; margin: 6px 0 0; }}
  .clean {{ color: #16a34a; font-weight: 600; }}
</style>
</head>
<body>
  <h1>🛡️ {escape(title_txt)}</h1>
  <div class="header-meta">
    { 'Generated' if is_en else '出力日時' }: {escape(now_str)} ·
    { 'Repositories' if is_en else '対象リポジトリ数' }: {len(target_repos)}
  </div>
  <div class="kpi-grid">
    <div class="kpi"><span>P0 Critical</span><strong>{counts['P0']}</strong></div>
    <div class="kpi"><span>P1 High</span><strong>{counts['P1']}</strong></div>
    <div class="kpi"><span>P2 Planned</span><strong>{counts['P2']}</strong></div>
    <div class="kpi"><span>P3 Backlog</span><strong>{counts['P3']}</strong></div>
    <div class="kpi"><span>New Findings</span><strong>+{new_cnt}</strong></div>
  </div>
  {(
    '<h2>🚨 ' + ('Cross-Repository P0 / P1 Top Summary' if is_en else '全リポジトリ横断 P0 / P1 サマリー') + '</h2>'
    + '<table style="width:100%;border-collapse:collapse;font-size:11px;margin-bottom:16px;">'
    + '<thead><tr style="background:#f1f5f9;text-align:left;"><th style="padding:5px;border:1px solid #cbd5e1;">' + ('Priority' if is_en else '優先度') + '</th><th style="padding:5px;border:1px solid #cbd5e1;">' + ('Repository' if is_en else 'リポジトリ') + '</th><th style="padding:5px;border:1px solid #cbd5e1;">' + ('Finding' if is_en else '指摘タイトル') + '</th><th style="padding:5px;border:1px solid #cbd5e1;">' + ('File' if is_en else '対象ファイル') + '</th><th style="padding:5px;border:1px solid #cbd5e1;">' + ('Action' if is_en else '推奨アクション') + '</th></tr></thead><tbody>'
    + ''.join(
        f'<tr><td style="padding:5px;border:1px solid #cbd5e1;"><span class="badge badge-{escape(r[1].lower())}">{escape(r[1])}</span></td><td style="padding:5px;border:1px solid #cbd5e1;">{escape(r[2])}</td><td style="padding:5px;border:1px solid #cbd5e1;">{escape(r[3])}</td><td style="padding:5px;border:1px solid #cbd5e1;"><code>{escape(r[4])}</code></td><td style="padding:5px;border:1px solid #cbd5e1;"><code>{escape(r[5][:80])}</code></td></tr>'
        for r in sorted(cross_rows, key=lambda x: x[0])
    )
    + '</tbody></table>'
  ) if cross_rows else ''}
  {''.join(repo_sections)}
</body>
</html>"""
