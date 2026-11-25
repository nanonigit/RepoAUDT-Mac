#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Skills, OSV Vulnerability MCP Scanner & Multi-LLM Audit Engine for RepoChex.
Supports:
  1. API Key Management for OpenAI, Anthropic Claude, Google Gemini, and Groq
  2. Real-time OSV.dev Vulnerability Database querying (npm / Packagist PHP / PyPI / Go / crates.io)
  3. PHP, Node.js, Python, Swift, Go Runtime EOL & OWASP Top 10 Security-Review Skill Static Analysis
  4. Live LLM Deep Security & Code Quality Audit via OpenAI / Claude / Gemini / Groq APIs
"""

import ast
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from connection_utils import validate_endpoint, open_endpoint
import copilot_bridge
import gemini_cli_bridge
from workflow_audit import MAX_FILES, find_template_injections_in_workflow, read_small_file, run_actionlint, run_zizmor, workflow_files
from source_scanners import scan_extended_security, scan_semgrep_and_trivy, scan_source
from runtime_patches import scan_runtime_patches
from eol_checker import evaluate_runtime_eol, extract_repo_runtime_and_framework_versions
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def get_app_support_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
        legacy_bases = [base / "RepoChex", base / "RepoChecker"]
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        legacy_bases = [base / "RepoChex", base / "RepoChecker"]
    app_dir = base / "RepoAUDT Mac"
    if not app_dir.exists():
        for old_dir in legacy_bases:
            if old_dir.exists():
                try:
                    shutil.copytree(old_dir, app_dir)
                    break
                except Exception as e:
                    print(f"Migration from {old_dir.name} to RepoAUDT Mac notice: {e}", file=sys.stderr)
    return app_dir


APP_SUPPORT_DIR = get_app_support_dir()
SETTINGS_FILE = APP_SUPPORT_DIR / "settings.json"


DEFAULT_SETTINGS: Dict[str, Any] = {
    "local_base_url": "http://127.0.0.1:11434/v1",
    "active_provider": "auto",  # none | auto | openai | claude | gemini | gemini_cli | groq | local | copilot
    "secondary_provider": "none",  # none | openai | claude | gemini | gemini_cli | groq | local | copilot
    "secondary_model": "",
    "keys": {
        "local": "",
        "openai": "",
        "claude": "",
        "gemini": "",
        "gemini_cli": "",
        "groq": "",
        "copilot": "",
    },
    "models": {
        "local": "",
        "openai": "gpt-4o",
        "claude": "claude-3-7-sonnet-latest",
        "gemini": "gemini-2.5-flash",
        "gemini_cli": "auto",
        "groq": "llama-3.3-70b-versatile",
        "copilot": "auto",
    },
    "skills": {
        "osv_mcp": True,
        "php_node_runtime_audit": True,
        "owasp_sast_skill": True,
        "llm_deep_audit": True,
    },
}


def get_candidate_env_files() -> List[Path]:
    """Return candidate .env file paths searched for API key fallbacks."""
    return [
        APP_SUPPORT_DIR / ".env",
        Path.cwd() / ".env",
        Path.home() / ".config" / "RepoAUDT Mac" / ".env",
        Path.home() / ".config" / "RepoChex" / ".env",
    ]


def load_settings() -> Dict[str, Any]:
    APP_SUPPORT_DIR.mkdir(parents=True, exist_ok=True)
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    if SETTINGS_FILE.exists():
        try:
            saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                settings["active_provider"] = saved.get("active_provider", "auto")
                settings["local_base_url"] = saved.get("local_base_url", DEFAULT_SETTINGS["local_base_url"])
                if isinstance(saved.get("keys"), dict):
                    settings["keys"].update(saved["keys"])
                if isinstance(saved.get("models"), dict):
                    settings["models"].update(saved["models"])
                if isinstance(saved.get("skills"), dict):
                    settings["skills"].update(saved["skills"])
        except Exception as exc:
            print(f"Warning: failed to load settings.json: {exc}", file=sys.stderr)

    # Fallback to environment variables or local Secrets/.env if not explicitly set in settings.json
    env_map = {
        "openai": "OPENAI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "groq": "GROQ_API_KEY",
    }
    for prov, env_name in env_map.items():
        if not settings["keys"].get(prov) and os.environ.get(env_name):
            settings["keys"][prov] = os.environ[env_name]

    for env_file in get_candidate_env_files():
        if env_file.exists():
            try:
                for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    sline = line.strip()
                    if not sline or sline.startswith("#") or "=" not in sline:
                        continue
                    k_env, v_env = sline.split("=", 1)
                    k_env = k_env.strip()
                    v_env = v_env.strip().strip('"').strip("'")
                    for prov, env_name in env_map.items():
                        if k_env == env_name and not settings["keys"].get(prov) and len(v_env) >= 12:
                            settings["keys"][prov] = v_env
            except Exception as exc:
                print(f"Warning: failed to read env file {env_file}: {exc}", file=sys.stderr)

    return settings


def save_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    current = load_settings()
    if "active_provider" in payload:
        prov_val = str(payload["active_provider"]).strip()
        if prov_val in ("none", "auto", "openai", "claude", "gemini", "gemini_cli", "groq", "local", "copilot"):
            current["active_provider"] = prov_val
    if "secondary_provider" in payload:
        sec_val = str(payload["secondary_provider"]).strip()
        if sec_val in ("none", "openai", "claude", "gemini", "gemini_cli", "groq", "local", "copilot"):
            current["secondary_provider"] = sec_val
    if "secondary_model" in payload:
        current["secondary_model"] = str(payload.get("secondary_model") or "").strip()[:120]
    if "local_base_url" in payload:
        current["local_base_url"] = validate_endpoint(payload["local_base_url"], local_only=True)
    if isinstance(payload.get("keys"), dict):
        for k in ("openai", "claude", "gemini", "gemini_cli", "groq", "local", "copilot"):
            if k in payload["keys"]:
                val = str(payload["keys"][k]).strip()
                # Keep existing key if input was left blank or still contains masked ellipsis
                if not val or ("..." in val and len(val) < 30):
                    continue
                # If masked prefix accidentally got prepended before paste, strip it
                if "..." in val and "sk-" in val:
                    idx = val.rfind("sk-")
                    if idx > 0:
                        val = val[idx:]
                current["keys"][k] = val
    if isinstance(payload.get("models"), dict):
        current["models"].update(payload["models"])
    if isinstance(payload.get("skills"), dict):
        current["skills"].update(payload["skills"])
    if isinstance(payload.get("aspm_policy"), dict):
        pol = current.setdefault("aspm_policy", {"block_on_p0": True, "block_on_tier1_kev": True, "warn_on_p1": True})
        for pk in ("block_on_p0", "block_on_tier1_kev", "warn_on_p1"):
            if pk in payload["aspm_policy"]:
                pol[pk] = bool(payload["aspm_policy"][pk])

    APP_SUPPORT_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except Exception as exc:
        print(f"Warning: failed to set 0600 permissions on {SETTINGS_FILE}: {exc}", file=sys.stderr)
    return get_masked_settings(current)


def mask_key(key: str) -> str:
    if not key or len(key) < 8:
        return ""
    return f"{key[:6]}...{key[-4:]}"


def get_masked_settings(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    s = settings or load_settings()
    masked_keys = {}
    configured_status = {}
    for k in ("openai", "claude", "gemini", "gemini_cli", "groq", "local", "copilot"):
        raw = s["keys"].get(k, "")
        masked_keys[k] = mask_key(raw)
        configured_status[k] = bool(raw and len(raw) >= 8)

    configured_status["local"] = bool(s.get("models", {}).get("local"))
    configured_status["copilot"] = configured_status["copilot"] or copilot_bridge.is_copilot_ready()
    configured_status["gemini_cli"] = configured_status["gemini_cli"] or gemini_cli_bridge.is_gemini_cli_ready()

    return {
        "local_base_url": s.get("local_base_url", DEFAULT_SETTINGS["local_base_url"]),
        "active_provider": s.get("active_provider", "auto"),
        "secondary_provider": s.get("secondary_provider", "none"),
        "secondary_model": s.get("secondary_model", ""),
        "keys_masked": masked_keys,
        "configured": configured_status,
        "models": s.get("models", DEFAULT_SETTINGS["models"]),
        "aspm_policy": {
            "block_on_p0": True,
            "block_on_tier1_kev": True,
            "warn_on_p1": True,
            **(s.get("aspm_policy") if isinstance(s.get("aspm_policy"), dict) else {}),
        },
        "skills": s.get("skills", DEFAULT_SETTINGS["skills"]),
    }


def _extract_osv_fixed_version(
    vuln_obj: Dict[str, Any], pkg_name: str, eco: str, installed: str = ""
) -> Optional[str]:
    """Extract the safest upgrade fixed version for (pkg_name, eco) from an OSV record."""
    if not isinstance(vuln_obj, dict):
        return None
    affected_list = vuln_obj.get("affected") or []
    if not isinstance(affected_list, list):
        return None

    def _collect_fixed(entries: List[Dict[str, Any]]) -> List[str]:
        versions: List[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for rng in entry.get("ranges") or []:
                if not isinstance(rng, dict):
                    continue
                for ev in rng.get("events") or []:
                    if isinstance(ev, dict) and ev.get("fixed"):
                        versions.append(str(ev["fixed"]).strip())
        return versions

    matched = [
        e for e in affected_list
        if isinstance(e, dict)
        and str((e.get("package") or {}).get("name") or "").lower() == pkg_name.lower()
        and (
            not (e.get("package") or {}).get("ecosystem")
            or str((e.get("package") or {}).get("ecosystem") or "").lower() == eco.lower()
        )
    ]
    candidates = _collect_fixed(matched) or _collect_fixed(affected_list)
    if not candidates:
        return None
    from source_scanners import select_safe_upgrade_version
    chosen = select_safe_upgrade_version(candidates, installed, pick_highest_same_major=False)
    return chosen or None


def _build_osv_advisory_entries(
    eco: str,
    pkg_name: str,
    clean_ver: str,
    vulns: List[Dict[str, Any]],
    *,
    fetch_details: bool = True,
) -> List[Dict[str, Any]]:
    """Convert OSV vulnerabilities for a package into advisory dicts, separating MAL-* malware."""
    if not vulns:
        return []
    entries: List[Dict[str, Any]] = []
    mal_vulns = [v for v in vulns if str(v.get("id") or "").startswith("MAL-")]
    cve_vulns = [v for v in vulns if not str(v.get("id") or "").startswith("MAL-")]

    for mv in mal_vulns:
        mal_id = str(mv.get("id") or "MAL-UNKNOWN")
        entries.append({
            "package_name": pkg_name,
            "ecosystem": eco,
            "pkg": f"{pkg_name} ({eco})",
            "installed": clean_ver,
            "fixed_version": None,
            "safe_version": None,
            "cve": mal_id,
            "osv_id": mal_id,
            "is_malware": True,
            "category": "malware",
            "priority_tier": "P0",
            "severity": "CRITICAL",
            "title": f"🚨 [マルウェアパッケージ検出] {pkg_name}@{clean_ver} ({mal_id})",
            "summary": (
                f"OpenSSF Malicious Packages ({mal_id}) により `{pkg_name}@{clean_ver}` ({eco}) が悪意あるマルウェアとして報告されています。"
                " バージョン上げではなく、直ちにアンインストールし、ビルド環境・認証情報の侵害有無を確認してください。"
            ),
            "impact": "依存パッケージインストール時の任意コード実行・認証情報窃取・サプライチェーン侵害の危険があります。",
            "sources": [
                {"name": f"OSV.dev ({mal_id})", "url": f"https://osv.dev/vulnerability/{mal_id}"},
            ],
        })

    if cve_vulns:
        v0 = cve_vulns[0]
        vid = v0.get("id", "OSV-VULN")
        aliases = list(v0.get("aliases") or [])
        osv_summary = str(v0.get("summary") or "").strip()
        osv_details = str(v0.get("details") or "").strip()
        fixed_ver = _extract_osv_fixed_version(v0, pkg_name, eco, installed=clean_ver)
        if fetch_details and (not osv_summary or not fixed_ver):
            try:
                vreq = urllib.request.Request(
                    f"https://api.osv.dev/v1/vulns/{vid}",
                    headers={"User-Agent": "RepoAUDT-SecuritySkill"},
                )
                with urllib.request.urlopen(vreq, timeout=4) as vresp:
                    if getattr(vresp, "status", 200) == 200:
                        vfull = json.loads(vresp.read().decode("utf-8", errors="ignore"))
                        if not osv_summary:
                            osv_summary = str(vfull.get("summary") or "").strip()
                        if not osv_details:
                            osv_details = str(vfull.get("details") or "").strip()
                        if not fixed_ver:
                            fixed_ver = _extract_osv_fixed_version(vfull, pkg_name, eco, installed=clean_ver)
                        for al in vfull.get("aliases") or []:
                            if al not in aliases:
                                aliases.append(al)
            except Exception:
                pass
        cve_alias = next((a for a in aliases if str(a).startswith("CVE-")), None)
        display_cve = f"{vid} ({cve_alias})" if (cve_alias and cve_alias != vid) else (cve_alias or vid)
        clean_details = re.sub(r"[#*`]+", "", osv_details).strip()
        first_sentence = clean_details.split("\n\n")[0].replace("\n", " ")[:240] if clean_details else ""
        detail_suffix = f" 脆弱性の内容: {osv_summary} ({first_sentence})" if osv_summary else ""
        entries.append({
            "package_name": pkg_name,
            "ecosystem": eco,
            "pkg": f"{pkg_name} ({eco})",
            "installed": clean_ver,
            "fixed_version": fixed_ver,
            "safe_version": fixed_ver,
            "cve": display_cve,
            "osv_id": vid,
            "severity": "HIGH",
            "title": f"[OSV脆弱性検出] {pkg_name} v{clean_ver} ({display_cve})" + (f" — {osv_summary}" if osv_summary else ""),
            "summary": f"OSV.dev 脆弱性データベースにおいて `{pkg_name}` ({eco}) バージョン `{clean_ver}` に既知の脆弱性 `{display_cve}` (計 {len(cve_vulns)} 件) が報告されています。{detail_suffix}",
            "impact": first_sentence or osv_summary or "放置すると外部からの不正リクエストによって認証回避・情報漏洩・サービス妨害 (DoS) 等に悪用される危険があります。",
            "sources": [
                {"name": f"OSV.dev ({vid})", "url": f"https://osv.dev/vulnerability/{vid}"},
                {"name": "GitHub Advisory", "url": f"https://github.com/advisories?query={pkg_name}"},
            ],
        })
    return entries


def query_osv_batch(packages: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    """
    Query OSV.dev (Google Open Source Vulnerability MCP/API) for real CVEs across
    npm (Node.js), Packagist (PHP Composer), PyPI (Python), Go, and crates.io (Rust).
    Each item in `packages` is (ecosystem, package_name, version).
    """
    if not packages:
        return []

    queries = []
    valid_pkgs = []
    for eco, name, ver in packages[:40]:
        clean_ver = re.sub(r"^[\^~>=<v\s]+", "", str(ver)).split(" ")[0].strip()
        if not clean_ver or clean_ver in ("*", "latest", "HEAD") or not re.match(r"^[0-9]+\.[0-9]+", clean_ver):
            continue
        queries.append({
            "version": clean_ver,
            "package": {"name": name, "ecosystem": eco},
        })
        valid_pkgs.append((eco, name, clean_ver))

    if not queries:
        return []

    advisories: List[Dict[str, Any]] = []
    try:
        req_body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=req_body,
            headers={"Content-Type": "application/json", "User-Agent": "RepoAUDT-SecuritySkill"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                results = data.get("results") or []
                for (eco, pkg_name, clean_ver), res_obj in zip(valid_pkgs, results):
                    vulns = res_obj.get("vulns") or []
                    if vulns:
                        advisories.extend(
                            _build_osv_advisory_entries(
                                eco, pkg_name, clean_ver, vulns, fetch_details=len(advisories) < 8
                            )
                        )
    except Exception as exc:
        print(f"Notice: OSV vulnerability query skipped/failed: {exc}", file=sys.stderr)

    return enrich_advisories_with_epss(advisories)


def enrich_advisories_with_epss(advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich CVE advisories with real-time FIRST.org EPSS (Exploit Prediction Scoring System)
    30-day exploitation probability and percentile scores (`https://api.first.org/data/v1/epss`).
    """
    if not advisories:
        return advisories

    cve_pattern = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
    cve_to_indices: Dict[str, List[int]] = {}
    for idx, adv in enumerate(advisories):
        raw_cve = str(adv.get("cve") or adv.get("id") or adv.get("title") or "")
        m = cve_pattern.search(raw_cve)
        if m:
            cve_id = m.group(1).upper()
            cve_to_indices.setdefault(cve_id, []).append(idx)

    if not cve_to_indices:
        return advisories

    try:
        cve_param = ",".join(sorted(cve_to_indices.keys())[:30])
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
        req = urllib.request.Request(url, headers={"User-Agent": "RepoAUDT-Mac-EPSS/1.2"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if getattr(resp, "status", 200) == 200:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for item in payload.get("data") or []:
                    cid = str(item.get("cve") or "").upper()
                    if cid in cve_to_indices:
                        epss_val = float(item.get("epss", 0.0))
                        pct_val = float(item.get("percentile", 0.0))
                        for i in cve_to_indices[cid]:
                            advisories[i]["epss"] = round(epss_val, 5)
                            advisories[i]["epss_percentile"] = round(pct_val, 5)
                            sources = advisories[i].setdefault("sources", [])
                            epss_url = f"https://api.first.org/data/v1/epss?cve={cid}"
                            if not any(s.get("url") == epss_url for s in sources):
                                sources.append({
                                    "name": f"FIRST.org EPSS ({epss_val * 100:.1f}%)",
                                    "url": epss_url,
                                    "type": "EPSS",
                                })
    except Exception as exc:
        print(f"Notice: EPSS enrichment skipped/failed: {exc}", file=sys.stderr)

    return advisories


SECRET_PATTERNS = [
    (
        "OpenAI API Key",
        r"\b(sk-[a-zA-Z0-9_-]{20,})\b",
        "OpenAI API 認証キー",
        "process.env.OPENAI_API_KEY || os.environ.get('OPENAI_API_KEY')",
    ),
    (
        "Anthropic Claude API Key",
        r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b",
        "Anthropic Claude API 認証キー",
        "process.env.ANTHROPIC_API_KEY || os.environ.get('ANTHROPIC_API_KEY')",
    ),
    (
        "Google / Gemini API Key",
        r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "Google Cloud / Gemini API アクセスキー",
        "process.env.GEMINI_API_KEY || os.environ.get('GEMINI_API_KEY')",
    ),
    (
        "GitHub Personal Access Token",
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
        "GitHub 個人アクセストークン (PAT)",
        "process.env.GITHUB_TOKEN || os.environ.get('GITHUB_TOKEN')",
    ),
    (
        "AWS Access Key ID",
        r"\b(AKIA[0-9A-Z]{16})\b",
        "Amazon Web Services (AWS) アクセスキーID",
        "process.env.AWS_ACCESS_KEY_ID || os.environ.get('AWS_ACCESS_KEY_ID')",
    ),
    (
        "AWS Secret Access Key",
        r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "Amazon Web Services (AWS) シークレットアクセスキー",
        "process.env.AWS_SECRET_ACCESS_KEY || os.environ.get('AWS_SECRET_ACCESS_KEY')",
    ),
    (
        "Slack Token / Webhook URL",
        r"(xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}|https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+)",
        "Slack Bot/ユーザーアクセストークンまたはIncoming Webhook URL",
        "process.env.SLACK_WEBHOOK_URL || os.environ.get('SLACK_WEBHOOK_URL')",
    ),
    (
        "Private Cryptographic Key",
        r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        "SSH / RSA / TLS 暗号化私有鍵 (Private Key)",
        "# キーファイルをリポジトリから除外して秘密情報管理システム(Vault/KMS)に配置",
    ),
    (
        "Database / Hardcoded Password",
        r"(?i)(?:db_password|database_password|api_secret|client_secret)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
        "平文のデータベース接続パスワードまたはクライアントシークレット",
        "DB_PASSWORD",
    ),
]


_TEST_DIR_NAMES = {
    "__tests__",
    "tests",
    "test",
    "__mocks__",
    "fixtures",
    "__fixtures__",
    "spec",
    "specs",
}
_PLACEHOLDER_MARKERS = (
    "example",
    "dummy",
    "your_",
    "<api_key>",
    "unit-test",
    "unittest",
    "test-",
    "test_",
    "-test",
    "_test",
    "mock",
    "fake",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "redact",
    "xxxx",
)
_KNOWN_WEAK_PASSWORDS = {"12345678", "password", "password123", "qwertyui"}


def _is_test_or_fixture_path(rel_path: str) -> bool:
    parts = [p.lower() for p in Path(rel_path).parts]
    if any(part in _TEST_DIR_NAMES for part in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    if ".test." in name or ".spec." in name:
        return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith(("_test.py", "_test.go", "test.swift", "tests.swift", "test.java", "spec.rb")):
        return True
    return False


def _is_placeholder_secret_line(line: str, raw_secret: str = "") -> bool:
    low_line = line.lower()
    low_secret = raw_secret.lower().strip()
    if any(marker in low_line for marker in _PLACEHOLDER_MARKERS):
        return True
    if "-----begin" in low_line and "..." in low_line:
        return True
    if low_secret:
        if any(marker in low_secret for marker in _PLACEHOLDER_MARKERS):
            return True
        if "..." in low_secret or re.search(r"x{4,}", low_secret):
            return True
        if low_secret in _KNOWN_WEAK_PASSWORDS or len(set(low_secret)) <= 2:
            return True
    return False


def _build_redacted_diff_removed_line(rel_path: str, stripped_line: str) -> str:
    """Never emit raw source line contents after secret detection; redact the entire line or RHS."""
    suffix = Path(rel_path).suffix.lower()
    if suffix in (".csv", ".tsv", ".env") or "," in stripped_line:
        return "- [REDACTED SECRET LINE]"
    m_assign = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_.-]{1,60})\s*([:=])\s*", stripped_line)
    if m_assign:
        key, op = m_assign.group(1), m_assign.group(2)
        return f"- {key} {op} [REDACTED]"
    return "- [REDACTED SECRET LINE]"


def _infer_env_var_name(stripped_line: str, secret_name: str, default_fix: str) -> str:
    m_lhs = re.search(r"([A-Za-z_][A-Za-z0-9_]{2,})\s*[:=]", stripped_line)
    if m_lhs:
        cand = m_lhs.group(1).upper()
        if any(k in cand for k in ("SECRET", "PASSWORD", "TOKEN", "KEY", "PASS", "AUTH")):
            return cand
    m_env = re.search(r"([A-Z][A-Z0-9_]{2,})", default_fix)
    if m_env:
        return m_env.group(1)
    return "APP_SECRET"


def _build_secret_fix_replacement(
    rel_path: str, stripped_line: str, secret_name: str, default_fix: str
) -> str:
    if secret_name == "Private Cryptographic Key":
        return default_fix
    env_var = _infer_env_var_name(stripped_line, secret_name, default_fix)
    suffix = Path(rel_path).suffix.lower()
    if suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        return f"process.env.{env_var} ?? '' // Load {env_var} from runtime environment / secret manager"
    if suffix == ".py":
        return f'os.environ.get("{env_var}", "")'
    if suffix == ".go":
        return f'os.Getenv("{env_var}")'
    if suffix == ".php":
        return f"getenv('{env_var}')"
    if suffix == ".rb":
        return f"ENV.fetch('{env_var}', '')"
    if suffix == ".swift":
        return f'ProcessInfo.processInfo.environment["{env_var}"]'
    if suffix in (".tf", ".tfvars"):
        return f"var.{env_var.lower()} # Supply via TF_VAR_{env_var.lower()} or Secrets Manager"
    if suffix in (".yml", ".yaml"):
        if ".github/workflows" in rel_path.replace("\\", "/"):
            return f"${{{{ secrets.{env_var} }}}}"
        return f"${{{env_var}}}"
    return f"# Load {env_var} from environment variable or secret manager"


_TERRAFORM_SECRET_ARN = re.compile(
    r'\s*[A-Za-z_][\w-]*\s*=\s*"\$\{(?:data\.)?aws_secretsmanager_secret'
    r'\.[A-Za-z_][\w-]*(?:\["[A-Za-z0-9/_+=.@-]+"\])?\.arn\}'
    r'(?::[A-Za-z0-9_./-]+::)?"\s*,?\s*(?:#.*|//.*)?'
)


def is_terraform_secret_arn(path: str, line: str) -> bool:
    return Path(path).suffix == ".tf" and _TERRAFORM_SECRET_ARN.fullmatch(line) is not None


def mask_detected_secret(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return "****"
    if s.startswith("sk-") or s.startswith("ghp_"):
        return f"{s[:7]}****...{s[-4:]}"
    if s.startswith("AKIA"):
        return f"{s[:6]}****...{s[-4:]}"
    if s.startswith("-----BEGIN"):
        return "-----BEGIN PRIVATE KEY [REDACTED]-----"
    return f"{s[:4]}****...{s[-4:]}"


def _normalize_secret_file_line(file_val: Any) -> Optional[Tuple[str, int]]:
    raw = str(file_val or "").split(" (Target:", 1)[0].strip()
    if ":" not in raw:
        return None
    path_part, _, line_part = raw.rpartition(":")
    if not line_part.strip().isdigit():
        return None
    norm_path = path_part.strip().replace("\\", "/").lstrip("./")
    if not norm_path:
        return None
    return (norm_path, int(line_part.strip()))


def merge_secret_and_gitleaks_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge custom secret scanner and Gitleaks hits on the same (file, line) into one record."""
    custom_by_loc: Dict[Tuple[str, int], Dict[str, Any]] = {}
    gitleaks_indices: set[int] = set()

    def _is_secondary_secret(it: Dict[str, Any]) -> bool:
        sc = str(it.get("scanner") or "").lower()
        tl = str(it.get("title") or "").lower()
        return (
            sc in ("gitleaks", "gitleaks-git", "trufflehog")
            or "[gitleaks]" in tl
            or "[gitleaks-history]" in tl
            or "[trufflehog]" in tl
        )

    def _is_primary_secret(it: Dict[str, Any]) -> bool:
        if _is_secondary_secret(it):
            return False
        return "シークレット漏洩検知" in str(it.get("title") or "") or str(it.get("category") or "").lower() == "secrets"

    for it in items:
        if not isinstance(it, dict) or not _is_primary_secret(it):
            continue
        loc = _normalize_secret_file_line(it.get("file") or it.get("path") or "")
        if loc and loc not in custom_by_loc:
            custom_by_loc[loc] = it

    # Also treat working-tree `gitleaks` hits as primary over `gitleaks-git` / `trufflehog` on the same (file, line)
    for it in items:
        if not isinstance(it, dict) or str(it.get("scanner") or "").lower() != "gitleaks":
            continue
        loc = _normalize_secret_file_line(it.get("file") or it.get("path") or "")
        if loc and loc not in custom_by_loc:
            custom_by_loc[loc] = it

    for idx, it in enumerate(items):
        if not isinstance(it, dict) or not _is_secondary_secret(it):
            continue
        loc = _normalize_secret_file_line(it.get("file") or it.get("path") or "")
        if loc and loc in custom_by_loc and custom_by_loc[loc] is not it:
            base = custom_by_loc[loc]
            sc_name = str(it.get("scanner") or "gitleaks").lower()
            detected_by = list(base.get("detected_by") or [str(base.get("scanner") or "secret_scanner")])
            if sc_name not in detected_by:
                detected_by.append(sc_name)
            base["detected_by"] = detected_by
            if it.get("official_source") and not base.get("official_source"):
                base["official_source"] = it["official_source"]
            if it.get("rule_id"):
                base["gitleaks_rule_id"] = it["rule_id"]
            gitleaks_indices.add(idx)

    return [it for idx, it in enumerate(items) if idx not in gitleaks_indices]


_ENV_SENSITIVE_KEY_RE = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|AUTH|CREDENTIAL)",
    re.IGNORECASE,
)
_ENV_CONN_WITH_CREDS_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/]+:([^@\s]+)@")
_ENV_KNOWN_KEY_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[bp]-[A-Za-z0-9-]{10,}|-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----)"
)


def _env_file_contains_sensitive_secrets(content: str) -> bool:
    """Return True if .env content contains real credentials, connection passwords, or known key formats."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _ENV_KNOWN_KEY_RE.search(line):
            return True
        m_conn = _ENV_CONN_WITH_CREDS_RE.search(line)
        if m_conn and not _is_placeholder_secret_line(line, m_conn.group(1)):
            return True
        if "=" in line:
            k_part, _, v_part = line.partition("=")
            key_name = k_part.strip().removeprefix("export ").strip()
            val = v_part.strip().strip('"').strip("'")
            if _ENV_SENSITIVE_KEY_RE.search(key_name) and val and not _is_placeholder_secret_line(line, val):
                return True
    return False


def scan_secrets_and_credentials(
    repo_dir: Path,
    match_comp: Any,
) -> List[Dict[str, Any]]:
    findings = []
    repo_path = Path(repo_dir) if not isinstance(repo_dir, Path) else repo_dir
    ignore_dirs = {
        ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
        ".next", ".venv", "venv", ".codex", "Pods", "DerivedData"
    }
    ignore_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
        ".zip", ".tar", ".gz", ".lock", ".resolved", ".map"
    }

    try:
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in ignore_dirs for part in file_path.parts):
                continue
            if file_path.suffix.lower() in ignore_exts:
                continue
            # Skip large files (> 500KB)
            try:
                if file_path.stat().st_size > 512 * 1024:
                    continue
            except Exception:
                continue

            try:
                rel_path = str(file_path.relative_to(repo_path))
            except Exception:
                rel_path = file_path.name

            low_name = file_path.name.lower()
            if (
                low_name.startswith((".env.example", "env.example", "env.e2e.example"))
                or low_name.endswith((".example", ".example.txt"))
            ):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Special check: committed .env or secret config file (2-tier based on contents)
            is_env_file = file_path.name == ".env" or file_path.name.startswith(".env.")
            is_secret_cfg = file_path.name in ("secrets.yml", "credentials.json")
            if is_env_file or is_secret_cfg:
                target_node = match_comp(rel_path)
                has_secrets = is_secret_cfg or _env_file_contains_sensitive_secrets(content)
                if has_secrets:
                    findings.append({
                        "severity": "critical",
                        "priority_tier": "P0",
                        "priority_reason": "実シークレット漏洩 / 認証ファイル露出（即時無効化が必要）",
                        "category": "secrets",
                        "title": f"🚨 [シークレット設定ファイル漏洩] `{file_path.name}` に認証情報が含まれたままコミットされています",
                        "file": f"{rel_path}:1 (Target: {target_node})",
                        "target_node": target_node,
                        "desc": f"`{rel_path}` に認証情報・APIキー・接続パスワードが含まれた状態で Git 管理下に置かれています。直ちに該当認証情報を無効化（Revoke/Rotate）し、`git rm --cached` で除外して `.gitignore` に追加してください。",
                        "diff": f"- (認証情報を含む設定ファイル: {file_path.name})\n+ (.gitignore に追加してシークレットマネージャーまたは環境変数で管理)",
                        "fix_cmd": f"git rm --cached {rel_path} && echo '{rel_path}' >> .gitignore",
                    })
                else:
                    findings.append({
                        "severity": "medium",
                        "priority_tier": "P2",
                        "priority_reason": "環境設定ファイルのGit管理（機密値未検出・.gitignore追加推奨）",
                        "category": "config",
                        "title": f"⚠️ [環境設定ファイルコミット] `{file_path.name}` が Git 管理下にあります（機密値は未検出・.gitignore 追加推奨）",
                        "file": f"{rel_path}:1 (Target: {target_node})",
                        "target_node": target_node,
                        "desc": f"`{rel_path}` がリポジトリにコミットされています。現時点でパスワードや API キーは検出されませんでしたが、将来的な誤コミット防止のため `.env.example` へのリネームと `.gitignore` 追加を推奨します。",
                        "diff": f"- (Git 管理下の環境設定: {file_path.name})\n+ (.env.example へリネームし、{file_path.name} を .gitignore に追加)",
                        "fix_cmd": f"git rm --cached {rel_path} && echo '{rel_path}' >> .gitignore",
                    })

            lines = content.splitlines()
            for line_no, line_str in enumerate(lines, start=1):
                stripped = line_str.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
                    if "-----BEGIN" not in stripped:
                        continue

                for secret_name, pattern, desc_label, fix_replacement in SECRET_PATTERNS:
                    if secret_name == "Database / Hardcoded Password" and _is_test_or_fixture_path(rel_path):
                        continue
                    m = re.search(pattern, stripped)
                    if m:
                        raw_secret = m.group(1) if m.groups() else m.group(0)
                        if _is_placeholder_secret_line(stripped, raw_secret):
                            continue
                        if secret_name == "Database / Hardcoded Password" and (
                            len(raw_secret) < 8 or is_terraform_secret_arn(rel_path, stripped)
                        ):
                            continue
                        masked = mask_detected_secret(raw_secret)
                        target_node = match_comp(rel_path)
                        safe_replacement = _build_secret_fix_replacement(
                            rel_path, stripped, secret_name, fix_replacement
                        )
                        redacted_removed = _build_redacted_diff_removed_line(rel_path, stripped)
                        findings.append({
                            "severity": "critical",
                            "priority_tier": "P0",
                            "priority_reason": "実シークレット漏洩 / 認証ファイル露出（即時無効化が必要）",
                            "category": "secrets",
                            "title": f"🚨 [シークレット漏洩検知] {secret_name} が平文でハードコードされています ({file_path.name}:{line_no})",
                            "file": f"{rel_path}:{line_no} (Target: {target_node})",
                            "target_node": target_node,
                            "desc": f"`{rel_path}` の {line_no}行目で、{desc_label}（`{masked}`）が平文で検出されました。ソースコード内に認証情報が存在すると、閲覧権限を持つ全員に漏洩し、不正利用やデータ侵害の原因となります。直ちに該当サービスでキーを無効化（Revoke/Rotate）し、環境変数または秘密情報マネージャーへ退避してください。",
                            "diff": f"{redacted_removed}\n+ {safe_replacement}",
                            "fix_cmd": f"sed -n '{max(1, line_no-2)},{line_no+2}p' {rel_path}",
                        })
                        if len(findings) >= 20:
                            return findings
                        break
    except Exception as e:
        print(f"Notice during secrets scan: {e}", file=sys.stderr)

    return findings


class SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor for Python SAST scanning (unsafe deserialization, SQLi, command injection)."""

    def __init__(self, rel_path: str, lines: List[str], target_node: str) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.target_node = target_node
        self.findings: List[Dict[str, Any]] = []

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        lineno = getattr(node, "lineno", 1)
        func_name = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Attribute):
            func_name = f"*.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # 1. Unsafe deserialization (pickle.load/loads, yaml.load without SafeLoader)
        if func_name in ("pickle.load", "pickle.loads", "cPickle.loads", "marshal.loads"):
            raw_line = self._line_text(lineno)
            self.findings.append({
                "severity": "high",
                "title": f"[Python AST監査] 安全でないデシリアライズ `{func_name}` ({Path(self.rel_path).name}:{lineno})",
                "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                "target_node": self.target_node,
                "desc": f"`{self.rel_path}` の {lineno}行目で `{func_name}` が使用されています。信頼できないデータの逆シリアライズは任意コード実行 (RCE) につながります。",
                "diff": f"- {raw_line}\n+ # Use json.loads() or validated schema parsing instead of pickle",
                "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
            })
        elif func_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and "Safe" in ast.dump(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                raw_line = self._line_text(lineno)
                self.findings.append({
                    "severity": "high",
                    "title": f"[Python AST監査] `yaml.load` の非安全ローダー使用 ({Path(self.rel_path).name}:{lineno})",
                    "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                    "target_node": self.target_node,
                    "desc": f"`{self.rel_path}` の {lineno}行目で SafeLoader を指定せずに `yaml.load` が呼ばれています。`yaml.safe_load` を使用してください。",
                    "diff": f"- {raw_line}\n+ yaml.safe_load(...)",
                    "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
                })

        # 2. SQL injection via f-string / % / .format() inside .execute()
        if func_name.endswith(".execute") and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and first_arg.func.attr == "format"
            ):
                raw_line = self._line_text(lineno)
                self.findings.append({
                    "severity": "high",
                    "title": f"[Python SQLi監査] 動的文字列フォーマットによるSQL実行 ({Path(self.rel_path).name}:{lineno})",
                    "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                    "target_node": self.target_node,
                    "desc": f"`{self.rel_path}` の {lineno}行目で SQL クエリ文字列が直接フォーマット結合されています。プレースホルダによるパラメータバインディングを使用してください。",
                    "diff": f"- {raw_line}\n+ cursor.execute('SELECT * FROM table WHERE id = ?', (param,))",
                    "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
                })

        # 3. Arbitrary code execution via eval() / exec() or subprocess with shell=True
        if func_name in ("eval", "exec"):
            raw_line = self._line_text(lineno)
            self.findings.append({
                "severity": "high",
                "title": f"[Python AST監査] 危険な動的コード実行 `{func_name}()` ({Path(self.rel_path).name}:{lineno})",
                "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                "target_node": self.target_node,
                "desc": f"`{self.rel_path}` の {lineno}行目で `{func_name}()` が使用されています。外部入力が渡されると任意コード実行 (RCE) につながるため、`ast.literal_eval()` または安全なパーサーに置き換えてください。",
                "diff": f"- {raw_line}\n+ ast.literal_eval(...)",
                "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
            })
        elif func_name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            raw_line = self._line_text(lineno)
            self.findings.append({
                "severity": "high",
                "title": f"[Python AST監査] `shell=True` によるコマンドインジェクションリスク ({Path(self.rel_path).name}:{lineno})",
                "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                "target_node": self.target_node,
                "desc": f"`{self.rel_path}` の {lineno}行目で `{func_name}(..., shell=True)` が使用されています。引数配列と `shell=False` を使用してください。",
                "diff": f"- {raw_line}\n+ subprocess.run(['cmd', 'arg'], shell=False, check=True)",
                "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
            })

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        lineno = getattr(node, "lineno", 1)
        is_empty_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if node.type is None and is_empty_pass:
            raw_line = self._line_text(lineno)
            self.findings.append({
                "severity": "medium",
                "title": f"[Python AST監査] 空の `except: pass` による例外握りつぶし ({Path(self.rel_path).name}:{lineno})",
                "file": f"{self.rel_path}:{lineno} (Target: {self.target_node})",
                "target_node": self.target_node,
                "desc": f"`{self.rel_path}` の {lineno}行目で裸の `except:` と `pass` により例外が完全に握りつぶされています。具体的な例外型を捕捉しログ出力を行ってください。",
                "diff": f"- {raw_line}\n+ except Exception as exc:\n+     logger.warning('Handled error: %s', exc)",
                "fix_cmd": f"sed -n '{max(1, lineno-2)},{lineno+2}p' {self.rel_path}",
            })
        self.generic_visit(node)


def scan_php_and_nodejs_and_polyglot_vulnerabilities(
    repo_dir: Path,
    components: List[Dict[str, Any]],
    force_sast: bool = False,
) -> Dict[str, Any]:
    """
    Security-Review Skill + Runtime EOL Scanner + OSV.dev Package CVE Scanner
    for PHP, Node.js/TypeScript, Python, Swift, Go, and Rust.
    """
    settings = load_settings()
    skills_cfg = dict(settings.get("skills", DEFAULT_SETTINGS["skills"]))
    if force_sast:
        skills_cfg["owasp_sast_skill"] = True

    frameworks: List[Dict[str, str]] = []
    databases: List[Dict[str, str]] = []
    ai_sdks: List[Dict[str, str]] = []
    security_advisories: List[Dict[str, Any]] = []
    sast_findings: List[Dict[str, Any]] = []
    osv_query_list: List[Tuple[str, str, str]] = []
    runtime_info: Dict[str, str] = {}

    ignore_dirs = {
        ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
        ".next", ".venv", "venv", ".codex"
    }

    def match_comp(rel_file: str) -> str:
        for c in components:
            if rel_file.startswith(c["path"].rstrip("/")) or rel_file in c.get("files", []):
                return c["name"]
        for c in components:
            if c.get("layer") == "service":
                return c["name"]
        return components[0]["name"] if components else "Core Service"

    # =========================================================================
    # 1. PHP & Composer Vulnerability & Runtime Audit (composer.json / *.php)
    # =========================================================================
    composer_json = repo_dir / "composer.json"
    php_files = [p for p in repo_dir.rglob("*.php") if not any(part in ignore_dirs for part in p.parts)]
    if composer_json.exists() or php_files:
        runtime_info["php"] = "PHP (version not declared)"
        if composer_json.exists():
            try:
                cdata = json.loads(composer_json.read_text(encoding="utf-8", errors="ignore"))
                req_all = {}
                req_all.update(cdata.get("require") or {})
                req_all.update(cdata.get("require-dev") or {})

                php_ver = str(req_all.get("php", ""))
                if php_ver:
                    runtime_info["php"] = f"PHP {php_ver}"
                    frameworks.append({
                        "name": "PHP Runtime Engine",
                        "version": php_ver,
                        "status": "info",
                        "desc": "Composer の互換性要件。稼働版は別途確認してください。",
                        "security_link": "https://www.php.net/supported-versions.php",
                    })

                for pkg_name, ver in req_all.items():
                    if pkg_name == "php" or pkg_name.startswith("ext-"):
                        continue
                    osv_query_list.append(("Packagist", pkg_name, str(ver)))
                    if any(k in pkg_name for k in ("laravel", "symfony", "guzzle", "wordpress", "monolog", "slim", "cakephp", "yii")):
                        frameworks.append({
                            "name": f"Composer: {pkg_name}",
                            "version": str(ver).lstrip("^~"),
                            "status": "latest",
                            "desc": "PHP Composer パッケージ",
                            "security_link": f"https://packagist.org/packages/{pkg_name}",
                        })
            except Exception:
                pass

        # Scan PHP source files for OWASP Top 10 vulnerabilities
        if skills_cfg.get("owasp_sast_skill", True):
            for pf in php_files[:40]:
                rel_p = str(pf.relative_to(repo_dir))
                try:
                    lines = pf.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    continue
                for idx, line in enumerate(lines, start=1):
                    s = line.strip()
                    # RCE / Command injection in PHP
                    if re.search(r"\b(eval|shell_exec|passthru|system|unserialize)\s*\(", s):
                        tnode = match_comp(rel_p)
                        sast_findings.append({
                            "severity": "high",
                            "title": f"[PHP脆弱性監査] 危険な動的実行・コマンド実行関数 ({pf.name}:{idx})",
                            "file": f"{rel_p}:{idx} (Target: {tnode})",
                            "target_node": tnode,
                            "desc": f"`{rel_p}` の {idx}行目で `eval / shell_exec / system / unserialize` が使用されています。外部入力が混入すると任意コード実行 (RCE) 脆弱性に直結するため、安全なAPIまたは `escapeshellarg()` / JSON への置換が必要です。",
                            "diff": f"- {s}\n+ // Security Fix: Avoid raw shell_exec/eval/unserialize; use safe parameterized API",
                            "fix_cmd": f"sed -n '{max(1, idx-2)},{idx+2}p' {rel_p}",
                        })
                        break
                    # SQL Injection in PHP
                    if re.search(r"(mysqli_query|->query)\s*\(.*\$_(GET|POST|REQUEST)", s):
                        tnode = match_comp(rel_p)
                        sast_findings.append({
                            "severity": "high",
                            "title": f"[PHP SQLi監査] 未エスケープ入力の直接SQLクエリ結合 ({pf.name}:{idx})",
                            "file": f"{rel_p}:{idx} (Target: {tnode})",
                            "target_node": tnode,
                            "desc": f"`{rel_p}` の {idx}行目で `$_GET / $_POST` パラメータが SQL クエリに直接結合されており、SQLインジェクションの危険があります。PDO プリペアドステートメント (`prepare` + `execute`) に置き換えてください。",
                            "diff": f"- {s}\n+ $stmt = $pdo->prepare('SELECT * FROM table WHERE id = :id');\n+ $stmt->execute([':id' => $_POST['id'] ?? '']);",
                            "fix_cmd": f"sed -n '{max(1, idx-2)},{idx+2}p' {rel_p}",
                        })
                        break
                    # XSS in PHP
                    if re.search(r"\becho\b.*\$_(GET|POST|REQUEST)", s) and "htmlspecialchars" not in s:
                        tnode = match_comp(rel_p)
                        sast_findings.append({
                            "severity": "high",
                            "title": f"[PHP XSS監査] 未サニタイズ出力によるクロスサイトスクリプティング ({pf.name}:{idx})",
                            "file": f"{rel_p}:{idx} (Target: {tnode})",
                            "target_node": tnode,
                            "desc": f"`{rel_p}` の {idx}行目でユーザー入力が `htmlspecialchars()` を介さず直接 `echo` 出力されています。反射型XSS攻撃を防ぐため必ずエスケープ処理を適用してください。",
                            "diff": f"- {s}\n+ echo htmlspecialchars((string)($_GET['param'] ?? ''), ENT_QUOTES, 'UTF-8');",
                            "fix_cmd": f"sed -n '{max(1, idx-2)},{idx+2}p' {rel_p}",
                        })
                        break

    # =========================================================================
    # 2. Node.js / TypeScript / npm Audit (package.json)
    # =========================================================================
    pkg_json = repo_dir / "package.json"
    if pkg_json.exists():
        try:
            pdata = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            engines = pdata.get("engines") or {}
            if engines.get("node"):
                runtime_info["node"] = str(engines["node"])

            all_deps = {}
            all_deps.update(pdata.get("dependencies") or {})
            all_deps.update(pdata.get("devDependencies") or {})
            for k, v in all_deps.items():
                osv_query_list.append(("npm", k, str(v)))
        except Exception as exc:
            print(f"Warning: failed to parse package.json: {exc}", file=sys.stderr)

    pkg_lock = repo_dir / "package-lock.json"
    if pkg_lock.exists():
        try:
            ldata = json.loads(pkg_lock.read_text(encoding="utf-8", errors="ignore"))
            packages_obj = ldata.get("packages") or {}
            for pkg_path, meta in list(packages_obj.items())[:60]:
                if not pkg_path or not isinstance(meta, dict):
                    continue
                ver = str(meta.get("version") or "").strip()
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                if name and ver:
                    osv_query_list.append(("npm", name, ver))
        except Exception:
            pass

    # =========================================================================
    # 3. Python / Go / Rust OSV Queue & Python AST Security Visitor
    # =========================================================================
    req_txt = repo_dir / "requirements.txt"
    if req_txt.exists():
        for ln in req_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([0-9A-Za-z\.\-]+)", ln)
            if m:
                osv_query_list.append(("PyPI", m.group(1), m.group(2)))

    if skills_cfg.get("owasp_sast_skill", True):
        py_files = [
            p for p in repo_dir.rglob("*.py")
            if not any(part in ignore_dirs or part == "tests" for part in p.relative_to(repo_dir).parts)
            and not p.name.startswith("test_")
        ]
        for pyf in py_files[:40]:
            rel_py = str(pyf.relative_to(repo_dir))
            try:
                src_py = pyf.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(src_py, filename=rel_py)
                visitor = SecurityASTVisitor(rel_py, src_py.splitlines(), match_comp(rel_py))
                visitor.visit(tree)
                sast_findings.extend(visitor.findings)
            except Exception:
                continue

    # =========================================================================
    # 4. Execute Live OSV.dev Vulnerability Database Query
    # =========================================================================
    if skills_cfg.get("osv_mcp", True) and osv_query_list:
        osv_advisories = query_osv_batch(osv_query_list)
        security_advisories.extend(osv_advisories)

    # =========================================================================
    # 5. Scan GitHub Actions Workflows & Hardcoded Secrets
    # =========================================================================
    workflow_scan = {"scanner": None, "status": "disabled"}
    if skills_cfg.get("owasp_sast_skill", True):
        files = workflow_files(Path(repo_dir))
        gha_findings, status = run_zizmor(files, match_comp)
        actionlint_findings, actionlint_status = run_actionlint(files, match_comp)
        builtin_findings = scan_github_actions_workflows(repo_dir, match_comp)

        def _loc_key(item: Dict[str, Any]) -> str:
            return str(item.get("file") or "").split(" (", 1)[0]

        seen_wf_locs = set()
        for src_list in (gha_findings or [], actionlint_findings or [], builtin_findings):
            for item in src_list:
                loc = _loc_key(item)
                key = (item.get("rule_id"), loc)
                # Deduplicate identical rule+location or same workflow line already flagged by a stronger scanner
                if key in seen_wf_locs or (src_list is not (gha_findings or []) and loc in {k[1] for k in seen_wf_locs}):
                    continue
                seen_wf_locs.add(key)
                sast_findings.append(item)

        active_wf_scanners = []
        if files:
            active_wf_scanners.append("builtin")
        if status == "complete":
            active_wf_scanners.append("zizmor")
        if actionlint_status == "complete":
            active_wf_scanners.append("actionlint")
        scanner = "+".join(active_wf_scanners) if active_wf_scanners else None
        workflow_scan = {"scanner": scanner, "status": status, "actionlint_status": actionlint_status}

    source_findings, source_scan = scan_source(
        Path(repo_dir), match_comp, include_quality=skills_cfg.get("owasp_sast_skill", True)
    )
    ext_sast_findings, trivy_advisories, ext_scan = scan_semgrep_and_trivy(
        Path(repo_dir),
        match_comp,
        include_sast=skills_cfg.get("owasp_sast_skill", True),
        include_vuln=skills_cfg.get("osv_mcp", True),
    )
    extended_findings, extended_scan = scan_extended_security(
        Path(repo_dir),
        match_comp,
        include_sast=skills_cfg.get("owasp_sast_skill", True),
    )
    if trivy_advisories:
        existing_cves = {
            (str(a.get("cve") or "").upper(), str(a.get("pkg") or "").lower())
            for a in security_advisories
        }
        for adv in trivy_advisories:
            cve_key = (str(adv.get("cve") or "").upper(), str(adv.get("pkg") or "").lower())
            if cve_key not in existing_cves:
                existing_cves.add(cve_key)
                security_advisories.append(adv)

    runtime_findings, runtime_patch_scan = ([], {"status": "disabled"})
    if skills_cfg.get("php_node_runtime_audit", True):
        runtime_findings, runtime_patch_scan = scan_runtime_patches(Path(repo_dir), match_comp)
    secret_findings = scan_secrets_and_credentials(repo_dir, match_comp)

    combined_sast = secret_findings + runtime_findings + source_findings + ext_sast_findings + extended_findings + sast_findings
    deduped_sast: List[Dict[str, Any]] = []
    seen_sast_locs = set()
    for item in combined_sast:
        loc = str(item.get("file") or "").split(" (", 1)[0]
        key = (loc, str(item.get("rule_id") or ""))
        if key in seen_sast_locs:
            continue
        seen_sast_locs.add(key)
        deduped_sast.append(item)
    sast_findings = merge_secret_and_gitleaks_findings(deduped_sast)
    source_scan = {**source_scan, **ext_scan, **extended_scan}
    security_advisories = enrich_advisories_with_epss(security_advisories)

    extracted_versions = extract_repo_runtime_and_framework_versions(Path(repo_dir))
    merged_runtime = {**extracted_versions, **runtime_info}
    runtime_eol = evaluate_runtime_eol(merged_runtime) if merged_runtime else []
    for eol_item in runtime_eol:
        if eol_item.get("is_eol"):
            prod = eol_item["product"]
            cyc = eol_item["cycle"]
            eol_date = eol_item.get("eol")
            latest_cyc = eol_item.get("latest_active_cycle") or "latest"
            sev_eol = "high" if eol_item.get("eol_over_1y") else "medium"
            sast_findings.append({
                "severity": sev_eol,
                "category": "eol",
                "title": f"[EOL検出] {prod} {cyc} はサポート終了済みです (EOL: {eol_date})",
                "file": f"package.json / Dockerfile (Target: {match_comp('package.json')})",
                "target_node": match_comp("package.json"),
                "desc": (
                    f"`{prod}` の宣言バージョン `{eol_item.get('declared')}` (サイクル `{cyc}`) は {eol_date} にサポート終了 (EOL) しています。"
                    f"セキュリティパッチが提供されないため、サポート中の `{latest_cyc}` 系へのアップグレードを推奨します。"
                ),
                "official_source": f"https://endoflife.date/{prod}",
            })

    return {
        "frameworks": frameworks,
        "databases": databases,
        "ai_sdks": ai_sdks,
        "runtime": runtime_info,
        "runtime_eol": runtime_eol,
        "security_advisories": security_advisories,
        "sast_findings": sast_findings,
        "workflow_scan": workflow_scan,
        "source_scan": source_scan,
        "license_summary": ext_scan.get("license_summary", {}),
        "runtime_patch_scan": runtime_patch_scan,
    }


def scan_github_actions_workflows(
    repo_dir: Path,
    match_comp: Any,
) -> List[Dict[str, Any]]:
    """
    Audit GitHub Actions workflows (.github/workflows/*.yml, *.yaml) for OWASP CI/CD
    and zizmor/actionlint security anti-patterns:
      1. Script injection via untrusted ${{ github.event.* }} / ${{ github.head_ref }} in `run:`
      2. Privileged `pull_request_target` combined with untrusted PR head checkout (Pwn Request)
      3. Over-privileged `permissions: write-all`
      4. Unpinned third-party Action mutable branch references (`@main`, `@master`, `@HEAD`)
    """
    findings: List[Dict[str, Any]] = []

    unpinned_uses_re = re.compile(
        r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(main|master|HEAD|develop)\b"
    )

    for wf in workflow_files(Path(repo_dir))[:MAX_FILES]:
        rel_path = str(wf.relative_to(repo_dir))
        try:
            raw = read_small_file(wf)
            if raw is None:
                continue
            content = raw.decode("utf-8", errors="ignore")
            lines = content.splitlines()
        except OSError:
            continue

        tnode = match_comp(rel_path)
        has_pr_target = bool(re.search(r"\bpull_request_target\b", content))

        # 1. Script injection via ${{ github.event.* }} in executable contexts only
        for inj in find_template_injections_in_workflow(content):
            inj_idx = inj["line_no"]
            expr = inj["expr"]
            item: Dict[str, Any] = {
                "severity": "critical",
                "rule_id": "template-injection",
                "title": f"🚨 [GitHub Actions監査] `${{{{ ... }}}}` によるシェルインジェクションリスク ({wf.name}:{inj_idx})",
                "file": f"{rel_path}:{inj_idx} (Target: {tnode})",
                "target_node": tnode,
                "desc": f"`{rel_path}` の {inj_idx}行目で外部入力由来のコンテキスト式 `{expr}` が直接展開されています。PRタイトルやブランチ名にシェルメタ文字が含まれると任意コマンド実行 (RCE) につながるため、{inj['remediation']}",
                "remediation": inj["remediation"],
                "fix_cmd": f"sed -n '{max(1, inj_idx-2)},{inj_idx+2}p' {rel_path}",
            }
            if inj["diff"]:
                item["diff"] = inj["diff"]
            findings.append(item)

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 2. Pwn request: pull_request_target + checkout of PR head
            if has_pr_target and "github.event.pull_request.head" in stripped and ("ref:" in stripped or "sha" in stripped):
                findings.append({
                    "severity": "critical",
                    "rule_id": "dangerous-triggers",
                    "title": f"🚨 [GitHub Actions Pwn Request] `pull_request_target` での外部ForkコードCheckout ({wf.name}:{idx})",
                    "file": f"{rel_path}:{idx} (Target: {tnode})",
                    "target_node": tnode,
                    "desc": f"`{rel_path}` は特権トークン・Secretsアクセス権を持つ `pull_request_target` トリガーを使用しながら、{idx}行目で信頼できない外部PRのHEADを直接チェックアウトしています。シークレット漏洩やリポジトリ乗っ取りに直結します。",
                    "diff": f"- {stripped}\n+ # Avoid checking out untrusted PR head inside pull_request_target",
                    "fix_cmd": f"sed -n '{max(1, idx-3)},{idx+3}p' {rel_path}",
                })

            # 3. Over-privileged permissions: write-all
            if re.match(r"^permissions:\s*write-all\b", stripped, re.IGNORECASE):
                findings.append({
                    "severity": "high",
                    "rule_id": "excessive-permissions",
                    "title": f"[GitHub Actions監査] 過剰なトークン権限 `permissions: write-all` ({wf.name}:{idx})",
                    "file": f"{rel_path}:{idx} (Target: {tnode})",
                    "target_node": tnode,
                    "desc": f"`{rel_path}` の {idx}行目で `GITHUB_TOKEN` に `write-all` が付与されています。最小権限の原則に従い `contents: read` 等を明示してください。",
                    "diff": f"- {stripped}\n+ permissions:\n+   contents: read",
                    "fix_cmd": f"sed -n '{max(1, idx-1)},{idx+3}p' {rel_path}",
                })

            # 4. Unpinned mutable branch in third-party action
            m_unpin = unpinned_uses_re.match(line)
            if m_unpin and not m_unpin.group(1).startswith("actions/"):
                action_slug, branch_ref = m_unpin.group(1), m_unpin.group(2)
                findings.append({
                    "severity": "medium",
                    "rule_id": "unpinned-uses",
                    "title": f"[GitHub Actions監査] サードパーティActionの未固定ブランチ参照 `{action_slug}@{branch_ref}` ({wf.name}:{idx})",
                    "file": f"{rel_path}:{idx} (Target: {tnode})",
                    "target_node": tnode,
                    "desc": f"`{rel_path}` の {idx}行目でサードパーティActionが可変ブランチ `@{branch_ref}` で参照されています。サプライチェーン攻撃防止のためフルコミットSHAまたはリリースタグに固定してください。",
                    "diff": f"- {stripped}\n+ uses: {action_slug}@<commit-sha-or-release-tag>",
                    "fix_cmd": f"sed -n '{max(1, idx-1)},{idx+2}p' {rel_path}",
                })

    return findings


def generate_cyclonedx_sbom(diagram_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an industry-standard CycloneDX 1.5 JSON Software Bill of Materials (SBOM)
    with Package URLs (purl) and embedded vulnerability advisories + EPSS scores.
    """
    repo_name = str(diagram_item.get("repo") or "repository")
    github_url = str(diagram_item.get("github_url") or "")
    deps = diagram_item.get("deps") or {}
    components: List[Dict[str, Any]] = []
    seen_purls = set()

    def _add_comp(name: str, version: str, comp_type: str, eco: str, desc: str = "") -> None:
        clean_name = re.sub(r"\s*\(.*?\)\s*$", "", str(name)).replace("Composer: ", "").strip()
        clean_ver = re.sub(r"^[\^~>=<v\s]+", "", str(version)).split(" ")[0].strip() or "latest"
        purl = f"pkg:{eco}/{clean_name}@{clean_ver}"
        if purl in seen_purls:
            return
        seen_purls.add(purl)
        components.append({
            "type": comp_type,
            "bom-ref": purl,
            "name": clean_name,
            "version": clean_ver,
            "purl": purl,
            "description": desc,
        })

    for fw in deps.get("frameworks") or []:
        if isinstance(fw, dict):
            fname = str(fw.get("name") or "")
            eco = "composer" if "composer" in fname.lower() or "php" in fname.lower() else "npm"
            _add_comp(fname, str(fw.get("version") or "latest"), "framework", eco, str(fw.get("desc") or ""))

    for db in deps.get("databases") or []:
        if isinstance(db, dict):
            _add_comp(str(db.get("name") or ""), str(db.get("version") or "latest"), "library", "generic", str(db.get("desc") or ""))

    for ai in deps.get("ai_sdks") or []:
        if isinstance(ai, dict):
            _add_comp(str(ai.get("name") or ""), str(ai.get("version") or "latest"), "library", "npm", str(ai.get("desc") or ""))

    vulnerabilities: List[Dict[str, Any]] = []
    for adv in deps.get("security_advisories") or []:
        if not isinstance(adv, dict):
            continue
        vid = str(adv.get("cve") or adv.get("id") or "VULN")
        ratings = [{"severity": str(adv.get("severity") or "HIGH").lower(), "method": "other"}]
        if adv.get("epss") is not None:
            ratings.append({
                "score": float(adv["epss"]),
                "severity": "high" if float(adv["epss"]) >= 0.1 else "medium",
                "method": "other",
            })
        vulnerabilities.append({
            "id": vid,
            "source": {"name": "OSV / NVD / FIRST EPSS"},
            "ratings": ratings,
            "description": str(adv.get("summary") or adv.get("title") or ""),
            "advisories": [{"title": s.get("name", ""), "url": s.get("url", "")} for s in (adv.get("sources") or []) if isinstance(s, dict)],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "RepoAUDT Mac", "name": "RepoAUDT Mac Security & Architecture Studio", "version": "1.2.0"}],
            "component": {
                "type": "application",
                "name": repo_name,
                "version": str(diagram_item.get("commit_hash") or "HEAD"),
                "externalReferences": [{"type": "vcs", "url": github_url}] if github_url else [],
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def generate_sarif_report(diagram_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a GitHub Code Scanning compatible SARIF 2.1.0 JSON report from
    a repository's CodeRabbit / OWASP SAST action items and CVE advisories.
    """
    repo_name = str(diagram_item.get("repo") or "repository")
    cr = diagram_item.get("coderabbit") or {}
    deps = diagram_item.get("deps") or {}
    action_items = list(cr.get("action_items") or []) + list(cr.get("findings") or [])
    advisories = list(deps.get("security_advisories") or [])

    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules = set()

    for idx, item in enumerate(action_items, start=1):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("cve") or f"REPOAUDT-SAST-{idx:03d}")
        sev = str(item.get("severity") or "high").lower()
        sarif_level = "error" if sev in ("critical", "high") else ("warning" if sev == "medium" else "note")
        sec_score = "9.0" if sev == "critical" else ("7.5" if sev == "high" else "5.0")

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": re.sub(r"[^A-Za-z0-9_]", "", str(item.get("title") or rule_id))[:48] or f"Rule{idx}",
                "shortDescription": {"text": str(item.get("title") or rule_id)},
                "fullDescription": {"text": str(item.get("desc") or item.get("title") or "")},
                "defaultConfiguration": {"level": sarif_level},
                "properties": {"security-severity": sec_score},
            })

        raw_file = str(item.get("file") or "README.md").split(" (Target:")[0].strip()
        uri_part = raw_file
        start_line = 1
        if ":" in raw_file:
            parts = raw_file.rsplit(":", 1)
            uri_part = parts[0].strip() or "README.md"
            try:
                start_line = max(1, int(re.sub(r"[^0-9]", "", parts[1]) or "1"))
            except ValueError:
                start_line = 1

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": f"[{repo_name}] {item.get('title', '')}: {item.get('desc', '')}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri_part.lstrip("/")},
                        "region": {"startLine": start_line, "startColumn": 1},
                    }
                }
            ],
        })

    for idx, adv in enumerate(advisories, start=1):
        if not isinstance(adv, dict):
            continue
        rule_id = str(adv.get("cve") or f"REPOAUDT-CVE-{idx:03d}")
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": re.sub(r"[^A-Za-z0-9_]", "", str(adv.get("title") or rule_id))[:48] or f"CveRule{idx}",
            "shortDescription": {"text": str(adv.get("title") or rule_id)},
            "fullDescription": {"text": str(adv.get("summary") or "")},
            "defaultConfiguration": {"level": "error"},
            "properties": {"security-severity": "8.0"},
        })
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": f"{adv.get('title', rule_id)}: {adv.get('summary', '')}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "package.json"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoAUDT Mac Security & SAST Engine",
                        "version": "1.2.0",
                        "informationUri": "https://github.com/nanonigit/RepoAUDT-Mac",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def choose_active_llm(settings: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    """
    Return (provider, api_key, model) if an API key is configured and LLM audit is enabled.
    """
    if not settings.get("skills", {}).get("llm_deep_audit", True):
        return None

    pref = settings.get("active_provider", "auto")
    if pref == "none":
        return None
    keys = settings.get("keys", {})
    models = settings.get("models", DEFAULT_SETTINGS["models"])

    if pref == "local":
        model = str(models.get("local", "")).strip()
        return ("local", keys.get("local", ""), model) if model else None

    if pref == "copilot":
        model = str(models.get("copilot") or DEFAULT_SETTINGS["models"]["copilot"]).strip()
        token = (keys.get("copilot") or "").strip()
        if token or copilot_bridge.is_copilot_ready():
            return ("copilot", token, model)
        return None

    if pref == "gemini_cli":
        model = str(models.get("gemini_cli") or DEFAULT_SETTINGS["models"]["gemini_cli"]).strip()
        token = (keys.get("gemini_cli") or "").strip()
        if token or gemini_cli_bridge.is_gemini_cli_ready():
            return ("gemini_cli", token, model)
        return None

    order = [pref] if pref in ("openai", "claude", "gemini", "groq") else ["openai", "claude", "gemini", "groq"]
    for prov in order:
        k = (keys.get(prov) or "").strip()
        if k and len(k) >= 8:
            return prov, k, models.get(prov, DEFAULT_SETTINGS["models"][prov])
    return None


def choose_secondary_llm(settings: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    """Resolve optional second-opinion AI provider for finding cross-checking."""
    sec = str(settings.get("secondary_provider") or "none").strip()
    if not sec or sec == "none":
        return None
    keys = settings.get("keys", {})
    models = settings.get("models", DEFAULT_SETTINGS["models"])
    override_model = str(settings.get("secondary_model") or "").strip()
    model = override_model or str(models.get(sec) or DEFAULT_SETTINGS["models"].get(sec, "")).strip()

    if sec == "local":
        return ("local", keys.get("local", ""), model) if model else None
    if sec == "copilot":
        token = (keys.get("copilot") or "").strip()
        if token or copilot_bridge.is_copilot_ready():
            return ("copilot", token, model or "auto")
        return None
    if sec == "gemini_cli":
        token = (keys.get("gemini_cli") or "").strip()
        if token or gemini_cli_bridge.is_gemini_cli_ready():
            return ("gemini_cli", token, model or "auto")
        return None
    k = (keys.get(sec) or "").strip()
    if k and len(k) >= 8:
        return (sec, k, model)
    return None


_CROSS_CHECK_SYSTEM_PROMPT = """You are a senior application security auditor verifying whether a reported finding is genuinely exploitable in the actual codebase.
Return ONLY valid JSON with these exact keys:
{
  "verdict": "confirmed" | "likely_false_positive" | "needs_review",
  "confidence": "high" | "medium" | "low",
  "summary": "Concise 2-3 sentence evidence-based explanation in Japanese",
  "action": "Concrete next step in Japanese"
}
Rules:
- Never fabricate code or config you did not see.
- If the code context is insufficient to prove exploitability, use "needs_review".
- Never output raw secrets or credentials."""


def _parse_verdict_json(raw_text: str) -> Dict[str, str]:
    txt = (raw_text or "").strip()
    if "```" in txt:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", txt, re.DOTALL)
        if m:
            txt = m.group(1)
    elif "{" in txt and "}" in txt:
        txt = txt[txt.find("{"):txt.rfind("}") + 1]
    try:
        data = json.loads(txt)
        if isinstance(data, dict):
            verdict = str(data.get("verdict") or "needs_review").strip().lower()
            if verdict not in ("confirmed", "likely_false_positive", "needs_review"):
                verdict = "needs_review"
            conf = str(data.get("confidence") or "medium").strip().lower()
            if conf not in ("high", "medium", "low"):
                conf = "medium"
            return {
                "verdict": verdict,
                "confidence": conf,
                "summary": str(data.get("summary") or raw_text[:280]).strip(),
                "action": str(data.get("action") or "").strip(),
            }
    except Exception:
        pass
    return {
        "verdict": "needs_review",
        "confidence": "low",
        "summary": (raw_text or "").strip()[:300],
        "action": "",
    }


def cross_check_finding(
    repo: str,
    finding: Dict[str, Any],
    *,
    code_context: str = "",
    settings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a single finding using primary AI and optional second-opinion AI in parallel.

    Works cleanly even when AI is disabled (`active_provider == 'none'`): returns
    a static-only result without making any external AI call.
    """
    from concurrent.futures import ThreadPoolExecutor

    s = settings if isinstance(settings, dict) else load_settings()
    primary = choose_active_llm(s)
    secondary = choose_secondary_llm(s)

    if primary is None and secondary is None:
        return {
            "ok": True,
            "mode": "static_only",
            "consensus": "static_only",
            "consensus_label": "AI 無効（静的解析のみ）",
            "primary": None,
            "secondary": None,
            "note": "AI 接続が「使用しない（静的解析のみ）」または未設定のため、AI クロスチェックは実行していません。",
        }

    title = str(finding.get("title") or "")
    file_loc = str(finding.get("file") or "")
    tier = str(finding.get("tier") or finding.get("priority_tier") or "")
    reason = str(finding.get("reason") or finding.get("priority_reason") or "")
    desc = str(finding.get("description") or finding.get("desc") or "")

    user_prompt = (
        f"Repository: {repo}\n"
        f"Priority: {tier}\n"
        f"Title: {title}\n"
        f"File: {file_loc}\n"
        f"Reason: {reason}\n"
        f"Details: {desc[:800]}\n"
    )
    if code_context.strip():
        user_prompt += f"\nActual redacted code snippet from repository:\n```\n{code_context[:2500]}\n```\n"

    def _run_one(spec: Tuple[str, str, str]) -> Dict[str, Any]:
        prov, key, mod = spec
        try:
            raw = call_llm_provider(prov, key, mod, _CROSS_CHECK_SYSTEM_PROMPT, user_prompt)
            parsed = _parse_verdict_json(raw)
            return {
                "ok": True,
                "provider": prov,
                "model": mod or "auto",
                **parsed,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": prov,
                "model": mod or "auto",
                "verdict": "error",
                "confidence": "low",
                "summary": str(exc)[:300],
                "action": "",
            }

    prim_res = None
    sec_res = None
    if primary and secondary:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_run_one, primary)
            f2 = pool.submit(_run_one, secondary)
            prim_res = f1.result()
            sec_res = f2.result()
    elif primary:
        prim_res = _run_one(primary)
    elif secondary:
        sec_res = _run_one(secondary)

    v1 = prim_res.get("verdict") if isinstance(prim_res, dict) and prim_res.get("ok") else None
    v2 = sec_res.get("verdict") if isinstance(sec_res, dict) and sec_res.get("ok") else None

    if v1 and v2:
        if v1 == v2 == "confirmed":
            consensus, label = "agreed_confirmed", "2 AI 一致：実コードで要対応"
        elif v1 == v2 == "likely_false_positive":
            consensus, label = "agreed_false_positive", "2 AI 一致：誤検知・影響なし"
        elif v1 == v2:
            consensus, label = "agreed_needs_review", "2 AI 一致：要追加確認"
        else:
            consensus, label = "disagreed", "意見不一致：目視確認を推奨"
        mode = "dual_ai"
    elif v1 or v2:
        sole = v1 or v2
        consensus = f"single_{sole}"
        label = (
            "単一 AI：実コードで要対応"
            if sole == "confirmed"
            else ("単一 AI：誤検知・影響なし" if sole == "likely_false_positive" else "単一 AI：要追加確認")
        )
        mode = "single_ai"
    else:
        consensus, label, mode = "error", "AI 検証エラー", "error"

    return {
        "ok": True,
        "mode": mode,
        "consensus": consensus,
        "consensus_label": label,
        "primary": prim_res,
        "secondary": sec_res,
    }


def is_openai_reasoning_or_nextgen_model(model: str) -> bool:
    m = (model or "").lower()
    return any(
        m.startswith(prefix) or k in m
        for prefix in ("gpt-5", "gpt-6", "o1", "o3", "o4")
        for k in ("luna", "sol", "terra", "astra", "codex", "gpt-5", "gpt-6", "o1", "o3", "o4")
    )


def call_llm_provider(provider: str, api_key: str, model: str, system_prompt: str, user_prompt: str) -> str:
    """
    Call OpenAI, Anthropic Claude, Google Gemini, or Groq REST API using stdlib urllib.
    Supports next-gen / reasoning models (`gpt-6-luna`, `gpt-5.6-luna`, `gpt-6.1-sol`, `o3-mini`, etc.)
    which reject non-default `temperature` and require `max_completion_tokens` or `/v1/responses`.
    """
    if provider == "copilot":
        return copilot_bridge.call_copilot_sync(
            model=model or DEFAULT_SETTINGS["models"]["copilot"],
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            github_token=api_key,
        )

    if provider == "gemini_cli":
        return gemini_cli_bridge.call_gemini_cli_sync(
            model=model or DEFAULT_SETTINGS["models"]["gemini_cli"],
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            api_key=api_key,
        )

    if provider == "local":
        settings = load_settings()
        base = validate_endpoint(settings.get("local_base_url", DEFAULT_SETTINGS["local_base_url"]), local_only=True)
        if not model.strip():
            raise ValueError("Enter the local model identifier first")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = "Bearer " + api_key
        request = urllib.request.Request(base + "/chat/completions", data=json.dumps({
            "model": model, "stream": False,
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        }).encode(), headers=headers, method="POST")
        with open_endpoint(request, timeout=120) as response:
            result = json.loads(response.read(2 * 1024 * 1024))
        text = result["choices"][0]["message"]["content"]
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Local LLM returned an empty completion")
        return text

    if provider in ("openai", "groq"):
        url = (
            "https://api.openai.com/v1/chat/completions"
            if provider == "openai"
            else "https://api.groq.com/openai/v1/chat/completions"
        )
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        if provider == "openai" and is_openai_reasoning_or_nextgen_model(model):
            # OpenAI reasoning models (gpt-6-luna, gpt-5.6-luna, o1/o3/o4) reject temperature != 1
            payload["max_completion_tokens"] = 1500
        else:
            payload["temperature"] = 0.2

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "RepoAUDT-Mac/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                choices = data.get("choices") or []
                if not choices or not isinstance(choices[0], dict):
                    raise RuntimeError(f"Unexpected {provider} response format: missing choices")
                return choices[0].get("message", {}).get("content", "")
        except urllib.error.HTTPError as he:
            # If the model requires /v1/responses endpoint (e.g. codex/responses-only models), fallback automatically
            if provider == "openai" and he.code in (400, 404):
                resp_payload = {
                    "model": model,
                    "input": f"{system_prompt}\n\n{user_prompt}",
                }
                req2 = urllib.request.Request(
                    "https://api.openai.com/v1/responses",
                    data=json.dumps(resp_payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                        "User-Agent": "RepoAUDT-Mac/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req2, timeout=25) as resp2:
                    d2 = json.loads(resp2.read().decode("utf-8", errors="ignore"))
                    return d2.get("output_text") or json.dumps(d2)
            raise

    if provider == "claude":
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": model,
            "max_tokens": 1500,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "RepoAUDT-Mac/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            blocks = data.get("content") or []
            if not blocks or not isinstance(blocks[0], dict):
                raise RuntimeError("Unexpected Claude response format: missing content")
            return blocks[0].get("text", "")

    if provider == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
                "User-Agent": "RepoAUDT-Mac/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            candidates = data.get("candidates") or []
            parts = (candidates[0].get("content") or {}).get("parts") or [] if candidates else []
            if not parts or not isinstance(parts[0], dict):
                raise RuntimeError("Unexpected Gemini response format: missing candidates")
            return parts[0].get("text", "")

    raise ValueError(f"Unsupported provider: {provider}")


def test_llm_connection(
    provider: str,
    api_key_override: Optional[str] = None,
    model_override: Optional[str] = None,
) -> Dict[str, Any]:
    if provider == "none":
        return {"ok": False, "provider": provider, "error": "AI は現在「使用しない（静的解析のみ）」に設定されています。"}
    settings = load_settings()
    api_key = (api_key_override or "").strip()
    if not api_key or ("..." in api_key and len(api_key) < 30):
        api_key = settings["keys"].get(provider, "")
    if "..." in api_key and "sk-" in api_key:
        idx = api_key.rfind("sk-")
        if idx > 0:
            api_key = api_key[idx:]
    if not api_key and provider not in ("local", "copilot", "gemini_cli"):
        return {"ok": False, "provider": provider, "error": f"{provider.upper()} の APIキーが未入力です。"}

    model = (model_override or "").strip() or settings["models"].get(provider, DEFAULT_SETTINGS["models"].get(provider, ""))

    # Step 1: For OpenAI, verify API key & model existence via GET /v1/models first (zero-cost check)
    models_verified = False
    model_exists_in_org = False
    available_luna_or_gpt = []
    if provider == "openai":
        try:
            mreq = urllib.request.Request(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}", "User-Agent": "RepoChex-macOS/1.0"},
            )
            with urllib.request.urlopen(mreq, timeout=12) as mresp:
                if mresp.status == 200:
                    mdata = json.loads(mresp.read().decode("utf-8", errors="ignore"))
                    all_mids = [m.get("id", "") for m in (mdata.get("data") or [])]
                    models_verified = True
                    model_exists_in_org = model in all_mids
                    available_luna_or_gpt = [
                        mid for mid in all_mids
                        if any(k in mid for k in ("luna", "gpt-6", "gpt-5.6", "gpt-5.4", "gpt-4o"))
                    ][:8]
        except urllib.error.HTTPError as mhe:
            # If the entered key gave 401, check if local Secrets/.env has a working OpenAI key
            if mhe.code == 401:
                fallback_key = ""
                for env_file in get_candidate_env_files():
                    if env_file.exists():
                        for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                            if line.strip().startswith("OPENAI_API_KEY="):
                                fallback_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                                break
                    if fallback_key:
                        break
                if fallback_key and fallback_key != api_key:
                    try:
                        mreq2 = urllib.request.Request(
                            "https://api.openai.com/v1/models",
                            headers={"Authorization": f"Bearer {fallback_key}", "User-Agent": "RepoAUDT-Mac/1.0"},
                        )
                        with urllib.request.urlopen(mreq2, timeout=12) as mresp2:
                            if mresp2.status == 200:
                                mdata2 = json.loads(mresp2.read().decode("utf-8", errors="ignore"))
                                all_mids2 = [m.get("id", "") for m in (mdata2.get("data") or [])]
                                # Auto-heal and save the working key from Secrets/.env
                                settings["keys"]["openai"] = fallback_key
                                SETTINGS_FILE.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
                                try:
                                    os.chmod(SETTINGS_FILE, 0o600)
                                except Exception:
                                    pass
                                api_key = fallback_key
                                models_verified = True
                                model_exists_in_org = model in all_mids2
                                available_luna_or_gpt = [
                                    mid for mid in all_mids2
                                    if any(k in mid for k in ("luna", "gpt-6", "gpt-5.6", "gpt-5.4", "gpt-4o"))
                                ][:8]
                    except Exception:
                        pass
                if not models_verified:
                    err_body = mhe.read().decode("utf-8", errors="ignore")[:240]
                    return {
                        "ok": False,
                        "provider": provider,
                        "error": f"[Step 1: /v1/models 認証停止] キー ({mask_key(api_key)}) が OpenAI サーバーから HTTP 401 (invalid_api_key) で拒否されました。詳細: {err_body}",
                    }

    # Step 2: Test completion with the selected model
    try:
        raw = call_llm_provider(
            provider=provider,
            api_key=api_key,
            model=model,
            system_prompt="Return a JSON object: {\"status\": \"ok\", \"engine\": \"ready\"}",
            user_prompt="Ping test. Respond with JSON.",
        )
        display_model = model or "CLI default"
        return {
            "ok": True,
            "provider": provider,
            "model": display_model,
            "message": f"✅ {provider.upper()} ({display_model}) への認証・推論テストに完全成功しました！",
            "sample": raw[:120],
        }
    except urllib.error.HTTPError as he:
        err_body = he.read().decode("utf-8", errors="ignore")[:260]
        if provider == "openai" and models_verified:
            if he.code == 429 and "insufficient_quota" in err_body:
                m_note = f"モデル `{model}` の存在も確認済" if model_exists_in_org else f"利用可能: {', '.join(available_luna_or_gpt[:4])}"
                return {
                    "ok": True,
                    "provider": provider,
                    "model": model,
                    "message": (
                        f"✅ APIキー認証成功 ({mask_key(api_key)}) & `/v1/models` で {m_note}！"
                        f"（※Step 2 推論コール `/v1/chat/completions` のみ OpenAI 側のクレジット残高不足 [HTTP 429 insufficient_quota] で停止しています）"
                    ),
                }
            if he.code == 404 or not model_exists_in_org:
                return {
                    "ok": False,
                    "provider": provider,
                    "error": f"✅ APIキー認証は成功しましたが、モデル `{model}` が見つかりません。利用可能なモデル例: {', '.join(available_luna_or_gpt)}",
                }
        return {"ok": False, "provider": provider, "error": f"HTTP {he.code}: {err_body}"}
    except Exception as exc:
        return {"ok": False, "provider": provider, "error": str(exc)}


DEEP_AUDIT_SYSTEM_PROMPT = """あなたはシニア・アプリケーションセキュリティエンジニア兼コード監査のプロフェッショナルです。
提供されたコード、設定ファイル、依存関係情報、または差分（PR/Commit）を解析し、実際に悪用可能な脆弱性・設計上の欠陥・重大な品質リスクのみを高い精度で報告し、具体的な改善提案と適用可能なパッチを提示してください。

## 1. 監査の基準と優先順位（Risk-First）
以下の領域を優先的に検査してください（OWASP ASVS v5.0 / CWE Top 25 / OWASP Cheat Sheet Series 準拠）：
1. **認証・認可・アクセス制御**: 権限チェック漏れ、IDOR、JWT/Sessionの扱い、RLS不備
2. **インジェクション**: SQLi、OSコマンドインジェクション、XSS、SSRF、テンプレートインジェクション
3. **CI/CD・設定ファイル（GitHub Actions等）**: `run:` ブロック内での外部入力展開、`pull_request_target` の誤用、過剰な権限（`permissions`）
4. **機密情報管理**: ハードコードされたAPIキー・トークン・パスワード、ログへの機密出力
5. **入力検証・ファイル処理**: スキーマ検証の欠如、パストラバーサル、安全でないデシリアライズ
6. **堅牢性・パフォーマンス・保守性**: 例外のもみ消し、リソースリーク、競合状態（Race Condition）、N+1クエリ、重大な型安全性欠如

## 2. 誤検知（False Positive）を防ぐ厳格なルール
単なるキーワードや正規表現の一致だけで警告を出さないでください。**必ずデータフロー（Source → Sink）と実行コンテキストを追跡**してから判定してください。

- **GitHub Actions の例**:
  - `run:` 内で `${{ github.event.* }}` を直接展開している場合のみ「Script Injection」として報告する。
  - `env:` や `with:` ブロック内で `KEY: ${{ github.event.* }}` として定義されている場合は、**すでに対策済みの安全なパターン**であるため警告しない（ただし後続の `run:` 内で `eval` 等に渡されている場合のみ警告する）。
- **SQL / コマンドの例**:
  - プレースホルダ（プリペアドステートメント）や引数配列渡し（`execFile` 等）が使われている場合は安全とみなす。
- **フレームワーク保護**:
  - ReactのJSX自動エスケープなど、フレームワーク標準の保護機構で無害化されている場合は誤検知しない。
- **不確実な場合**:
  - 前後のコンテキストが不足して悪用可能性を断定できない場合は、`severity` を下げて `confidence: "low"` と明記し、推測で断定しない。

## 3. 依存関係・CVE評価およびパッチ情報のルール
- ライブラリやCVEを評価する際は、理論上のCVSSスコアだけでなく、**OSV.dev / GitHub Advisory (GHSA)** の影響バージョン範囲、および **CISA KEV（悪用実績）/ EPSS（悪用確率）** の観点を考慮して現実的な優先度（Critical〜Low）を決定する。
- **ハルシネーション厳禁**: `fixed_version` や `advisory_url` などのパッチ情報は、入力データや確実な知識から裏付けられる場合のみ記載し、**存在しないURLやバージョン番号を推測で捏造せず、不確実な場合は必ず `null` にすること**。

## 4. 改善提案・修正パッチ（diff）の品質ルール
- 修正案（`diff`）を提示する場合は、元のコードの構文（YAMLのインデント、言語の型やスコープ）を破壊しない**構文的に有効でそのまま適用可能なパッチ**のみを生成すること。
- 汎用テンプレートの丸写しや、`// TODO`、`// ...` などのプレースホルダは絶対に出力しない。
- 即座に改修・アップデートできない場合のための暫定回避策（`workaround`）や、修正後に安全性を確認するコマンド・テスト案（`verification`）も併記すること。

## 5. 出力フォーマット
問題が検出された場合のみ、以下のJSON配列形式で出力してください（問題がなければ空配列 `[]` を返す）。説明は簡潔かつ具体的に記述し、根拠となるファイル・行番号と攻撃/障害シナリオを必ず含めてください。
※ JSONオブジェクト形式が必須のAPI環境では `{"findings": [...]}` の形式で返してください。

```json
[
  {
    "id": "一意なルールID (例: gha-script-injection, sqli-raw-query)",
    "category": "security | reliability | performance | maintainability",
    "severity": "critical | high | medium | low | info",
    "confidence": "high | medium | low",
    "cwe": "CWE-XX (該当しない場合は null)",
    "title": "問題の簡潔なタイトル",
    "file": "ファイルパス",
    "line": 50,
    "desc": "何が問題で、どのような攻撃シナリオや障害リスクが成立するかの具体的な説明",
    "remediation": "推奨される改善・修正方針（OWASP等の根拠があれば記載）",
    "patch_info": {
      "fixed_version": "修正済みバージョン (依存関係の場合、不明/該当なしなら null)",
      "advisory_url": "OSV / GHSA / CVE / 公式パッチの参照URL (不明/該当なしなら null)",
      "workaround": "即座にアップデートや改修ができない場合の暫定回避策 (不要なら null)"
    },
    "diff": "構文的に有効でそのまま適用可能な修正差分（Unified Diff形式）",
    "verification": "パッチ適用後に正常性・安全性を確認するためのテストやコマンド案"
  }
]
```

## 6. 対象プロジェクトの技術スタック
- 言語 / フレームワーク: {{LANGUAGE_AND_FRAMEWORK}}
- インフラ / CI/CD: {{INFRA_AND_CICD}}"""


def _detect_stack_context(repo_dir: Path) -> Tuple[str, str]:
    """Infer language/framework and infra/CI-CD labels from repository files."""
    langs: List[str] = []
    infra: List[str] = []
    if (repo_dir / "package.json").exists():
        langs.append("Node.js / JavaScript")
    if (repo_dir / "tsconfig.json").exists():
        langs.append("TypeScript")
    if (repo_dir / "pyproject.toml").exists() or (repo_dir / "requirements.txt").exists():
        langs.append("Python")
    if (repo_dir / "composer.json").exists():
        langs.append("PHP / Composer")
    if (repo_dir / "go.mod").exists():
        langs.append("Go")
    if (repo_dir / "Cargo.toml").exists():
        langs.append("Rust")
    if any(repo_dir.glob("*.swift")) or (repo_dir / "Package.swift").exists() or (repo_dir / "Sources").is_dir():
        langs.append("Swift / macOS")

    if (repo_dir / ".github" / "workflows").is_dir():
        infra.append("GitHub Actions")
    if (repo_dir / "Dockerfile").exists() or any(repo_dir.glob("docker-compose*.yml")) or any(repo_dir.glob("docker-compose*.yaml")):
        infra.append("Docker")

    return (
        ", ".join(langs) if langs else "マニフェスト・ソースコードから自動判定",
        ", ".join(infra) if infra else "特記事項なし",
    )


def _parse_deep_audit_items(raw: str) -> List[Dict[str, Any]]:
    """Extract a list of finding dicts from JSON array or wrapped object output."""
    cleaned = str(raw or "").strip()
    if not cleaned:
        return []
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", cleaned)
    if fence:
        cleaned = fence.group(1).strip()
    if not cleaned:
        return []

    parsed: Any = None
    try:
        parsed = json.loads(cleaned)
    except Exception:
        arr_match = re.search(r"\[.*\]", cleaned, re.DOTALL)
        obj_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        candidate = arr_match.group(0) if arr_match else (obj_match.group(0) if obj_match else "")
        if not candidate:
            return []
        try:
            parsed = json.loads(candidate)
        except Exception:
            return []

    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        for key in ("findings", "items", "results", "issues"):
            val = parsed.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
    return []


def run_llm_deep_vulnerability_audit(
    repo_dir: Path,
    repo_name: str,
    components: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    items, label, _status = run_llm_deep_vulnerability_audit_with_status(repo_dir, repo_name, components)
    return items, label


def run_llm_deep_vulnerability_audit_with_status(
    repo_dir: Path,
    repo_name: str,
    components: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[str], str]:
    """
    If an LLM provider is configured, send repository manifests, CI/CD workflows,
    and source snippets to the LLM to perform Risk-First security & quality auditing.
    Returns (llm_action_items, provider_label, llm_audit_status).
    """
    settings = load_settings()
    chosen = choose_active_llm(settings)
    if not chosen:
        return [], None, "disabled"

    provider, api_key, model = chosen
    comp_names = [c["name"] for c in components]

    # Collect compact manifest, workflow, and source snippets
    snippets: List[str] = []
    for manifest in ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "Info.plist"):
        mp = repo_dir / manifest
        if mp.exists():
            snippets.append(f"=== {manifest} ===\n" + mp.read_text(encoding="utf-8", errors="ignore")[:1200])

    for wf in workflow_files(repo_dir)[:3]:
        rel_wf = str(wf.relative_to(repo_dir))
        snippets.append(f"=== {rel_wf} ===\n" + wf.read_text(encoding="utf-8", errors="ignore")[:1200])

    ignore_dirs = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".next"}
    src_files = [
        p for p in repo_dir.rglob("*")
        if p.is_file() and p.suffix in {".php", ".ts", ".tsx", ".js", ".py", ".swift", ".go"}
        and not any(part in ignore_dirs for part in p.parts)
    ][:6]
    for sf in src_files:
        rel = str(sf.relative_to(repo_dir))
        snippets.append(f"=== {rel} ===\n" + sf.read_text(encoding="utf-8", errors="ignore")[:900])

    if not snippets:
        return [], f"{provider.upper()} ({model})", "skipped"

    lang_fw, infra_cicd = _detect_stack_context(repo_dir)
    sys_prompt = (
        DEEP_AUDIT_SYSTEM_PROMPT
        .replace("{{LANGUAGE_AND_FRAMEWORK}}", lang_fw)
        .replace("{{INFRA_AND_CICD}}", infra_cicd)
    )
    user_prompt = (
        f"Repository: {repo_name}\n"
        f"Available Diagram Nodes: {', '.join(comp_names)}\n\n"
        + "\n\n".join(snippets[:8])
    )

    try:
        raw = ""
        for attempt in range(2):
            raw = call_llm_provider(provider, api_key, model, sys_prompt, user_prompt)
            if str(raw or "").strip():
                break
        if not str(raw or "").strip():
            return [], f"{provider.upper()} ({model})", "skipped"
        items = _parse_deep_audit_items(raw)
        valid_items: List[Dict[str, Any]] = []
        allowed_severities = {"critical", "high", "medium", "low", "info"}
        for it in items[:6]:
            title = str(it.get("title") or "").strip()
            desc = str(it.get("desc") or "").strip()
            if not title or not desc:
                continue

            sev = str(it.get("severity") or "medium").strip().lower()
            if sev not in allowed_severities:
                sev = "medium"

            tn = str(it.get("target_node") or "").strip() or (comp_names[0] if comp_names else repo_name)
            file_path = str(it.get("file") or "src/").strip()
            line_no = it.get("line")
            loc = f"{file_path}:{line_no}" if isinstance(line_no, int) and line_no > 0 else file_path

            cwe = it.get("cwe")
            confidence = str(it.get("confidence") or "").strip().lower()
            remediation = str(it.get("remediation") or "").strip()
            patch_info = it.get("patch_info") if isinstance(it.get("patch_info"), dict) else {}
            fixed_ver = patch_info.get("fixed_version")
            advisory_url = patch_info.get("advisory_url")
            workaround = patch_info.get("workaround")

            desc_parts = [desc]
            if remediation:
                desc_parts.append(f"【修正方針】{remediation}")
            if fixed_ver:
                desc_parts.append(f"【修正済みバージョン】{fixed_ver}")
            if workaround:
                desc_parts.append(f"【暫定回避策】{workaround}")
            if confidence == "low":
                desc_parts.append("（※確信度: low — 前後のコンテキストを含めて手動確認してください）")

            title_prefix = f"[{provider.upper()} AI監査]"
            cwe_suffix = f" ({cwe})" if isinstance(cwe, str) and cwe.strip() else ""
            entry: Dict[str, Any] = {
                "severity": sev,
                "title": f"{title_prefix} {title}{cwe_suffix}",
                "file": f"{loc} (Target: {tn})",
                "target_node": tn,
                "desc": "\n".join(desc_parts),
                "diff": str(it.get("diff") or ""),
                "fix_cmd": str(it.get("verification") or it.get("fix_cmd") or ""),
            }
            if isinstance(advisory_url, str) and advisory_url.startswith(("https://", "http://")):
                entry["official_source"] = advisory_url
            valid_items.append(entry)
        return valid_items, f"{provider.upper()} ({model})", "completed"
    except Exception as exc:
        print(f"Notice: LLM deep audit skipped/failed for {repo_name}: {exc}", file=sys.stderr)
        return [], f"{provider.upper()} ({model})", "skipped"


_DEP_MANIFEST_BASENAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}
_ADVISORY_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.IGNORECASE)
_OSV_TITLE_PKG_RE = re.compile(r"(?:\[OSV脆弱性検出\]|\[依存関係脆弱性集約\])\s+([@a-zA-Z0-9_./-]+)")


def _strip_finding_file_and_line(raw_file: str) -> Tuple[str, Optional[int]]:
    base = str(raw_file or "").split(" (Target:", 1)[0].strip()
    if ":" in base:
        left, right = base.rsplit(":", 1)
        if right.isdigit():
            cleaned = left.strip()
            return (cleaned[2:] if cleaned.startswith("./") else cleaned), int(right)
    return (base[2:] if base.startswith("./") else base), None


def _extract_osv_package_name(item: Dict[str, Any]) -> str:
    for key in ("pkg", "package_name"):
        val = str(item.get(key) or "").strip()
        if val:
            return re.sub(r"\s*\([^)]+\)\s*$", "", val).strip().lower()
    m = _OSV_TITLE_PKG_RE.search(str(item.get("title") or ""))
    return m.group(1).strip().lower() if m else ""


def _ai_mentions_package(ai_item: Dict[str, Any], pkg: str) -> bool:
    if not pkg:
        return False
    haystack = f"{ai_item.get('title', '')}\n{ai_item.get('diff', '')}".lower()
    patterns = [rf"(?<![a-z0-9_/@-]){re.escape(pkg)}(?![a-z0-9_/-])"]
    if pkg == "next":
        patterns.append(r"(?<![a-z0-9_/-])next\.js(?![a-z0-9_/-])")
    elif pkg == "ckeditor5":
        patterns.append(r"(?<![a-z0-9_/-])ckeditor\s*5(?![a-z0-9_/-])")
    return any(re.search(pat, haystack) for pat in patterns)


def _classify_gha_finding(item: Dict[str, Any]) -> str:
    text = f"{item.get('title', '')} {item.get('desc', '')}".lower()
    if any(k in text for k in ("インジェクション", "injection", "head_ref", "cwe-78")):
        return "injection"
    if "write-all" in text:
        return "write_all"
    if any(k in text for k in ("未固定", "unpinned", "cwe-829")):
        return "unpinned_action"
    return ""


def merge_ai_and_static_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate overlapping AI audit findings against OSV and static GitHub Actions findings.

    1. When an AI finding targets a dependency manifest (e.g. package.json) for a package/CVE
       already reported by OSV or aggregated dependency findings, keep the canonical OSV row
       and attach the AI summary as a supplemental note.
    2. When an AI finding and static [GitHub Actions監査] findings cover the same workflow file
       and vulnerability class (e.g. script injection), keep the consolidated AI finding (which
       includes a full unified diff) and append the static scanner's detected line numbers.
    """
    if not items or len(items) < 2:
        return list(items or [])

    copied = [dict(it) for it in items if isinstance(it, dict)]

    # Index OSV / aggregated dependency findings
    osv_entries: List[Tuple[int, str, Set[str]]] = []
    # Index AI GitHub Actions findings by (workflow_path, gha_class)
    ai_gha_index: Dict[Tuple[str, str], int] = {}

    for idx, it in enumerate(copied):
        title = str(it.get("title") or "")
        is_osv = title.startswith("[OSV脆弱性検出]") or title.startswith("[依存関係脆弱性集約]")
        if is_osv:
            pkg = _extract_osv_package_name(it)
            adv_ids = {m.upper() for m in _ADVISORY_ID_RE.findall(f"{title} {it.get('desc', '')}")}
            osv_entries.append((idx, pkg, adv_ids))
            continue

        if "AI監査]" in title:
            fpath, _ = _strip_finding_file_and_line(str(it.get("file") or ""))
            if fpath.startswith(".github/workflows/"):
                gha_cls = _classify_gha_finding(it)
                if gha_cls and (fpath, gha_cls) not in ai_gha_index:
                    ai_gha_index[(fpath, gha_cls)] = idx

    drop_indices: Set[int] = set()
    gha_static_lines: Dict[int, List[int]] = {}

    for idx, it in enumerate(copied):
        title = str(it.get("title") or "")
        fpath, line_no = _strip_finding_file_and_line(str(it.get("file") or ""))
        basename = Path(fpath).name.lower() if fpath else ""

        # Rule 1: AI manifest dependency finding duplicates OSV / aggregated dependency finding
        if "AI監査]" in title and basename in _DEP_MANIFEST_BASENAMES and osv_entries:
            ai_adv_ids = {m.upper() for m in _ADVISORY_ID_RE.findall(f"{title} {it.get('desc', '')}")}
            matched_osv_idx: Optional[int] = None
            for osv_idx, pkg, osv_adv_ids in osv_entries:
                if (ai_adv_ids and osv_adv_ids and (ai_adv_ids & osv_adv_ids)) or _ai_mentions_package(it, pkg):
                    matched_osv_idx = osv_idx
                    break
            if matched_osv_idx is not None:
                osv_item = copied[matched_osv_idx]
                ai_first_line = str(it.get("desc") or "").splitlines()[0].strip() if it.get("desc") else ""
                note = f"【AI監査補足】{title}"
                if ai_first_line:
                    note += f" — {ai_first_line[:200]}"
                existing_desc = str(osv_item.get("desc") or "")
                if note not in existing_desc:
                    osv_item["desc"] = f"{existing_desc}\n{note}".strip()
                osv_item["ai_corroborated"] = True
                drop_indices.add(idx)
                continue

        # Rule 2: Static [GitHub Actions監査] line findings covered by consolidated AI workflow finding
        if "[GitHub Actions監査]" in title and fpath.startswith(".github/workflows/"):
            gha_cls = _classify_gha_finding(it)
            ai_idx = ai_gha_index.get((fpath, gha_cls))
            if ai_idx is not None:
                if line_no is not None:
                    gha_static_lines.setdefault(ai_idx, []).append(line_no)
                drop_indices.add(idx)

    for ai_idx, lines in gha_static_lines.items():
        unique_lines = sorted(set(lines))
        if unique_lines:
            line_str = ", ".join(f"L{ln}" for ln in unique_lines)
            existing_desc = str(copied[ai_idx].get("desc") or "")
            note = f"【静的スキャナ検知行】{line_str}"
            if note not in existing_desc:
                copied[ai_idx]["desc"] = f"{existing_desc}\n{note}".strip()
            copied[ai_idx]["static_corroborated"] = True

    return [it for idx, it in enumerate(copied) if idx not in drop_indices]
