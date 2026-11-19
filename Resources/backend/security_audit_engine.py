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
from workflow_audit import MAX_FILES, read_workflow, run_zizmor, workflow_files
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
    "active_provider": "auto",  # auto | openai | claude | gemini | groq | local
    "keys": {
        "local": "",
        "openai": "",
        "claude": "",
        "gemini": "",
        "groq": "",
    },
    "models": {
        "local": "",
        "openai": "gpt-4o",
        "claude": "claude-3-7-sonnet-latest",
        "gemini": "gemini-2.5-flash",
        "groq": "llama-3.3-70b-versatile",
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
        if prov_val in ("auto", "openai", "claude", "gemini", "groq", "local"):
            current["active_provider"] = prov_val
    if "local_base_url" in payload:
        current["local_base_url"] = validate_endpoint(payload["local_base_url"], local_only=True)
    if isinstance(payload.get("keys"), dict):
        for k in ("openai", "claude", "gemini", "groq", "local"):
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
    for k in ("openai", "claude", "gemini", "groq", "local"):
        raw = s["keys"].get(k, "")
        masked_keys[k] = mask_key(raw)
        configured_status[k] = bool(raw and len(raw) >= 8)

    configured_status["local"] = bool(s.get("models", {}).get("local"))

    return {
        "local_base_url": s.get("local_base_url", DEFAULT_SETTINGS["local_base_url"]),
        "active_provider": s.get("active_provider", "auto"),
        "keys_masked": masked_keys,
        "configured": configured_status,
        "models": s.get("models", DEFAULT_SETTINGS["models"]),
        "skills": s.get("skills", DEFAULT_SETTINGS["skills"]),
    }


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
                        v0 = vulns[0]
                        vid = v0.get("id", "OSV-VULN")
                        aliases = list(v0.get("aliases") or [])
                        osv_summary = str(v0.get("summary") or "").strip()
                        osv_details = str(v0.get("details") or "").strip()
                        if not osv_summary and len(advisories) < 8:
                            try:
                                vreq = urllib.request.Request(
                                    f"https://api.osv.dev/v1/vulns/{vid}",
                                    headers={"User-Agent": "RepoAUDT-SecuritySkill"},
                                )
                                with urllib.request.urlopen(vreq, timeout=4) as vresp:
                                    if getattr(vresp, "status", 200) == 200:
                                        vfull = json.loads(vresp.read().decode("utf-8", errors="ignore"))
                                        osv_summary = str(vfull.get("summary") or "").strip()
                                        osv_details = str(vfull.get("details") or "").strip()
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
                        advisories.append({
                            "pkg": f"{pkg_name} ({eco})",
                            "installed": clean_ver,
                            "cve": display_cve,
                            "osv_id": vid,
                            "severity": "HIGH",
                            "title": f"[OSV脆弱性検出] {pkg_name} v{clean_ver} ({display_cve})" + (f" — {osv_summary}" if osv_summary else ""),
                            "summary": f"OSV.dev 脆弱性データベースにおいて `{pkg_name}` ({eco}) バージョン `{clean_ver}` に既知の脆弱性 `{display_cve}` (計 {len(vulns)} 件) が報告されています。{detail_suffix}",
                            "impact": first_sentence or osv_summary or "放置すると外部からの不正リクエストによって認証回避・情報漏洩・サービス妨害 (DoS) 等に悪用される危険があります。",
                            "sources": [
                                {"name": f"OSV.dev ({vid})", "url": f"https://osv.dev/vulnerability/{vid}"},
                                {"name": "GitHub Advisory", "url": f"https://github.com/advisories?query={pkg_name}"},
                            ],
                        })
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
        "process.env.DB_PASSWORD || os.environ.get('DB_PASSWORD')",
    ),
]


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

            # Special check: committed .env or .env.local file
            if file_path.name in (".env", ".env.local", ".env.production", ".env.stage", "secrets.yml", "credentials.json"):
                target_node = match_comp(rel_path)
                findings.append({
                    "severity": "critical",
                    "title": f"🚨 [シークレット設定ファイル漏洩] `{file_path.name}` がリポジトリにコミットされています",
                    "file": f"{rel_path}:1 (Target: {target_node})",
                    "target_node": target_node,
                    "desc": f"`{rel_path}` は本番または検証用の認証情報・APIキーが含まれるシークレット設定ファイルです。Gitリポジトリへのコミットは不正侵入の直接要因となります。直ちにGit管理対象から除外（`git rm --cached`）し、`.gitignore` に追加してください。",
                    "diff": f"- (リポジトリ内に保持: {file_path.name})\n+ (.gitignore に追加してローカルまたはシークレットマネージャーで管理)",
                    "fix_cmd": f"git rm --cached {rel_path} && echo '{rel_path}' >> .gitignore",
                })

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_no, line_str in enumerate(lines, start=1):
                stripped = line_str.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
                    if "-----BEGIN" not in stripped:
                        continue

                for secret_name, pattern, desc_label, fix_replacement in SECRET_PATTERNS:
                    # Ignore obvious test/placeholder strings
                    low = stripped.lower()
                    if "example" in low or "dummy" in low or "your_" in low or "<api_key>" in low:
                        continue
                    m = re.search(pattern, stripped)
                    if m:
                        raw_secret = m.group(1) if m.groups() else m.group(0)
                        if secret_name == "Database / Hardcoded Password" and (
                            len(raw_secret) < 8 or is_terraform_secret_arn(rel_path, stripped)
                        ):
                            continue
                        masked = mask_detected_secret(raw_secret)
                        target_node = match_comp(rel_path)
                        findings.append({
                            "severity": "critical",
                            "title": f"🚨 [シークレット漏洩検知] {secret_name} が平文でハードコードされています ({file_path.name}:{line_no})",
                            "file": f"{rel_path}:{line_no} (Target: {target_node})",
                            "target_node": target_node,
                            "desc": f"`{rel_path}` の {line_no}行目で、{desc_label}（`{masked}`）が平文で検出されました。ソースコード内に認証情報が存在すると、閲覧権限を持つ全員に漏洩し、不正利用やデータ侵害の原因となります。直ちに該当サービスでキーを無効化（Revoke/Rotate）し、環境変数または秘密情報マネージャーへ退避してください。",
                            "diff": f"- {stripped.replace(raw_secret, '[REDACTED]', 1)}\n+ {fix_replacement}",
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
        runtime_info["php"] = "PHP 8.x Runtime"
        if composer_json.exists():
            try:
                cdata = json.loads(composer_json.read_text(encoding="utf-8", errors="ignore"))
                req_all = {}
                req_all.update(cdata.get("require") or {})
                req_all.update(cdata.get("require-dev") or {})

                php_ver = str(req_all.get("php", ""))
                if php_ver:
                    runtime_info["php"] = f"PHP {php_ver}"
                    if re.search(r"(?:^|[^\d.])(5\.|7\.|8\.0(?:\b|$))", php_ver):
                        security_advisories.append({
                            "pkg": "php (Runtime)",
                            "installed": php_ver,
                            "cve": "PHP-EOL-SECURITY",
                            "severity": "CRITICAL",
                            "title": f"PHP ランタイム ({php_ver}) セキュリティサポート終了 (EOL) リスク",
                            "summary": f"`composer.json` で指定されている PHP バージョン `{php_ver}` は公式セキュリティサポートが終了 (EOL) しています。未パッチの遠隔コード実行 (RCE) 等のリスクがあるため、PHP 8.2 / 8.3 LTS への移行が必要です。",
                            "sources": [
                                {"name": "PHP Supported Versions", "url": "https://www.php.net/supported-versions.php"},
                            ],
                        })
                        frameworks.append({
                            "name": "PHP Runtime Engine",
                            "version": php_ver,
                            "status": "warn",
                            "desc": "⚠️ EOLバージョン検出 — PHP 8.2/8.3への更新推奨",
                            "security_link": "https://www.php.net/supported-versions.php",
                        })
                    else:
                        frameworks.append({
                            "name": "PHP Runtime Engine",
                            "version": php_ver,
                            "status": "latest",
                            "desc": "PHP サーバーサイド実行ランタイム",
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
            node_ver = str(engines.get("node", "Node.js 20.x LTS"))
            runtime_info["node"] = node_ver
            if re.search(r"(?:^|[^\d.])(12|14|16|18)(?:\.|$|x|\s)", node_ver):
                security_advisories.append({
                    "pkg": "Node.js Runtime",
                    "installed": node_ver,
                    "cve": "NODEJS-EOL-AUDIT",
                    "severity": "HIGH",
                    "title": f"Node.js ランタイム ({node_ver}) EOL / セキュリティ更新終了警告",
                    "summary": f"`package.json` の `engines.node` ({node_ver}) は旧世代ランタイムを含んでいます。OpenSSL および HTTP/2 関連の脆弱性対策のため Node.js 20 LTS または 22 LTS へのアップグレードを推奨します。",
                    "sources": [
                        {"name": "Node.js Security Releases", "url": "https://nodejs.org/en/blog/vulnerability"},
                    ],
                })

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
        builtin_findings = scan_github_actions_workflows(repo_dir, match_comp)
        external_keys = {(item["rule_id"], item["file"]) for item in (gha_findings or [])}
        sast_findings.extend(gha_findings or [])
        sast_findings.extend(
            item for item in builtin_findings if (item["rule_id"], item["file"]) not in external_keys
        )
        scanner = "builtin+zizmor" if status == "complete" else "builtin" if files else None
        workflow_scan = {"scanner": scanner, "status": status}

    secret_findings = scan_secrets_and_credentials(repo_dir, match_comp)
    sast_findings = secret_findings + sast_findings
    security_advisories = enrich_advisories_with_epss(security_advisories)

    return {
        "frameworks": frameworks,
        "databases": databases,
        "ai_sdks": ai_sdks,
        "runtime": runtime_info,
        "security_advisories": security_advisories,
        "sast_findings": sast_findings,
        "workflow_scan": workflow_scan,
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

    untrusted_expr_re = re.compile(
        r"\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|discussion|commits|head_commit|pages)\.[A-Za-z0-9_.\[\]]*(?:title|body|message|ref|label|name|email|page_name))\s*\}\}",
        re.IGNORECASE,
    )
    unpinned_uses_re = re.compile(
        r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(main|master|HEAD|develop)\b"
    )

    for wf in workflow_files(Path(repo_dir))[:MAX_FILES]:
        rel_path = str(wf.relative_to(repo_dir))
        try:
            raw = read_workflow(wf)
            if raw is None:
                continue
            content = raw.decode("utf-8", errors="ignore")
            lines = content.splitlines()
        except OSError:
            continue

        tnode = match_comp(rel_path)
        has_pr_target = bool(re.search(r"\bpull_request_target\b", content))

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 1. Script injection via ${{ github.event.* }}
            m_inj = untrusted_expr_re.search(stripped)
            if m_inj:
                expr = m_inj.group(0)
                findings.append({
                    "severity": "critical",
                    "rule_id": "template-injection",
                    "title": f"🚨 [GitHub Actions監査] `${{{{ ... }}}}` によるシェルインジェクションリスク ({wf.name}:{idx})",
                    "file": f"{rel_path}:{idx} (Target: {tnode})",
                    "target_node": tnode,
                    "desc": f"`{rel_path}` の {idx}行目で外部入力由来のコンテキスト式 `{expr}` が直接展開されています。PRタイトルやブランチ名にシェルメタ文字が含まれると任意コマンド実行 (RCE) につながるため、`env:` 環境変数経由で参照してください。",
                    "diff": f"- {stripped}\n+ env:\n+   UNTRUSTED_INPUT: {expr}\n+ run: echo \"$UNTRUSTED_INPUT\"",
                    "fix_cmd": f"sed -n '{max(1, idx-2)},{idx+2}p' {rel_path}",
                })

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
    keys = settings.get("keys", {})
    models = settings.get("models", DEFAULT_SETTINGS["models"])

    if pref == "local":
        model = str(models.get("local", "")).strip()
        return ("local", keys.get("local", ""), model) if model else None

    order = [pref] if pref in ("openai", "claude", "gemini", "groq") else ["openai", "claude", "gemini", "groq"]
    for prov in order:
        k = (keys.get(prov) or "").strip()
        if k and len(k) >= 8:
            return prov, k, models.get(prov, DEFAULT_SETTINGS["models"][prov])
    return None


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


def test_llm_connection(provider: str, api_key_override: Optional[str] = None) -> Dict[str, Any]:
    settings = load_settings()
    api_key = (api_key_override or "").strip()
    if not api_key or ("..." in api_key and len(api_key) < 30):
        api_key = settings["keys"].get(provider, "")
    if "..." in api_key and "sk-" in api_key:
        idx = api_key.rfind("sk-")
        if idx > 0:
            api_key = api_key[idx:]
    if not api_key and provider != "local":
        return {"ok": False, "provider": provider, "error": f"{provider.upper()} の APIキーが未入力です。"}

    model = settings["models"].get(provider, DEFAULT_SETTINGS["models"].get(provider, ""))

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
        return {
            "ok": True,
            "provider": provider,
            "model": model,
            "message": f"✅ {provider.upper()} ({model}) への認証・推論テストに完全成功しました！",
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


def run_llm_deep_vulnerability_audit(
    repo_dir: Path,
    repo_name: str,
    components: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    If an LLM API key (OpenAI, Claude, Gemini, Groq) is configured, send a compact
    summary of the repository's manifests and source snippets to the LLM to perform
    deep vulnerability & CodeRabbit architectural review.
    Returns (llm_action_items, provider_label).
    """
    settings = load_settings()
    chosen = choose_active_llm(settings)
    if not chosen:
        return [], None

    provider, api_key, model = chosen
    comp_names = [c["name"] for c in components]

    # Collect compact manifest + source snippets
    snippets = []
    for manifest in ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "Info.plist"):
        mp = repo_dir / manifest
        if mp.exists():
            snippets.append(f"=== {manifest} ===\n" + mp.read_text(encoding="utf-8", errors="ignore")[:1200])

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
        return [], f"{provider.upper()} ({model})"

    sys_prompt = (
        "あなたは CodeRabbit & OWASP セキュリティ監査AIです。"
        "与えられたリポジトリのマニフェスト（PHP/Composer, Node.js/npm, Python, Swift等）とソースコード抜粋から、"
        "セキュリティ脆弱性・バージョンリスク・エラー処理漏れを最大2件特定し、必ず以下のJSON形式で日本語で出力してください:\n"
        "{\"items\": [{\"severity\": \"high\", \"title\": \"指摘タイトル\", \"file\": \"対象ファイル名\", "
        "\"target_node\": \"構成図の対象ノード名\", \"desc\": \"要対応の理由とリスク\", "
        "\"diff\": \"- 旧コード\\n+ 推奨修正コード\", \"fix_cmd\": \"修正または確認コマンド\"}]}"
    )
    user_prompt = (
        f"Repository: {repo_name}\n"
        f"Available Diagram Nodes: {', '.join(comp_names)}\n\n"
        + "\n\n".join(snippets[:6])
    )

    try:
        raw = call_llm_provider(provider, api_key, model, sys_prompt, user_prompt)
        # Extract JSON block if wrapped in markdown
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        parsed = json.loads(m.group(0) if m else raw)
        items = parsed.get("items") or []
        valid_items = []
        for it in items[:2]:
            if isinstance(it, dict) and it.get("title") and it.get("desc"):
                tn = it.get("target_node") or (comp_names[0] if comp_names else repo_name)
                valid_items.append({
                    "severity": it.get("severity", "high"),
                    "title": f"[{provider.upper()} AI監査] {it['title']}",
                    "file": f"{it.get('file', 'src/')} (Target: {tn})",
                    "target_node": tn,
                    "desc": it["desc"],
                    "diff": it.get("diff", ""),
                    "fix_cmd": it.get("fix_cmd", ""),
                })
        return valid_items, f"{provider.upper()} ({model})"
    except Exception as exc:
        print(f"Notice: LLM deep audit skipped/failed for {repo_name}: {exc}", file=sys.stderr)
        return [], f"{provider.upper()} ({model})"
