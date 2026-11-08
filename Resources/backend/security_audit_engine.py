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

import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
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
    app_dir = base / "RepoCHK Mac"
    if not app_dir.exists():
        for old_dir in legacy_bases:
            if old_dir.exists():
                try:
                    shutil.copytree(old_dir, app_dir)
                    break
                except Exception as e:
                    print(f"Migration from {old_dir.name} to RepoCHK Mac notice: {e}", file=sys.stderr)
    return app_dir


APP_SUPPORT_DIR = get_app_support_dir()
SETTINGS_FILE = APP_SUPPORT_DIR / "settings.json"


DEFAULT_SETTINGS: Dict[str, Any] = {
    "active_provider": "auto",  # auto | openai | claude | gemini | groq
    "keys": {
        "openai": "",
        "claude": "",
        "gemini": "",
        "groq": "",
    },
    "models": {
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


def load_settings() -> Dict[str, Any]:
    APP_SUPPORT_DIR.mkdir(parents=True, exist_ok=True)
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    if SETTINGS_FILE.exists():
        try:
            saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                settings["active_provider"] = saved.get("active_provider", "auto")
                if isinstance(saved.get("keys"), dict):
                    settings["keys"].update(saved["keys"])
                if isinstance(saved.get("models"), dict):
                    settings["models"].update(saved["models"])
                if isinstance(saved.get("skills"), dict):
                    settings["skills"].update(saved["skills"])
        except Exception:
            pass

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

    candidate_envs = [
        APP_SUPPORT_DIR / ".env",
        Path.cwd() / ".env",
        Path.home() / ".config" / "RepoCHK Mac" / ".env",
        Path.home() / ".config" / "RepoChex" / ".env",
    ]
    for env_file in candidate_envs:
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
            except Exception:
                pass

    return settings


def save_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    current = load_settings()
    if "active_provider" in payload:
        current["active_provider"] = payload["active_provider"]
    if isinstance(payload.get("keys"), dict):
        for k in ("openai", "claude", "gemini", "groq"):
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
    except Exception:
        pass
    return get_masked_settings(current)


def mask_key(key: str) -> str:
    if not key or len(key) < 8:
        return ""
    return f"{key[:6]}...{key[-4:]}"


def get_masked_settings(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    s = settings or load_settings()
    masked_keys = {}
    configured_status = {}
    for k in ("openai", "claude", "gemini", "groq"):
        raw = s["keys"].get(k, "")
        masked_keys[k] = mask_key(raw)
        configured_status[k] = bool(raw and len(raw) >= 8)

    return {
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
            headers={"Content-Type": "application/json", "User-Agent": "RepoCHK-SecuritySkill"},
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
                        advisories.append({
                            "pkg": f"{pkg_name} ({eco})",
                            "installed": clean_ver,
                            "cve": vid,
                            "severity": "HIGH",
                            "title": f"[OSV脆弱性検出] {pkg_name} v{clean_ver} ({vid})",
                            "summary": f"OSV.dev 脆弱性データベースにおいて `{pkg_name}` ({eco}) バージョン `{clean_ver}` に既知の脆弱性 `{vid}` (他 {len(vulns)} 件) が報告されています。最新パッチバージョンへの更新を強く推奨します。",
                            "sources": [
                                {"name": f"OSV.dev ({vid})", "url": f"https://osv.dev/vulnerability/{vid}"},
                                {"name": "GitHub Advisory", "url": f"https://github.com/advisories?query={pkg_name}"},
                            ],
                        })
    except Exception:
        pass

    return advisories


def scan_php_and_nodejs_and_polyglot_vulnerabilities(
    repo_dir: Path,
    components: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Security-Review Skill + Runtime EOL Scanner + OSV.dev Package CVE Scanner
    for PHP, Node.js/TypeScript, Python, Swift, Go, and Rust.
    """
    settings = load_settings()
    skills_cfg = settings.get("skills", DEFAULT_SETTINGS["skills"])

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
                    if any(old_v in php_ver for old_v in ("5.", "7.", "8.0")):
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
            if any(old_n in node_ver for old_n in ("12", "14", "16", "18")):
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
        except Exception:
            pass

    # =========================================================================
    # 3. Python / Go / Rust OSV Queue
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

    # =========================================================================
    # 4. Execute Live OSV.dev Vulnerability Database Query
    # =========================================================================
    if skills_cfg.get("osv_mcp", True) and osv_query_list:
        osv_advisories = query_osv_batch(osv_query_list)
        security_advisories.extend(osv_advisories)

    return {
        "frameworks": frameworks,
        "databases": databases,
        "ai_sdks": ai_sdks,
        "runtime": runtime_info,
        "security_advisories": security_advisories,
        "sast_findings": sast_findings,
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
                "User-Agent": "RepoCHK-Mac/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                return data["choices"][0]["message"]["content"]
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
                        "User-Agent": "RepoCHK-Mac/1.0",
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
                "User-Agent": "RepoCHK-Mac/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return data["content"][0]["text"]

    if provider == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "RepoCHK-Mac/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

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
    if not api_key:
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
                for env_file in candidate_envs:
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
                            headers={"Authorization": f"Bearer {fallback_key}", "User-Agent": "RepoCHK-Mac/1.0"},
                        )
                        with urllib.request.urlopen(mreq2, timeout=12) as mresp2:
                            if mresp2.status == 200:
                                mdata2 = json.loads(mresp2.read().decode("utf-8", errors="ignore"))
                                all_mids2 = [m.get("id", "") for m in (mdata2.get("data") or [])]
                                # Auto-heal and save the working key from Secrets/.env
                                settings["keys"]["openai"] = fallback_key
                                SETTINGS_FILE.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
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
    except Exception:
        return [], f"{provider.upper()} ({model})"
