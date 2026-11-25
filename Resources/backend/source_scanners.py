"""Bounded local Ruff and Gitleaks scans of tracked working-tree files."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from workflow_audit import MAX_REPORT_BYTES, read_small_file

MAX_TRACKED_FILES = 3000
MAX_SOURCE_BYTES = 32 * 1024 * 1024
TOOL_DIRS = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))
RULE_ID = re.compile(r"[A-Za-z0-9_-]{1,100}")
RUFF_RULES = {
    "F401": ("Unused import", "unused-import", "low"),
    "F811": ("Redefined unused name", "redefined-while-unused", "low"),
    "F821": ("Undefined name", "undefined-name", "medium"),
    "F822": ("Undefined export", "undefined-export", "medium"),
    "F823": ("Local name referenced before assignment", "undefined-local", "medium"),
    "F841": ("Unused local variable", "unused-variable", "low"),
}


def executable(name):
    return next(
        (str(path / name) for path in TOOL_DIRS if os.access(path / name, os.X_OK)),
        None,
    )


def run_read_only(command, directory, environment, *, allowed=(0,), timeout=30):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            command,
            cwd=directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if result.returncode not in allowed:
            raise ValueError("Scanner failed")
        output.seek(0)
        raw = output.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("Scanner output exceeded limit")
        return raw


def stage_sources(repo, directory, environment, *, python_only):
    raw = run_read_only(
        ["/usr/bin/git", "ls-files", "--cached", "-z", "--"],
        repo,
        {**environment, "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"},
        timeout=10,
    )
    files = {}
    bytes_left = MAX_SOURCE_BYTES
    partial = False
    for raw_path in dict.fromkeys(raw.split(b"\0")):
        if not raw_path:
            continue
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            partial = True
            continue
        parts = path.split("/")
        if any(part in ("", ".", "..", ".git") for part in parts) or any(
            ord(c) < 32 for c in path
        ):
            partial = True
            continue
        if python_only and Path(path).suffix not in (".py", ".pyi"):
            continue
        if len(files) >= MAX_TRACKED_FILES or bytes_left <= 0:
            partial = True
            break
        source = repo / path
        if any(
            parent.is_symlink()
            for parent in source.parents
            if parent != repo and repo in parent.parents
        ):
            partial = True
            continue
        try:
            content = read_small_file(source)
        except OSError:
            partial = True
            continue
        if content is None or len(content) > bytes_left:
            partial = True
            continue
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        files[path] = len(content.splitlines())
        bytes_left -= len(content)
    return files, partial


_DOC_OR_TEST_DIRS = {"__tests__", "tests", "test", "fixtures", "__fixtures__", "docs", "e2e", "seeds", "migrations"}
_DOC_OR_TEST_PLACEHOLDERS = (
    "...",
    "unit-test-",
    "example-",
    "dummy-",
    "mock-",
    "fake-",
    "placeholder",
    "your_",
    "changeme",
)


_PUBLIC_CLIENT_KEY_RE = re.compile(
    r"(?:reCaptchaKey|RECAPTCHA_SITE_KEY|NEXT_PUBLIC_[A-Z0-9_]+|VITE_PUBLIC_[A-Z0-9_]+|aws_appsync_apiKey|(?:sitekey|site_key|data-sitekey)\b[^\n]{0,24}['\"]6L[A-Za-z0-9_-]{28,50}['\"])",
    re.IGNORECASE,
)

_QUOTED_ASSIGNMENT_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z0-9_."'\[\]-]+)\s*[:=]\s*(['"])([^'"\n]+)\2\s*[,;]?\s*$"""
)
_LOWER_SNAKE_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*){2,}$")
_SECRET_PREFIXES = ("sk_", "pk_", "rk_", "whsec_", "ghp_", "gho_", "ghu_", "ghs_", "xox", "akia")


def _is_public_client_key_line(line: str) -> bool:
    low = line.lower()
    if any(priv in low for priv in ("private_key", "secret_key", "client_secret", "api_secret")):
        return False
    return bool(_PUBLIC_CLIENT_KEY_RE.search(line))


def _is_snake_case_identifier_key_line(line: str) -> bool:
    """Return True for benign map/metadata key constants like `const PROVENANCE_KEY = 'cerebras_gemma4_retirement_provenance'`."""
    m = _QUOTED_ASSIGNMENT_RE.match(line)
    if not m:
        return False
    lhs, _, val = m.groups()
    lhs_low = lhs.lower()
    if any(s in lhs_low for s in ("secret", "password", "passwd", "token", "credential", "private")):
        return False
    if val.startswith(_SECRET_PREFIXES):
        return False
    return bool(_LOWER_SNAKE_IDENTIFIER_RE.fullmatch(val))


def _is_benign_generic_api_key(directory: Path, relative: str, line: int) -> bool:
    """Return True if a generic-api-key hit is an obvious doc/test/example/seed entry or public client key."""
    try:
        lines = (directory / relative).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        lines = []
    if 1 <= line <= len(lines) and (
        _is_public_client_key_line(lines[line - 1])
        or _is_snake_case_identifier_key_line(lines[line - 1])
    ):
        return True
    rel_low = relative.lower().replace("\\", "/")
    parts = [p.lower() for p in Path(relative).parts]
    name = parts[-1] if parts else ""
    if (
        name.startswith((".env.example", "env.example", "env.e2e.example"))
        or name.endswith((".example", ".example.txt"))
        or name == "readme.md"
        or rel_low.endswith("source-manifest.json")
        or "/seeds/" in f"/{rel_low}"
        or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".docs.ts", ".docs.js"))
    ):
        return True
    is_doc_or_test = (
        any(p in _DOC_OR_TEST_DIRS for p in parts[:-1])
        or ".docs." in name
        or ".test." in name
        or ".spec." in name
    )
    if not is_doc_or_test:
        return False
    try:
        lines = (directory / relative).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    if not 1 <= line <= len(lines):
        return False
    stripped = lines[line - 1].strip()
    low = stripped.lower()
    is_comment = stripped.startswith(("*", "//", "#", "/*"))
    has_placeholder = any(marker in low for marker in _DOC_OR_TEST_PLACEHOLDERS)
    return is_comment or has_placeholder


def _is_benign_private_key_doc(directory: Path, relative: str, line: int) -> bool:
    """Return True if a Gitleaks private-key hit is a single-line ellipsis/doc placeholder in docs/README."""
    rel_low = relative.lower().replace("\\", "/")
    parts = [p.lower() for p in Path(relative).parts]
    name = parts[-1] if parts else ""
    is_doc = (
        "docs" in parts[:-1]
        or name == "readme.md"
        or name.endswith((".md", ".mdx"))
    )
    if not is_doc:
        return False
    try:
        lines = (directory / relative).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    if not 1 <= line <= len(lines):
        return False
    low = lines[line - 1].lower()
    return "..." in low or "base64 content" in low or "placeholder" in low or "example" in low


def parse_findings(scanner, raw, directory, files, match_component):
    data = json.loads(raw)
    if data is None and scanner == "gitleaks":
        return []
    if not isinstance(data, list):
        raise ValueError("Unexpected scanner output")
    findings = []
    seen = set()
    for item in data:
        if scanner == "ruff":
            rule = item["code"]
            if rule not in RUFF_RULES:
                # Invalid Python syntax belongs to parser diagnostics, outside this rule set.
                continue
            source = item["filename"]
            line = item["location"]["row"]
            label, slug, severity = RUFF_RULES[rule]
            desc = "Review this Python quality finding using the linked Ruff rule."
            docs = f"https://docs.astral.sh/ruff/rules/{slug}/"
        else:
            source, line, rule = item["File"], item["StartLine"], item["RuleID"]
            if not RULE_ID.fullmatch(rule):
                raise ValueError("Invalid Gitleaks rule ID")
            label, severity = "Potential exposed credential", "high"
            desc = "Verify the credential candidate. If it is real, revoke or rotate it and move the value to a secret store."
            docs = "https://github.com/gitleaks/gitleaks"
        path = Path(source)
        if path.is_absolute():
            path = path.relative_to(directory)
        relative = path.as_posix()
        if (
            relative not in files
            or type(line) is not int
            or not 1 <= line <= files[relative]
        ):
            raise ValueError("Finding is outside the staged source")
        key = (rule, relative, line)
        if key in seen:
            continue
        seen.add(key)
        if scanner == "gitleaks" and rule == "generic-api-key" and _is_benign_generic_api_key(directory, relative, line):
            continue
        if scanner == "gitleaks" and rule == "private-key" and _is_benign_private_key_doc(directory, relative, line):
            continue
        component = match_component(relative)
        findings.append(
            {
                "severity": severity,
                "title": f"[{scanner}] {label} ({rule})",
                "file": f"{relative}:{line} (Target: {component})",
                "target_node": component,
                "desc": desc,
                "official_source": docs,
                "scanner": scanner,
                "rule_id": rule,
            }
        )
    return findings


def scan_source(repo, match_component, *, include_quality=True):
    binaries = {
        "ruff": executable("ruff") if include_quality else None,
        "gitleaks": executable("gitleaks"),
    }
    statuses = {name: "not_installed" for name in binaries}
    if not include_quality:
        statuses["ruff"] = "disabled"
    if not any(binaries.values()):
        return [], statuses

    with tempfile.TemporaryDirectory(prefix="repoaudt-source-") as temp:
        root = Path(temp).resolve()
        directory = root / "source"
        directory.mkdir()
        environment = {"HOME": temp, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}
        try:
            files, partial = stage_sources(
                repo.resolve(),
                directory,
                environment,
                python_only=not binaries["gitleaks"],
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            statuses.update(
                {
                    name: "source_unavailable"
                    for name, binary in binaries.items()
                    if binary
                }
            )
            return [], statuses

        config = root / "gitleaks.toml"
        config.write_text(
            "[extend]\n"
            "useDefault = true\n\n"
            "[[allowlists]]\n"
            'description = "Ignore truncated JWT header-only documentation examples ending in ellipsis"\n'
            "regexes = [\n"
            "  '''eyJ[A-Za-z0-9_-]{10,}\\.\\.\\.'''\n"
            "]\n\n"
            "[[allowlists]]\n"
            'description = "Ignore env example templates and integrity manifest hashes"\n'
            "paths = [\n"
            "  '''(^|/)\\.env(\\..+)?\\.example$''',\n"
            "  '''(^|/)env(\\.e2e)?\\.example(\\.txt)?$''',\n"
            "  '''\\.github/astra_review/source-manifest\\.json$'''\n"
            "]\n",
            encoding="utf-8",
        )
        ignore = root / "gitleaksignore"
        ignore.touch()
        findings = []
        for name, binary in binaries.items():
            if binary is None:
                continue
            selected = {
                path: lines
                for path, lines in files.items()
                if name != "ruff" or Path(path).suffix in (".py", ".pyi")
            }
            if not selected:
                statuses[name] = "partial" if partial else "no_files"
                continue
            if name == "ruff":
                command = [
                    binary,
                    "check",
                    "--isolated",
                    "--no-cache",
                    "--no-fix",
                    "--no-respect-gitignore",
                    "--select",
                    ",".join(RUFF_RULES),
                    "--output-format=json",
                    ".",
                ]
            else:
                command = [
                    binary,
                    "dir",
                    "--config",
                    str(config),
                    "--gitleaks-ignore-path",
                    str(ignore),
                    "--ignore-gitleaks-allow",
                    "--no-banner",
                    "--log-level=error",
                    "--redact=100",
                    "--max-decode-depth=0",
                    "--report-format=json",
                    "--report-path=-",
                    "--exit-code=10",
                    ".",
                ]
            try:
                raw = run_read_only(
                    command,
                    directory,
                    environment,
                    allowed=(0, 1) if name == "ruff" else (0, 10),
                )
                findings.extend(
                    parse_findings(name, raw, directory, selected, match_component)
                )
                statuses[name] = "partial" if partial else "complete"
            except subprocess.TimeoutExpired:
                statuses[name] = "timeout"
            except (OSError, ValueError, KeyError, TypeError):
                statuses[name] = "tool_error"
        return findings, statuses


_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def parse_semgrep(raw, directory, files, match_component):
    """Parse Semgrep JSON output into normalized SAST findings."""
    text = raw.decode("utf-8", errors="ignore").strip() if isinstance(raw, (bytes, bytearray)) else str(raw).strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Unexpected Semgrep JSON output")
    results = data.get("results") or []
    findings = []
    seen = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id") or "semgrep-rule")
        raw_path = str(item.get("path") or "")
        start = item.get("start") or {}
        line = start.get("line")
        extra = item.get("extra") or {}
        sev_raw = str(extra.get("severity") or "WARNING").upper()
        message = str(extra.get("message") or "").strip()
        path = Path(raw_path)
        if path.is_absolute():
            path = path.relative_to(directory)
        relative = path.as_posix().removeprefix("./")
        if relative not in files or type(line) is not int or not 1 <= line <= files[relative]:
            continue
        key = (check_id, relative, line)
        if key in seen:
            continue
        seen.add(key)
        component = match_component(relative)
        short_rule = check_id.rsplit(".", 1)[-1]
        findings.append({
            "severity": _SEMGREP_SEVERITY.get(sev_raw, "medium"),
            "title": f"[semgrep] {short_rule} ({Path(relative).name}:{line})",
            "file": f"{relative}:{line} (Target: {component})",
            "target_node": component,
            "desc": message or f"Semgrep rule `{check_id}` flagged this code pattern.",
            "official_source": f"https://semgrep.dev/r/{check_id}",
            "scanner": "semgrep",
            "rule_id": check_id,
        })
    return findings


_TRIVY_ECOSYSTEM_BY_TYPE = {
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "uv": "PyPI",
    "gomod": "Go",
    "composer": "Packagist",
    "cargo": "crates.io",
}


def _infer_trivy_ecosystem(res: dict, target: str) -> str:
    res_type = str(res.get("Type") or "").strip().lower()
    if res_type in _TRIVY_ECOSYSTEM_BY_TYPE:
        return _TRIVY_ECOSYSTEM_BY_TYPE[res_type]
    low_target = target.lower()
    if low_target.endswith(("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        return "npm"
    if low_target.endswith(("requirements.txt", "pyproject.toml", "poetry.lock", "pipfile.lock")):
        return "PyPI"
    if low_target.endswith(("go.mod", "go.sum")):
        return "Go"
    if low_target.endswith(("composer.json", "composer.lock")):
        return "Packagist"
    if low_target.endswith(("cargo.toml", "cargo.lock")):
        return "crates.io"
    return "npm"


_PRERELEASE_RE = re.compile(r"-(?:rc|alpha|beta|dev|canary|preview|next|pre)(?:[.\-\d]|$)", re.IGNORECASE)


def _is_prerelease_version(raw: str) -> bool:
    return bool(_PRERELEASE_RE.search(str(raw or "").strip()))


def _parse_version_tuple(raw: str):
    m = re.search(r"(\d+(?:\.\d+)*)", str(raw or "").strip())
    if not m:
        return None
    parts = [int(part) for part in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def select_safe_upgrade_version(candidates, installed: str = "", *, pick_highest_same_major: bool = False) -> str:
    """
    Pick a safe upgrade version from candidates:
      1. Never downgrade: exclude any candidate <= installed.
      2. Prefer stable (non-prerelease) candidates; if only prereleases exist, return "".
      3. Prefer same-major upgrade over next-major; if none in same major, pick smallest next-major.
         When pick_highest_same_major=True (e.g. merging multiple CVEs), pick the highest same-major
         upgrade so all CVEs in that branch are resolved at once.
    """
    if isinstance(candidates, str):
        raw_list = [part.strip() for part in re.split(r"[,;]", candidates) if part.strip()]
    else:
        raw_list = [str(c).strip() for c in (candidates or []) if str(c).strip()]
    if not raw_list:
        return ""

    stable_valid = []
    for cand in raw_list:
        if _is_prerelease_version(cand):
            continue
        ver = _parse_version_tuple(cand)
        if ver is not None:
            stable_valid.append((cand, ver))

    if not stable_valid:
        return ""

    inst_ver = _parse_version_tuple(installed)
    if inst_ver is not None:
        strictly_newer = [(cand, ver) for cand, ver in stable_valid if ver > inst_ver]
        if not strictly_newer:
            return ""
        same_major = [(cand, ver) for cand, ver in strictly_newer if ver[0] == inst_ver[0]]
        if same_major:
            chooser = max if pick_highest_same_major else min
            return chooser(same_major, key=lambda item: item[1])[0]
        return min(strictly_newer, key=lambda item: item[1])[0]

    return max(stable_valid, key=lambda item: item[1])[0]


def _select_best_fixed_version(raw_fixed: str, installed: str = "") -> str:
    """Pick the single best upgrade target from comma-separated Trivy FixedVersion values."""
    return select_safe_upgrade_version(raw_fixed, installed, pick_highest_same_major=False)


_RISKY_COPYLEFT_RE = re.compile(r"\b(?:AGPL|GPL|SSPL|BUSL)(?:-[\w.]+)?\b", re.IGNORECASE)


def parse_trivy_licenses(raw, files, match_component):
    """Parse Trivy FS JSON Licenses[] into (copyleft_findings, license_summary)."""
    text = raw.decode("utf-8", errors="ignore").strip() if isinstance(raw, (bytes, bytearray)) else str(raw).strip()
    summary = {"MIT": 0, "Apache-2.0": 0, "BSD": 0, "copyleft_risk": 0, "other": 0}
    if not text:
        return [], summary
    data = json.loads(text)
    if not isinstance(data, dict):
        return [], summary
    results = data.get("Results")
    if not isinstance(results, list):
        return [], summary

    findings = []
    seen = set()
    for res in results:
        if not isinstance(res, dict):
            continue
        target = str(res.get("Target") or "").removeprefix("./")
        component = match_component(target or "package.json")
        for lic in res.get("Licenses") or []:
            if not isinstance(lic, dict):
                continue
            pkg_name = str(lic.get("PkgName") or "").strip()
            lic_name = str(lic.get("Name") or "").strip()
            if not lic_name:
                continue
            low = lic_name.lower()
            if "mit" in low:
                summary["MIT"] += 1
            elif "apache-2.0" in low or "apache 2" in low:
                summary["Apache-2.0"] += 1
            elif "bsd" in low:
                summary["BSD"] += 1
            elif _RISKY_COPYLEFT_RE.search(lic_name):
                summary["copyleft_risk"] += 1
                key = (pkg_name, lic_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "severity": "medium",
                    "priority_tier": "P2",
                    "priority_reason": "法務・OSSライセンス要確認（強コピーレフト）",
                    "category": "license",
                    "package_name": pkg_name,
                    "title": f"[OSSライセンス監査] 強コピーレフトライセンス検出: {pkg_name} ({lic_name})",
                    "file": f"{target or 'package.json'}:1 (Target: {component})",
                    "target_node": component,
                    "desc": (
                        f"`{pkg_name}` に強コピーレフト系ライセンス `{lic_name}` が検出されました。"
                        "商用プロプライエタリ製品への組み込み・配布時のソース開示義務リスクについて法務確認または代替パッケージ検討を推奨します。"
                    ),
                    "official_source": str(lic.get("Link") or "https://spdx.org/licenses/"),
                    "scanner": "trivy-license",
                    "rule_id": lic_name,
                })
            else:
                summary["other"] += 1
    return findings, summary


def generate_trivy_cyclonedx_sbom(repo_dir: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    """Generate a CycloneDX JSON SBOM for repo_dir using Trivy FS."""
    trivy_bin = executable("trivy")
    if not trivy_bin:
        return None, "Trivy がインストールされていないため CycloneDX SBOM を生成できません（`brew install trivy` で導入できます）。"
    if not repo_dir or not repo_dir.is_dir():
        return None, "対象リポジトリのローカルキャッシュが見つかりません。先にリポジトリを解析してください。"
    env = {"HOME": str(repo_dir), "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "en_US.UTF-8"}
    cmd = [trivy_bin, "fs", "--format", "cyclonedx", "--quiet", "--timeout", "35s", "--output", "-", "."]
    try:
        raw = run_read_only(cmd, repo_dir, env, allowed=(0,), timeout=40)
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        if isinstance(data, dict):
            return data, ""
        return None, "Trivy SBOM の出力形式が不正です。"
    except subprocess.TimeoutExpired:
        return None, "Trivy SBOM 生成がタイムアウトしました。"
    except Exception as exc:
        return None, f"Trivy SBOM 生成に失敗しました: {exc}"


def _is_internal_alb_terraform(repo_dir: Optional[Path], target: str) -> bool:
    """Return True if the Terraform module containing target defines an internal=true aws_lb."""
    if not repo_dir:
        return False
    mod_dir = (Path(repo_dir) / target).parent
    if not mod_dir.is_dir():
        return False
    for tf in mod_dir.glob("*.tf"):
        try:
            text = tf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r'resource\s+"aws_lb"\s+"', text) and re.search(r"^\s*internal\s*=\s*true\b", text, re.MULTILINE):
            return True
    return False


def parse_trivy(raw, files, match_component, *, repo_dir: Optional[Path] = None):
    """Parse Trivy FS JSON output into (misconfig_findings, vulnerability_advisories)."""
    text = raw.decode("utf-8", errors="ignore").strip() if isinstance(raw, (bytes, bytearray)) else str(raw).strip()
    if not text:
        return [], []
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Unexpected Trivy JSON output")
    results = data.get("Results") or []
    findings = []
    advisories = []
    seen_misconf = set()
    seen_vulns = set()

    for res in results:
        if not isinstance(res, dict):
            continue
        target = str(res.get("Target") or "").removeprefix("./")
        if target not in files:
            continue
        component = match_component(target)

        for vuln in res.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cve = str(vuln.get("VulnerabilityID") or "").strip()
            pkg = str(vuln.get("PkgName") or "").strip()
            if not cve or (cve, pkg) in seen_vulns:
                continue
            seen_vulns.add((cve, pkg))
            sev = _TRIVY_SEVERITY.get(str(vuln.get("Severity") or "MEDIUM").upper(), "medium")
            installed = str(vuln.get("InstalledVersion") or "").strip()
            raw_fixed = str(vuln.get("FixedVersion") or "").strip()
            fixed = _select_best_fixed_version(raw_fixed, installed)
            ecosystem = _infer_trivy_ecosystem(res, target)
            title = str(vuln.get("Title") or f"{pkg} ({installed}) vulnerability {cve}").strip()
            desc = str(vuln.get("Description") or title).strip()
            ref_url = str(vuln.get("PrimaryURL") or f"https://avd.aquasec.com/nvd/{cve.lower()}")
            clean_title = title.strip()
            pkg_prefix = f"{pkg.lower()}:"
            while clean_title.lower().startswith(pkg_prefix):
                clean_title = clean_title[len(pkg_prefix):].lstrip()
            if not clean_title:
                clean_title = title.strip()
            advisories.append({
                "cve": cve,
                "cwe_ids": [str(c).strip() for c in (vuln.get("CweIDs") or []) if str(c).strip()],
                "severity": sev.upper(),
                "package_name": pkg,
                "ecosystem": ecosystem,
                "pkg": pkg,
                "installed": installed,
                "installed_version": installed,
                "fixed_version": fixed,
                "safe_version": fixed,
                "fixed_versions_all": raw_fixed,
                "title": f"[Trivy] {pkg}: {clean_title} ({cve})" if cve not in clean_title else f"[Trivy] {pkg}: {clean_title}",
                "summary": desc,
                "target": target,
                "scanner": "trivy",
                "sources": [{"name": "Trivy/AVD", "url": ref_url}],
            })

        for misconf in res.get("Misconfigurations") or []:
            if not isinstance(misconf, dict):
                continue
            rule_id = str(misconf.get("ID") or misconf.get("AVDID") or "trivy-misconfig")
            cause = misconf.get("CauseMetadata") or {}
            line = cause.get("StartLine")
            line_int = line if type(line) is int and 1 <= line <= files[target] else 1
            key = (rule_id, target, line_int)
            if key in seen_misconf:
                continue
            seen_misconf.add(key)
            sev = _TRIVY_SEVERITY.get(str(misconf.get("Severity") or "MEDIUM").upper(), "medium")
            title = str(misconf.get("Title") or rule_id).strip()
            desc = str(misconf.get("Description") or misconf.get("Message") or title).strip()
            resolution = str(misconf.get("Resolution") or "").strip()
            if resolution:
                desc = f"{desc} 修正案: {resolution}"
            ref_url = str(misconf.get("PrimaryURL") or "https://avd.aquasec.com/")
            reachability = None
            if rule_id.upper() == "AVD-AWS-0054" and _is_internal_alb_terraform(repo_dir, target):
                sev = "medium"
                reachability = "mitigated"
                desc = f"{desc} （VPC内部専用ALB: internal = true を検知）"
            item_dict = {
                "severity": sev,
                "title": f"[trivy] {title} ({Path(target).name}:{line_int})",
                "file": f"{target}:{line_int} (Target: {component})",
                "target_node": component,
                "desc": desc,
                "official_source": ref_url,
                "scanner": "trivy",
                "rule_id": rule_id,
            }
            if reachability:
                item_dict["reachability"] = reachability
            findings.append(item_dict)

    return findings, advisories


def scan_semgrep_and_trivy(repo, match_component, *, include_sast=True, include_vuln=True):
    """Run Semgrep and Trivy on tracked working-tree files with bounded timeouts."""
    binaries = {
        "semgrep": executable("semgrep") if include_sast else None,
        "trivy": executable("trivy") if (include_sast or include_vuln) else None,
    }
    statuses = {name: "not_installed" for name in binaries}
    if not include_sast:
        statuses["semgrep"] = "disabled"
    if not (include_sast or include_vuln):
        statuses["trivy"] = "disabled"
    if not any(binaries.values()):
        return [], [], statuses

    with tempfile.TemporaryDirectory(prefix="repoaudt-ext-") as temp:
        root = Path(temp).resolve()
        directory = root / "source"
        directory.mkdir()
        real_home = str(Path.home())
        base_env = {
            "HOME": real_home,
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_USER_LOG_FILE": str(root / "semgrep.log"),
        }
        try:
            files, partial = stage_sources(
                repo.resolve(),
                directory,
                {"HOME": temp, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"},
                python_only=False,
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            statuses.update({name: "source_unavailable" for name, b in binaries.items() if b})
            return [], [], statuses

        if not files:
            for name, b in binaries.items():
                if b:
                    statuses[name] = "partial" if partial else "no_files"
            return [], [], statuses

        sast_findings = []
        advisories = []

        if binaries["semgrep"]:
            cmd = [
                binaries["semgrep"],
                "scan",
                "--config",
                "auto",
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--metrics=off",
                "--timeout",
                "10",
                "--max-target-bytes",
                "262144",
                ".",
            ]
            try:
                raw = run_read_only(cmd, directory, base_env, allowed=(0, 1), timeout=35)
                sast_findings.extend(parse_semgrep(raw, directory, files, match_component))
                statuses["semgrep"] = "partial" if partial else "complete"
            except subprocess.TimeoutExpired:
                statuses["semgrep"] = "timeout"
            except (OSError, ValueError, KeyError, TypeError):
                statuses["semgrep"] = "tool_error"

        if binaries["trivy"]:
            scanners = []
            if include_vuln:
                scanners.extend(["vuln", "license"])
            if include_sast:
                scanners.append("misconfig")
            cmd = [
                binaries["trivy"],
                "fs",
                "--scanners",
                ",".join(scanners),
                "--format",
                "json",
                "--quiet",
                "--timeout",
                "30s",
                ".",
            ]
            try:
                raw = run_read_only(cmd, directory, base_env, allowed=(0,), timeout=35)
                misconfs, vulns = parse_trivy(raw, files, match_component, repo_dir=directory)
                lic_findings, lic_summary = parse_trivy_licenses(raw, files, match_component)
                if include_sast:
                    sast_findings.extend(misconfs)
                if include_vuln:
                    advisories.extend(vulns)
                    sast_findings.extend(lic_findings)
                    statuses["license_summary"] = lic_summary
                statuses["trivy"] = "partial" if partial else "complete"
            except subprocess.TimeoutExpired:
                statuses["trivy"] = "timeout"
            except (OSError, ValueError, KeyError, TypeError):
                statuses["trivy"] = "tool_error"

        return sast_findings, advisories, statuses


_HADOLINT_SEVERITY = {"error": "high", "warning": "medium", "info": "low", "style": "low"}
_TEST_OR_DOC_SEGMENTS = ("test", "tests", "__tests__", "spec", "fixture", "fixtures", "mock", "mocks", "docs", "doc", "example", "examples")
_SENSITIVE_KEY_EXTS = (".p12", ".pfx", ".jks", ".keystore")
_SUSPICIOUS_INSTALL_RE = re.compile(
    r"(?:curl\s+|wget\s+|\|\s*(?:sh|bash|zsh)\b|base64\s+-d|\beval\s+|\bnode\s+-e\b|\bpython3?\s+-c\b)",
    re.IGNORECASE,
)


def _is_test_or_doc_relpath(rel_path: str) -> bool:
    parts = [p.lower() for p in Path(rel_path).parts]
    name = Path(rel_path).name.lower()
    if any(seg in parts for seg in _TEST_OR_DOC_SEGMENTS):
        return True
    return name.startswith("test_") or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".md"))


def parse_gitleaks_git(raw: str, match_component, *, repo_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    data = json.loads(raw or "[]")
    if not isinstance(data, list):
        return []
    findings: List[Dict[str, Any]] = []
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("File") or "").lstrip("./")
        if not rel or _is_test_or_doc_relpath(rel):
            continue
        rule = str(item.get("RuleID") or "secret")
        commit = str(item.get("Commit") or "")[:8]
        line = int(item.get("StartLine") or 1)
        if repo_root is not None:
            if rule == "generic-api-key" and _is_benign_generic_api_key(repo_root, rel, line):
                continue
            if rule == "private-key" and _is_benign_private_key_doc(repo_root, rel, line):
                continue
        dedup_key = (rel, rule, line, commit)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        is_generic = rule == "generic-api-key"
        findings.append({
            "severity": "high" if is_generic else "critical",
            "category": "secrets",
            "rule_id": f"gitleaks-git:{rule}",
            "title": f"[gitleaks-history] Git 履歴にシークレット候補 ({rule}) が残存 ({Path(rel).name}:{line} @ {commit or 'history'})",
            "file": f"{rel}:{line} (Target: {match_component(rel)})",
            "desc": (
                f"Git コミット履歴 (`{commit or 'past commit'}`) 内の `{rel}` (L{line}) で `{rule}` が検出されました。"
                "HEAD から削除済みでも履歴から復元可能なため、該当シークレットを無効化（Revoke/Rotate）し、必要に応じ Git 履歴からも削除してください。"
            ),
            "official_source": "https://github.com/gitleaks/gitleaks",
            "scanner": "gitleaks-git",
            "confidence": "medium" if is_generic else "high",
            "commit_sha": commit,
        })
    return findings


def scan_git_history_secrets(repo: Path, match_component, *, max_commits: int = 100) -> Tuple[List[Dict[str, Any]], str]:
    """Scan recent Git commit history with `gitleaks git` (--redact=100, read-only)."""
    gitleaks_bin = executable("gitleaks")
    if not gitleaks_bin:
        return [], "unavailable"
    repo_path = Path(repo)
    if not (repo_path / ".git").exists():
        return [], "no_files"
    cmd = [
        gitleaks_bin,
        "git",
        f"--log-opts=-n {max(1, int(max_commits))}",
        "--no-banner",
        "--log-level=error",
        "--redact=100",
        "--max-decode-depth=0",
        "--report-format=json",
        "--report-path=-",
        "--exit-code=10",
        ".",
    ]
    base_env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
    try:
        raw = run_read_only(cmd, repo_path, base_env, allowed=(0, 10), timeout=35)
        return parse_gitleaks_git(raw, match_component, repo_root=repo_path), "complete"
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except (OSError, ValueError, KeyError, TypeError):
        return [], "tool_error"


def parse_hadolint(raw: str, repo_root: Path, match_component) -> List[Dict[str, Any]]:
    data = json.loads(raw or "[]")
    if not isinstance(data, list):
        return []
    findings: List[Dict[str, Any]] = []
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "DL0000")
        level = str(item.get("level") or "warning").lower()
        sev = _HADOLINT_SEVERITY.get(level, "medium")
        if sev == "low":
            # Keep actionable error/warning Dockerfile issues; skip minor style nitpicks
            continue
        line = int(item.get("line") or 1)
        message = str(item.get("message") or "").strip()
        raw_file = str(item.get("file") or "Dockerfile")
        try:
            rel = str(Path(raw_file).resolve().relative_to(repo_root.resolve()))
        except Exception:
            rel = raw_file.lstrip("./")
        key = (rel, code, line)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "severity": sev,
            "category": "iac",
            "rule_id": f"hadolint:{code}",
            "title": f"[hadolint] {code}: {message} ({Path(rel).name}:{line})",
            "file": f"{rel}:{line} (Target: {match_component(rel)})",
            "desc": f"Dockerfile 静的監査 (Hadolint `{code}`): {message}",
            "official_source": f"https://github.com/hadolint/hadolint/wiki/{code}",
            "scanner": "hadolint",
            "confidence": "high",
        })
    return findings


def scan_hadolint(repo: Path, match_component) -> Tuple[List[Dict[str, Any]], str]:
    """Scan all Dockerfiles in the repository with Hadolint."""
    hadolint_bin = executable("hadolint")
    if not hadolint_bin:
        return [], "unavailable"
    repo_path = Path(repo)
    dockerfiles: List[str] = []
    ignore_dirs = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".next", ".venv", "venv"}
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fn in filenames:
            low = fn.lower()
            if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
                rel = str(Path(root, fn).relative_to(repo_path))
                dockerfiles.append(rel)
    if not dockerfiles:
        return [], "no_files"
    cmd = [hadolint_bin, "--format", "json", *sorted(dockerfiles)[:20]]
    base_env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
    try:
        raw = run_read_only(cmd, repo_path, base_env, allowed=(0, 1), timeout=20)
        return parse_hadolint(raw, repo_path, match_component), "complete"
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except (OSError, ValueError, KeyError, TypeError):
        return [], "tool_error"


def parse_trufflehog(raw: str, match_component) -> List[Dict[str, Any]]:
    """Parse TruffleHog NDJSON output without ever exposing raw secret values."""
    findings: List[Dict[str, Any]] = []
    seen = set()
    for line_str in (raw or "").splitlines():
        line_str = line_str.strip()
        if not line_str or not line_str.startswith("{"):
            continue
        try:
            item = json.loads(line_str)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        detector = str(item.get("DetectorName") or item.get("DetectorType") or "Secret").strip()
        fs_meta = (
            (item.get("SourceMetadata") or {}).get("Data") or {}
        ).get("Filesystem") or {}
        rel = str(fs_meta.get("file") or "").lstrip("./")
        line_no = int(fs_meta.get("line") or 1)
        if not rel or _is_test_or_doc_relpath(rel):
            continue
        key = (rel, line_no, detector.lower())
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "severity": "critical",
            "category": "secrets",
            "rule_id": f"trufflehog:{detector.lower()}",
            "title": f"[trufflehog] {detector} シークレット候補を検出 ({Path(rel).name}:{line_no})",
            "file": f"{rel}:{line_no} (Target: {match_component(rel)})",
            "desc": (
                f"TruffleHog (`{detector}` 検出器) が `{rel}` (L{line_no}) で認証情報パターンを検出しました（生シークレットはマスク済み）。"
                "実在する認証情報であれば即時無効化（Revoke/Rotate）し、環境変数またはシークレットマネージャーへ移行してください。"
            ),
            "official_source": "https://github.com/trufflesecurity/trufflehog",
            "scanner": "trufflehog",
            "confidence": "high",
        })
    return findings


def scan_trufflehog(repo: Path, match_component) -> Tuple[List[Dict[str, Any]], str]:
    """Run TruffleHog filesystem scan with --no-verification (strictly offline/local)."""
    th_bin = executable("trufflehog")
    if not th_bin:
        return [], "unavailable"
    repo_path = Path(repo)
    with tempfile.TemporaryDirectory(prefix="repoaudt-th-") as tmp:
        exclude_file = Path(tmp) / "exclude.txt"
        exclude_file.write_text(
            r"""(^|/)(\.git|node_modules|vendor|dist|build|\.next|__pycache__|\.venv|venv)(/|$)
\.lock$
package-lock\.json$
yarn\.lock$
pnpm-lock\.yaml$
""",
            encoding="utf-8",
        )
        cmd = [
            th_bin,
            "filesystem",
            "--json",
            "--no-verification",
            "--no-update",
            "--exclude-paths",
            str(exclude_file),
            ".",
        ]
        base_env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
        try:
            raw = run_read_only(cmd, repo_path, base_env, allowed=(0, 183), timeout=35)
            return parse_trufflehog(raw, match_component), "complete"
        except subprocess.TimeoutExpired:
            return [], "timeout"
        except (OSError, ValueError, KeyError, TypeError):
            return [], "tool_error"


_POPULAR_NPM_PACKAGES = {
    "react", "react-dom", "next", "express", "axios", "lodash", "typescript",
    "tailwindcss", "eslint", "prettier", "prisma", "zod", "stripe", "openai",
    "chalk", "commander", "dotenv", "cors", "jsonwebtoken", "mongoose",
    "sequelize", "uuid", "moment", "dayjs", "webpack", "vite", "vitest",
    "jest", "playwright", "puppeteer", "socket.io", "redis", "mysql2",
    "multer", "helmet", "bcrypt", "bcryptjs", "yup", "formik", "rxjs",
    "nodemailer", "winston", "pino", "fastify", "nestjs", "svelte", "vue",
}

_POPULAR_PYPI_PACKAGES = {
    "requests", "fastapi", "django", "flask", "pydantic", "numpy", "pandas",
    "boto3", "httpx", "uvicorn", "sqlalchemy", "pytest", "celery", "redis",
    "cryptography", "pyjwt", "pillow", "scipy", "torch", "transformers",
    "openai", "anthropic", "aiohttp", "beautifulsoup4", "lxml", "pyyaml",
    "jinja2", "click", "typer", "alembic", "psycopg2", "pymongo", "sentry-sdk",
}


def _levenshtein_1(a: str, b: str) -> bool:
    """Return True if two strings have Levenshtein edit distance == 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    i = j = diffs = 0
    while i < len(shorter) and j < len(longer):
        if shorter[i] != longer[j]:
            diffs += 1
            if diffs > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


def _detect_typosquat(pkg_name: str, popular: set[str]) -> Optional[str]:
    low = pkg_name.strip().lower()
    if not low or low.startswith("@") or len(low) < 4 or low in popular:
        return None
    for target in popular:
        if len(target) >= 4 and _levenshtein_1(low, target):
            return target
    return None


def scan_web_and_supply_chain_config(repo: Path, match_component) -> Tuple[List[Dict[str, Any]], str]:
    """Fast built-in audit for Next.js risky config, CORS wildcard+credentials, suspicious npm install scripts, and committed keystores/sourcemaps."""
    repo_path = Path(repo)
    findings: List[Dict[str, Any]] = []
    ignore_dirs = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".next", ".venv", "venv"}

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fn in filenames:
            full = Path(root, fn)
            rel = str(full.relative_to(repo_path))
            low_name = fn.lower()

            # 1. Committed keystore / PKCS12 archives
            if low_name.endswith(_SENSITIVE_KEY_EXTS) and not _is_test_or_doc_relpath(rel):
                findings.append({
                    "severity": "critical",
                    "category": "secrets",
                    "rule_id": "committed-keystore-file",
                    "title": f"🚨 [認証ファイル露出] 秘密鍵アーカイブ `{fn}` がコミットされています",
                    "file": f"{rel}:1 (Target: {match_component(rel)})",
                    "desc": f"`{rel}` は秘密鍵・証明書を含むキーストアファイルです。直ちに証明書を失効させ、`git rm --cached {rel}` で除外してください。",
                    "fix_cmd": f"git rm --cached {rel} && echo '{rel}' >> .gitignore",
                    "scanner": "web-config-audit",
                    "confidence": "high",
                })
                continue

            # 2. Committed JS source maps (.js.map / .mjs.map)
            if low_name.endswith((".js.map", ".mjs.map")) and not _is_test_or_doc_relpath(rel):
                findings.append({
                    "severity": "medium",
                    "category": "sast",
                    "rule_id": "committed-sourcemap",
                    "title": f"[設定監査] ビルド成果物のソースマップ `{fn}` がコミットされています",
                    "file": f"{rel}:1 (Target: {match_component(rel)})",
                    "desc": f"`{rel}` がリポジトリに含まれています。本番配信された場合、元のソースコード構造が外部から閲覧可能になる恐れがあります。",
                    "fix_cmd": f"git rm --cached {rel} && echo '*.map' >> .gitignore",
                    "scanner": "web-config-audit",
                    "confidence": "high",
                })
                continue

            # 3. Next.js dangerouslyAllowSVG: true
            if low_name.startswith("next.config.") and low_name.endswith((".js", ".mjs", ".cjs", ".ts")):
                try:
                    text = full.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for idx, ln in enumerate(text.splitlines(), 1):
                    if re.search(r"\bdangerouslyAllowSVG\s*:\s*true\b", ln):
                        findings.append({
                            "severity": "high",
                            "category": "sast",
                            "rule_id": "nextjs-dangerously-allow-svg",
                            "title": f"[Web設定監査] Next.js で dangerouslyAllowSVG: true が有効化されています ({fn}:{idx})",
                            "file": f"{rel}:{idx} (Target: {match_component(rel)})",
                            "desc": (
                                f"`{rel}` (L{idx}) で `dangerouslyAllowSVG: true` が設定されています。"
                                "Next.js Image Optimization API の SVG 経由 XSS/RCE リスクが高まるため、`contentSecurityPolicy` の厳格化または無効化を推奨します。"
                            ),
                            "official_source": "https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowsvg",
                            "scanner": "web-config-audit",
                            "confidence": "high",
                        })

            # 4. package.json suspicious preinstall/postinstall scripts
            if low_name == "package.json":
                try:
                    pkg_data = json.loads(full.read_text(encoding="utf-8", errors="ignore"))
                except (OSError, ValueError):
                    continue
                scripts = pkg_data.get("scripts") if isinstance(pkg_data, dict) else None
                if isinstance(scripts, dict):
                    for hook in ("preinstall", "install", "postinstall", "prepare"):
                        cmd_val = str(scripts.get(hook) or "").strip()
                        if cmd_val and _SUSPICIOUS_INSTALL_RE.search(cmd_val):
                            findings.append({
                                "severity": "critical",
                                "category": "sast",
                                "rule_id": f"npm-suspicious-{hook}",
                                "title": f"🚨 [サプライチェーン監査] package.json の `{hook}` に外部取得/シェル実行コマンドが含まれます",
                                "file": f"{rel}:1 (Target: {match_component(rel)})",
                                "desc": f"`{rel}` の `scripts.{hook}` に不審なコマンド（`{cmd_val[:120]}`）が含まれています。`npm install` 時に自動実行されるため、サプライチェーン攻撃リスクとして内容を確認してください。",
                                "scanner": "web-config-audit",
                                "confidence": "high",
                            })
                for dep_section in ("dependencies", "devDependencies"):
                    dep_map = pkg_data.get(dep_section) if isinstance(pkg_data, dict) else None
                    if not isinstance(dep_map, dict):
                        continue
                    for dep_name, dep_ver in dep_map.items():
                        dep_s = str(dep_name or "").strip()
                        ver_s = str(dep_ver or "").strip()
                        if re.match(r"^(?:http://|git\+http://)", ver_s, re.IGNORECASE):
                            findings.append({
                                "severity": "high",
                                "category": "sca",
                                "rule_id": "npm-insecure-tarball-url",
                                "title": f"[サプライチェーン監査] `{dep_s}` が平文 HTTP URL から取得されています",
                                "file": f"{rel}:1 (Target: {match_component(rel)})",
                                "desc": f"`{rel}` の `{dep_section}.{dep_s}` が平文 HTTP (`{ver_s[:100]}`) を参照しています。中間者攻撃やパッケージ差し替えリスクがあるため npm レジストリまたは HTTPS+integrity 検証へ移行してください。",
                                "package_name": dep_s,
                                "scanner": "web-config-audit",
                                "confidence": "high",
                            })
                        typo_target = _detect_typosquat(dep_s, _POPULAR_NPM_PACKAGES)
                        if typo_target:
                            findings.append({
                                "severity": "high",
                                "category": "sca",
                                "rule_id": "npm-typosquat-suspect",
                                "title": f"⚠️ [サプライチェーン監査] `{dep_s}` は人気パッケージ `{typo_target}` のタイポスクワッティング疑いがあります",
                                "file": f"{rel}:1 (Target: {match_component(rel)})",
                                "desc": f"`{rel}` の `{dep_section}` に `{dep_s}` が含まれています（人気パッケージ `{typo_target}` と1文字違い）。意図した正規パッケージか確認してください。",
                                "package_name": dep_s,
                                "scanner": "web-config-audit",
                                "confidence": "medium",
                            })

            # 4b. Python requirements.txt insecure index/URL & typosquatting
            if low_name == "requirements.txt" or (low_name.startswith("requirements") and low_name.endswith(".txt")):
                try:
                    req_lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError:
                    req_lines = []
                for idx, rline in enumerate(req_lines, 1):
                    stripped = rline.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if re.search(r"--(?:extra-)?index-url\s+http://", stripped, re.IGNORECASE):
                        findings.append({
                            "severity": "high",
                            "category": "sca",
                            "rule_id": "pypi-insecure-index-url",
                            "title": f"[サプライチェーン監査] `{fn}` に平文 HTTP の PyPI インデックスURLが含まれます (L{idx})",
                            "file": f"{rel}:{idx} (Target: {match_component(rel)})",
                            "desc": f"`{rel}` (L{idx}) で平文 `http://` の index-url が指定されています。Dependency Confusion / 中間者攻撃リスクがあります。",
                            "scanner": "web-config-audit",
                            "confidence": "high",
                        })
                        continue
                    m_pkg = re.match(r"^([A-Za-z0-9_.-]+)", stripped)
                    if m_pkg:
                        py_pkg = m_pkg.group(1)
                        typo_target = _detect_typosquat(py_pkg, _POPULAR_PYPI_PACKAGES)
                        if typo_target:
                            findings.append({
                                "severity": "high",
                                "category": "sca",
                                "rule_id": "pypi-typosquat-suspect",
                                "title": f"⚠️ [サプライチェーン監査] `{py_pkg}` は人気 PyPI パッケージ `{typo_target}` のタイポスクワッティング疑いがあります",
                                "file": f"{rel}:{idx} (Target: {match_component(rel)})",
                                "desc": f"`{rel}` (L{idx}) の `{py_pkg}` は人気パッケージ `{typo_target}` と1文字違いです。正規パッケージか確認してください。",
                                "package_name": py_pkg,
                                "scanner": "web-config-audit",
                                "confidence": "medium",
                            })

            # 4c. Python setup.py install-time network/shell execution
            if low_name == "setup.py" and not _is_test_or_doc_relpath(rel):
                try:
                    setup_txt = full.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    setup_txt = ""
                if "setup(" in setup_txt and re.search(r"\b(?:urllib\.request|requests\.|subprocess\.|os\.system|eval\(|exec\()", setup_txt):
                    findings.append({
                        "severity": "high",
                        "category": "sast",
                        "rule_id": "pypi-setup-exec",
                        "title": f"[サプライチェーン監査] `setup.py` 内にインストール時外部通信/シェル実行が含まれます",
                        "file": f"{rel}:1 (Target: {match_component(rel)})",
                        "desc": f"`{rel}` に `subprocess` / `os.system` / `urllib` / `eval` 等が含まれています。`pip install` 時の任意コード実行リスクがないか確認してください。",
                        "scanner": "web-config-audit",
                        "confidence": "medium",
                    })

            # 5. Dangerous CORS wildcard + credentials: true in TS/JS backend files
            if low_name.endswith((".ts", ".js", ".mjs", ".cjs")) and not _is_test_or_doc_relpath(rel):
                try:
                    if full.stat().st_size > 200_000:
                        continue
                    text = full.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "cors" in text.lower() and "credentials" in text:
                    m_cors = re.search(
                        r"(?:cors|enableCors)\s*\(\s*\{[^}]{0,300}(?:origin\s*:\s*(?:['\"]\*['\"]|true)[^}]{0,200}credentials\s*:\s*true|credentials\s*:\s*true[^}]{0,200}origin\s*:\s*(?:['\"]\*['\"]|true))",
                        text,
                        re.IGNORECASE | re.DOTALL,
                    )
                    if m_cors:
                        line_no = text[: m_cors.start()].count("\n") + 1
                        findings.append({
                            "severity": "high",
                            "category": "sast",
                            "rule_id": "cors-wildcard-credentials",
                            "title": f"[Web設定監査] CORS で origin 全許可と credentials: true が併用されています ({fn}:{line_no})",
                            "file": f"{rel}:{line_no} (Target: {match_component(rel)})",
                            "desc": f"`{rel}` (L{line_no}) で `origin: '*'` または `origin: true` と `credentials: true` が同時指定されています。任意オリジンからの認証済みリクエスト（CSRF/情報窃取）を許すため、許可オリジンを明示的なホワイトリストに制限してください。",
                            "scanner": "web-config-audit",
                            "confidence": "high",
                        })

    return findings, "complete"


def scan_extended_security(repo: Path, match_component, *, include_sast: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run extended scanners: gitleaks git history, hadolint, trufflehog (--no-verification), and web/supply-chain config checks."""
    all_findings: List[Dict[str, Any]] = []
    statuses: Dict[str, Any] = {}

    git_hist_findings, git_hist_status = scan_git_history_secrets(repo, match_component)
    all_findings.extend(git_hist_findings)
    statuses["gitleaks_git"] = git_hist_status

    th_findings, th_status = scan_trufflehog(repo, match_component)
    all_findings.extend(th_findings)
    statuses["trufflehog"] = th_status

    if include_sast:
        hado_findings, hado_status = scan_hadolint(repo, match_component)
        all_findings.extend(hado_findings)
        statuses["hadolint"] = hado_status

        web_findings, web_status = scan_web_and_supply_chain_config(repo, match_component)
        all_findings.extend(web_findings)
        statuses["web_config"] = web_status
    else:
        statuses["hadolint"] = "disabled"
        statuses["web_config"] = "disabled"

    return all_findings, statuses
