"""Bounded local Ruff and Gitleaks scans of tracked working-tree files."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

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
        config.write_text("[extend]\nuseDefault = true\n")
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


def _parse_version_tuple(raw: str):
    m = re.search(r"(\d+(?:\.\d+)*)", str(raw or "").strip())
    if not m:
        return None
    return tuple(int(part) for part in m.group(1).split("."))


def _select_best_fixed_version(raw_fixed: str, installed: str = "") -> str:
    """Pick the single best upgrade target from comma-separated Trivy FixedVersion values."""
    candidates = [part.strip() for part in re.split(r"[,;]", str(raw_fixed or "")) if part.strip()]
    if not candidates:
        return ""
    if len(candidates) == 1:
        return candidates[0]

    parsed = [(cand, _parse_version_tuple(cand)) for cand in candidates]
    valid = [(cand, ver) for cand, ver in parsed if ver is not None]
    if not valid:
        return candidates[-1]

    inst_ver = _parse_version_tuple(installed)
    if inst_ver is not None:
        same_major_upgrades = [
            (cand, ver) for cand, ver in valid if ver[0] == inst_ver[0] and ver >= inst_ver
        ]
        if same_major_upgrades:
            return min(same_major_upgrades, key=lambda item: item[1])[0]
        higher_upgrades = [(cand, ver) for cand, ver in valid if ver >= inst_ver]
        if higher_upgrades:
            return min(higher_upgrades, key=lambda item: item[1])[0]

    return max(valid, key=lambda item: item[1])[0]


def parse_trivy(raw, files, match_component):
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
            advisories.append({
                "cve": cve,
                "severity": sev.upper(),
                "package_name": pkg,
                "ecosystem": ecosystem,
                "pkg": pkg,
                "installed": installed,
                "installed_version": installed,
                "fixed_version": fixed,
                "safe_version": fixed,
                "fixed_versions_all": raw_fixed,
                "title": f"[Trivy] {pkg}: {title} ({cve})" if cve not in title else f"[Trivy] {pkg}: {title}",
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
            findings.append({
                "severity": sev,
                "title": f"[trivy] {title} ({Path(target).name}:{line_int})",
                "file": f"{target}:{line_int} (Target: {component})",
                "target_node": component,
                "desc": desc,
                "official_source": ref_url,
                "scanner": "trivy",
                "rule_id": rule_id,
            })

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
                scanners.append("vuln")
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
                misconfs, vulns = parse_trivy(raw, files, match_component)
                if include_sast:
                    sast_findings.extend(misconfs)
                if include_vuln:
                    advisories.extend(vulns)
                statuses["trivy"] = "partial" if partial else "complete"
            except subprocess.TimeoutExpired:
                statuses["trivy"] = "timeout"
            except (OSError, ValueError, KeyError, TypeError):
                statuses["trivy"] = "tool_error"

        return sast_findings, advisories, statuses
