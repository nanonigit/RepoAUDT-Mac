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
