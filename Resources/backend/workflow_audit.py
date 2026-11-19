"""Local GitHub Actions static analysis with optional zizmor."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import unquote

WORKFLOWS = Path(".github/workflows")
MAX_FILES = 25
MAX_FILE_BYTES = 256 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
ZIZMOR_PATHS = (Path("/opt/homebrew/bin/zizmor"), Path("/usr/local/bin/zizmor"))
RULE = re.compile(r"zizmor/([a-z0-9-]{1,80})")
LEVELS = {"error": "high", "warning": "medium", "note": "low"}


def workflow_files(repo):
    github = repo / ".github"
    directory = repo / WORKFLOWS
    if github.is_symlink() or directory.is_symlink() or not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.suffix in (".yml", ".yaml") and not path.is_symlink() and path.is_file()
    )


def read_workflow(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            return None
        content = stream.read(MAX_FILE_BYTES + 1)
    return content if len(content) <= MAX_FILE_BYTES else None


def parse_sarif(raw, staged, match_component):
    sarif = json.loads(raw)
    runs = sarif["runs"]
    if sarif["version"] != "2.1.0" or len(runs) != 1:
        raise ValueError("Unexpected SARIF format")
    results = runs[0]["results"]
    if not isinstance(results, list):
        raise ValueError("Missing SARIF results")
    findings = []
    seen = set()
    for item in results:
        rule = RULE.fullmatch(item["ruleId"])
        locations = item.get("locations", [])
        if rule is None or not locations:
            raise ValueError("Invalid SARIF finding")
        location = locations[0]["physicalLocation"]
        path = unquote(location["artifactLocation"]["uri"])
        line = location["region"]["startLine"]
        if path not in staged or type(line) is not int or not 1 <= line <= staged[path]:
            raise ValueError("SARIF finding is outside the audit input")
        name = rule[1]
        key = (name, path, line)
        if key in seen:
            continue
        seen.add(key)
        component = match_component(path)
        findings.append(
            {
                "severity": LEVELS.get(item.get("level"), "info"),
                "title": f"[zizmor] {name} ({Path(path).name}:{line})",
                "file": f"{path}:{line} (Target: {component})",
                "target_node": component,
                "desc": f"zizmor detected the `{name}` rule at this location. Consult the linked rule for its rationale and recommended remediation.",
                "official_source": f"https://docs.zizmor.sh/audits/#{name}",
                "scanner": "zizmor",
                "rule_id": name,
            }
        )
    return findings


def run_zizmor(files, match_component):
    """Return findings and the reason when the caller needs to fall back."""
    if not files:
        return [], "no_workflows"
    binary = next(
        (str(path) for path in ZIZMOR_PATHS if os.access(path, os.X_OK)), None
    )
    if not binary:
        return None, "not_installed"
    if len(files) > MAX_FILES:
        return None, "input_limit"
    try:
        with tempfile.TemporaryDirectory(prefix="repoaudt-workflows-") as tmp:
            directory = Path(tmp)
            (directory / WORKFLOWS).mkdir(parents=True)
            staged = {}
            for path in files:
                content = read_workflow(path)
                if content is None:
                    return None, "input_limit"
                relative = (WORKFLOWS / path.name).as_posix()
                (directory / relative).write_bytes(content)
                staged[relative] = len(content.splitlines())
            with tempfile.TemporaryFile() as report:
                result = subprocess.run(
                    [
                        binary,
                        "--offline",
                        "--no-config",
                        "--no-ignores",
                        "--strict-collection",
                        "--format=sarif",
                        "--",
                        *staged,
                    ],
                    cwd=directory,
                    env={"HOME": tmp, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"},
                    stdin=subprocess.DEVNULL,
                    stdout=report,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
                if result.returncode != 0:
                    return None, "tool_error"
                report.seek(0)
                raw = report.read(MAX_REPORT_BYTES + 1)
                if len(raw) > MAX_REPORT_BYTES:
                    return None, "output_limit"
            return parse_sarif(raw, staged, match_component), "complete"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None, "tool_error"
