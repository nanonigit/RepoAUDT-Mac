"""Local GitHub Actions static analysis with optional zizmor."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

WORKFLOWS = Path(".github/workflows")
MAX_FILES = 25
MAX_FILE_BYTES = 256 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
ZIZMOR_PATHS = (Path("/opt/homebrew/bin/zizmor"), Path("/usr/local/bin/zizmor"))
ACTIONLINT_PATHS = (Path("/opt/homebrew/bin/actionlint"), Path("/usr/local/bin/actionlint"))
RULE = re.compile(r"zizmor/([a-z0-9-]{1,80})")
LEVELS = {"error": "high", "warning": "medium", "note": "low"}

_YAML_KEY_RE = re.compile(r'^["\']?([A-Za-z0-9_.-]+)["\']?\s*:(?:\s+(.*)|\s*$)')
_BLOCK_SCALAR_RE = re.compile(r'^[|>][+-]?\d*(?:\s+#.*)?$')
UNTRUSTED_GHA_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|discussion|commits|head_commit|pages|workflow_run)\.[A-Za-z0-9_.\[\]]*(?:title|body|message|ref|label|name|email|page_name|head_branch))\s*\}\}",
    re.IGNORECASE,
)


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


def read_small_file(path):
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
                "line_num": line,
                "path": path,
            }
        )
    return group_zizmor_findings(findings)


def group_zizmor_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group zizmor findings by (file_path, rule_id) while preserving line list and first line link."""
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str]] = []
    for item in findings:
        path = str(item.get("path") or "").strip()
        rule_id = str(item.get("rule_id") or "").strip()
        line_num = item.get("line_num")
        if not path or not rule_id or type(line_num) is not int:
            continue
        key = (path, rule_id)
        if key not in groups:
            order.append(key)
            groups[key] = {**item, "lines": [line_num]}
        else:
            if line_num not in groups[key]["lines"]:
                groups[key]["lines"].append(line_num)

    grouped: List[Dict[str, Any]] = []
    for key in order:
        g = dict(groups[key])
        path, rule_id = key
        lines = sorted(g.pop("lines"))
        g.pop("line_num", None)
        g.pop("path", None)
        first_line = lines[0]
        component = g.get("target_node", "")
        g["lines"] = lines
        g["occurrence_count"] = len(lines)
        g["file"] = f"{path}:{first_line} (Target: {component})"
        if len(lines) > 1:
            preview = ", ".join(f"L{ln}" for ln in lines[:5]) + (", ..." if len(lines) > 5 else "")
            g["title"] = f"[zizmor] {rule_id} ({Path(path).name} — {len(lines)}箇所: {preview})"
        else:
            g["title"] = f"[zizmor] {rule_id} ({Path(path).name}:{first_line})"
        grouped.append(g)
    return grouped


def annotate_workflow_reachability(files: List[Path], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect safe workflow patterns (explicit checkout ref / toJSON) and mark as mitigated."""
    content_by_name: Dict[str, str] = {}
    for p in files:
        try:
            content_by_name[(WORKFLOWS / p.name).as_posix()] = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

    for item in findings:
        file_loc = str(item.get("file") or "").split(" (Target:", 1)[0]
        rel_path = file_loc.rsplit(":", 1)[0] if ":" in file_loc else file_loc
        text = content_by_name.get(rel_path, "")
        if not text:
            continue
        rule_id = str(item.get("rule_id") or "")
        if rule_id == "dangerous-triggers" and "pull_request_target" in text:
            if re.search(r"ref:\s*\$\{\{\s*github\.(?:workflow_sha|event\.pull_request\.base\.sha)\s*\}\}", text):
                item["reachability"] = "mitigated"
                item["severity"] = "medium"
                item["desc"] = str(item.get("desc") or "") + " [Mitigated: actions/checkout が安全なベース/ワークフローSHAを明示指定しています]"
        elif rule_id == "template-injection":
            lines_list = item.get("lines") or []
            file_lines = text.splitlines()
            if lines_list and all(
                1 <= ln <= len(file_lines) and "tojson(" in file_lines[ln - 1].lower()
                for ln in lines_list
            ):
                item["reachability"] = "mitigated"
                item["severity"] = "medium"
                item["desc"] = str(item.get("desc") or "") + " [Mitigated: toJSON() による安全なシリアライズを検知]"
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
                content = read_small_file(path)
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
            parsed = parse_sarif(raw, staged, match_component)
            return annotate_workflow_reachability(files, parsed), "complete"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None, "tool_error"


def parse_actionlint(raw: bytes, staged: Dict[str, int], match_component: Any) -> List[Dict[str, Any]]:
    """Parse actionlint JSON output into normalized workflow findings."""
    text = raw.decode("utf-8", errors="ignore").strip()
    if not text:
        return []
    entries = json.loads(text)
    if not isinstance(entries, list):
        raise ValueError("Unexpected actionlint JSON format")
    findings: List[Dict[str, Any]] = []
    seen = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        path = str(item.get("filepath") or "").removeprefix("./")
        line = item.get("line")
        kind = str(item.get("kind") or "syntax")
        message = str(item.get("message") or "").strip()
        if path not in staged or type(line) is not int or not 1 <= line <= staged[path]:
            continue
        key = (kind, path, line)
        if key in seen:
            continue
        seen.add(key)
        severity = "medium" if kind in ("credentials", "runner-label", "shellcheck") else "low"
        component = match_component(path)
        findings.append({
            "severity": severity,
            "title": f"[actionlint] {kind}: {message[:80]} ({Path(path).name}:{line})",
            "file": f"{path}:{line} (Target: {component})",
            "target_node": component,
            "desc": message or f"actionlint detected `{kind}` issue at this location.",
            "official_source": "https://github.com/rhysd/actionlint/blob/main/docs/checks.md",
            "scanner": "actionlint",
            "rule_id": f"actionlint-{kind}",
        })
    return findings


def run_actionlint(files: List[Path], match_component: Any) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """Run actionlint (with shellcheck) on workflow files in an isolated temp directory."""
    if not files:
        return [], "no_workflows"
    binary = next(
        (str(path) for path in ACTIONLINT_PATHS if os.access(path, os.X_OK)), None
    )
    if not binary:
        return None, "not_installed"
    if len(files) > MAX_FILES:
        return None, "input_limit"
    try:
        with tempfile.TemporaryDirectory(prefix="repoaudt-actionlint-") as tmp:
            directory = Path(tmp)
            (directory / WORKFLOWS).mkdir(parents=True)
            staged: Dict[str, int] = {}
            for path in files:
                content = read_small_file(path)
                if content is None:
                    return None, "input_limit"
                relative = (WORKFLOWS / path.name).as_posix()
                (directory / relative).write_bytes(content)
                staged[relative] = len(content.splitlines())
            with tempfile.TemporaryFile() as report:
                result = subprocess.run(
                    [binary, "-format", "{{json .}}", *staged],
                    cwd=directory,
                    env={"HOME": tmp, "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "en_US.UTF-8"},
                    stdin=subprocess.DEVNULL,
                    stdout=report,
                    stderr=subprocess.DEVNULL,
                    timeout=20,
                    check=False,
                )
                if result.returncode not in (0, 1):
                    return None, "tool_error"
                report.seek(0)
                raw = report.read(MAX_REPORT_BYTES + 1)
                if len(raw) > MAX_REPORT_BYTES:
                    return None, "output_limit"
            return parse_actionlint(raw, staged, match_component), "complete"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None, "tool_error"


def _derive_env_var_name(expr: str, existing_vars: set) -> str:
    """Derive a collision-free uppercase environment variable name from a GitHub Actions expression."""
    inner = re.sub(r"^\$\{\{\s*|\s*\}\}$", "", expr).strip()
    inner = re.sub(r"^github\.event\.", "", inner, flags=re.IGNORECASE)
    inner = re.sub(r"^github\.", "", inner, flags=re.IGNORECASE)
    inner = re.sub(r"\bpull_request\b", "PR", inner, flags=re.IGNORECASE)
    candidate = re.sub(r"[^A-Za-z0-9]+", "_", inner).strip("_").upper()
    if not candidate or candidate[0].isdigit():
        candidate = "UNTRUSTED_INPUT"
    if candidate not in existing_vars:
        return candidate
    suffix = 2
    while f"{candidate}_{suffix}" in existing_vars:
        suffix += 1
    return f"{candidate}_{suffix}"


def _is_inside_double_quotes(line: str, pos: int) -> bool:
    """Return True if character index `pos` is inside an unescaped double-quoted string."""
    in_dq = False
    escaped = False
    for ch in line[:pos]:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_dq = not in_dq
    return in_dq


def _replace_expr_with_env_ref(raw_line: str, expr: str, env_name: str, shell: str) -> str:
    """Replace `expr` in `raw_line` with a shell-appropriate environment variable reference."""
    shell_lower = shell.lower().strip()
    if shell_lower in ("pwsh", "powershell"):
        bare_ref = f"$env:{env_name}"
        quoted_ref = f'"$env:{env_name}"'
    elif shell_lower == "cmd":
        bare_ref = f"%{env_name}%"
        quoted_ref = f'"%{env_name}%"'
    else:
        bare_ref = f"${env_name}"
        quoted_ref = f'"${env_name}"'

    single_quoted = f"'{expr}'"
    if single_quoted in raw_line and shell_lower not in ("pwsh", "powershell", "cmd"):
        return raw_line.replace(single_quoted, quoted_ref, 1)

    pos = raw_line.find(expr)
    if pos >= 0 and _is_inside_double_quotes(raw_line, pos):
        return raw_line.replace(expr, bare_ref, 1)
    return raw_line.replace(expr, quoted_ref, 1)


def _build_run_injection_diff(
    raw_line: str,
    expr: str,
    step: Dict[str, Any],
) -> Tuple[str, str]:
    """Build a syntactically valid YAML diff moving `expr` into `env:` for a `run:` step."""
    env_name = _derive_env_var_name(expr, step["env_vars"])
    updated_line = _replace_expr_with_env_ref(raw_line, expr, env_name, step["shell"])
    key_indent = step["key_indent"]
    step_indent = step["step_indent"]
    key_pad = " " * key_indent
    env_pad = " " * (key_indent + 2)
    dash_pad = " " * step_indent

    if step["run_has_dash"] and step["run_is_inline"] and not step["has_env"]:
        run_part = updated_line.split("- ", 1)[1] if "- " in updated_line else updated_line.lstrip()
        diff = (
            f"- {raw_line}\n"
            f"+ {dash_pad}- env:\n"
            f"+ {env_pad}{env_name}: {expr}\n"
            f"+ {key_pad}{run_part}"
        )
    elif step["has_env"]:
        diff = (
            f"  {key_pad}env:\n"
            f"+ {env_pad}{env_name}: {expr}\n"
            f"- {raw_line}\n"
            f"+ {updated_line}"
        )
    elif step["run_is_inline"]:
        diff = (
            f"+ {key_pad}env:\n"
            f"+ {env_pad}{env_name}: {expr}\n"
            f"- {raw_line}\n"
            f"+ {updated_line}"
        )
    else:
        diff = (
            f"+ {key_pad}env:\n"
            f"+ {env_pad}{env_name}: {expr}\n"
            f"  {key_pad}run: |\n"
            f"- {raw_line}\n"
            f"+ {updated_line}"
        )
    return env_name, diff


def _new_step(step_indent: int, key_indent: int) -> Dict[str, Any]:
    return {
        "step_indent": step_indent,
        "key_indent": key_indent,
        "shell": "",
        "uses": "",
        "has_env": False,
        "env_vars": set(),
        "run_is_inline": False,
        "run_has_dash": False,
        "candidates": [],
    }


def _finalize_step_candidates(step: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert raw step candidates into context-verified template-injection records."""
    if not step or not step["candidates"]:
        return []
    results: List[Dict[str, Any]] = []
    uses_lower = step["uses"].lower()
    is_github_script = uses_lower.startswith("actions/github-script")

    for ctx, line_no, raw_line, expr in step["candidates"]:
        if ctx == "github_script" and not is_github_script:
            continue
        if ctx == "run":
            env_name, diff = _build_run_injection_diff(raw_line, expr, step)
            results.append({
                "context": "run",
                "line_no": line_no,
                "expr": expr,
                "env_name": env_name,
                "diff": diff,
                "remediation": (
                    f"ステップの `env:` に `{env_name}: {expr}` を定義し、"
                    f"`run:` 内では環境変数として参照してください。"
                ),
            })
        elif ctx == "github_script":
            env_name = _derive_env_var_name(expr, step["env_vars"])
            results.append({
                "context": "github_script",
                "line_no": line_no,
                "expr": expr,
                "env_name": env_name,
                "diff": "",
                "remediation": (
                    f"`actions/github-script` の `with.script` 内で直接展開せず、"
                    f"ステップの `env:` に `{env_name}: {expr}` を定義して "
                    f"`process.env.{env_name}` 経由で参照してください。"
                ),
            })
    return results


def find_template_injections_in_workflow(content: str) -> List[Dict[str, Any]]:
    """
    Parse YAML workflow structure by indentation and return template-injection
    findings only for executable contexts (`steps[*].run` and `actions/github-script` `with.script`).
    Excludes `env:`, non-script `with:`, `if:`, `concurrency.group:`, `name:`, etc.
    """
    lines = content.splitlines()
    # Stack entries: (indent, key_name, is_list_item)
    stack: List[Tuple[int, str, bool]] = []
    block_ctx: Optional[str] = None
    block_owner_indent: int = -1
    current_step: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = []

    def _flush_step() -> None:
        nonlocal current_step
        if current_step is not None:
            findings.extend(_finalize_step_candidates(current_step))
            current_step = None

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if block_ctx is not None:
            if indent > block_owner_indent:
                if not stripped.startswith("#") and current_step is not None:
                    if block_ctx in ("run", "github_script"):
                        m = UNTRUSTED_GHA_EXPR_RE.search(raw_line)
                        if m:
                            current_step["candidates"].append((block_ctx, idx, raw_line, m.group(0)))
                continue
            block_ctx = None
            block_owner_indent = -1

        if stripped.startswith("#"):
            continue

        is_dash = stripped == "-" or stripped.startswith("- ")
        if is_dash:
            while stack and stack[-1][0] > indent:
                stack.pop()
            if stack and stack[-1][2] and stack[-1][0] == indent:
                stack.pop()
            in_steps = any(item[1] == "steps" for item in stack)
            if in_steps and (not stack or stack[-1][1] == "steps"):
                _flush_step()
                current_step = _new_step(indent, indent + 2)
            elif not in_steps:
                _flush_step()
            stack.append((indent, "<item>", True))
            after_dash = stripped[1:].lstrip()
            if not after_dash:
                continue
            key_indent = indent + (len(stripped) - len(after_dash))
            kv = _YAML_KEY_RE.match(after_dash)
            has_dash_on_line = True
        else:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if not any(item[1] == "steps" for item in stack):
                _flush_step()
            key_indent = indent
            kv = _YAML_KEY_RE.match(stripped)
            has_dash_on_line = False

        if not kv:
            continue

        key = kv.group(1)
        rest = (kv.group(2) or "").strip()
        parent_key = stack[-1][1] if stack else ""
        grandparent_key = stack[-2][1] if len(stack) >= 2 else ""

        if current_step is not None and parent_key == "<item>":
            if not has_dash_on_line and key_indent != current_step["key_indent"]:
                current_step["key_indent"] = key_indent
            if key == "uses":
                current_step["uses"] = rest.strip("\"'")
            elif key == "shell":
                current_step["shell"] = rest.strip("\"'")
            elif key == "env":
                current_step["has_env"] = True
        elif current_step is not None and parent_key == "env":
            current_step["env_vars"].add(key)

        stack.append((key_indent, key, False))

        in_step_root = current_step is not None and parent_key == "<item>"
        in_step_with = current_step is not None and parent_key == "with" and grandparent_key == "<item>"

        if in_step_root and key == "run":
            if _BLOCK_SCALAR_RE.match(rest) or rest == "":
                current_step["run_is_inline"] = False
                current_step["run_has_dash"] = has_dash_on_line
                block_ctx = "run"
                block_owner_indent = key_indent
            else:
                current_step["run_is_inline"] = True
                current_step["run_has_dash"] = has_dash_on_line
                m = UNTRUSTED_GHA_EXPR_RE.search(raw_line)
                if m:
                    current_step["candidates"].append(("run", idx, raw_line, m.group(0)))
        elif in_step_with and key == "script":
            if _BLOCK_SCALAR_RE.match(rest) or rest == "":
                block_ctx = "github_script"
                block_owner_indent = key_indent
            else:
                m = UNTRUSTED_GHA_EXPR_RE.search(raw_line)
                if m:
                    current_step["candidates"].append(("github_script", idx, raw_line, m.group(0)))
        elif _BLOCK_SCALAR_RE.match(rest):
            block_ctx = "other"
            block_owner_indent = key_indent

    _flush_step()
    return findings
