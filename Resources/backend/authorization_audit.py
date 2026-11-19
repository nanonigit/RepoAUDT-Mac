"""Conservative, read-only authorization evidence for Python HTTP handlers."""

import ast
import difflib
import os
from pathlib import Path
import re
from urllib.parse import quote

from workflow_audit import read_small_file

RULE_ID = "CWE-862-python-local-privileged-route"
CWE = "https://cwe.mitre.org/data/definitions/862.html"
FILE_LIMIT = 160
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "vendor",
    "__pycache__",
}
SAFE_PATH = re.compile(r"[A-Za-z0-9_./-]+\.py")
SAFE_PRELUDE_CALLS = {
    "self.headers.get",
    "self._get_allowed_origin",
    "self._send_json",
    "int",
    "self.rfile.read",
    "self.rfile.read(length).decode",
}
SAFE_ROUTE_CALLS = {
    "self._send_json",
    "json.loads",
    "body.get",
    "str",
    "Path.home",
    "Path.home().resolve",
    "(Path.home() / 'Git').resolve",
    "repo_root.__truediv__",
    "(repo_root / repo_name).resolve",
    "os.path.commonpath",
    "candidate_dir.is_dir",
    "time.time",
    "subprocess.run",
}


def named(expression, name):
    return isinstance(expression, ast.Name) and expression.id == name


def is_origin_boundary(statement):
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.BoolOp):
        return False
    values = statement.test.values
    return (
        isinstance(statement.test.op, ast.And)
        and len(values) == 2
        and named(values[0], "origin")
        and isinstance(values[1], ast.UnaryOp)
        and isinstance(values[1].op, ast.Not)
        and ast.unparse(values[1].operand) == "self._get_allowed_origin()"
        and any(isinstance(node, ast.Return) for node in statement.body)
    )


def path_matches(test, path):
    """True / false for recognized route dispatch, None for an unknown condition."""
    if isinstance(test, ast.Call) and ast.unparse(test.func) == "self.path.startswith":
        args = test.args
        if (
            len(args) == 1
            and isinstance(args[0], ast.Constant)
            and isinstance(args[0].value, str)
        ):
            return path.startswith(args[0].value)
    if (
        isinstance(test, ast.Compare)
        and ast.unparse(test.left) == "self.path"
        and len(test.ops) == 1
    ):
        try:
            operand = ast.literal_eval(test.comparators[0])
        except (ValueError, SyntaxError):
            return None
        if isinstance(test.ops[0], ast.Eq) and isinstance(operand, str):
            return path == operand
        if isinstance(test.ops[0], ast.In) and isinstance(operand, (list, tuple, set)):
            return path in operand
    return None


def route_path(statement):
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.Call):
        return None
    args = statement.test.args
    if (
        len(args) != 1
        or not isinstance(args[0], ast.Constant)
        or not isinstance(args[0].value, str)
    ):
        return None
    path = args[0].value
    return (
        path
        if path.startswith("/api/") and path_matches(statement.test, path) is True
        else None
    )


def prelude_is_known(statements, path):
    last_boundary = None
    origin_seen = False
    body_seen = False
    for statement in statements:
        if (
            isinstance(statement, ast.Assign)
            and ast.unparse(statement) == "origin = self.headers.get('Origin')"
        ):
            origin_seen = True
        if isinstance(statement, ast.Assign) and any(
            named(target, "body_raw") for target in statement.targets
        ):
            body_seen = ast.unparse(statement.value) in (
                "self.rfile.read(length).decode('utf-8')",
                "self.rfile.read(length).decode('utf-8', errors='ignore') if length > 0 else '{}'",
            )
        if isinstance(statement, ast.If):
            if not statement.orelse and path_matches(statement.test, path) is False:
                continue
            if is_origin_boundary(statement):
                last_boundary = statement
            elif not (
                isinstance(statement.test, ast.Compare)
                and named(statement.test.left, "length")
                and all(
                    isinstance(value, ast.Constant)
                    or named(value, "MAX_REQUEST_BODY_BYTES")
                    for value in statement.test.comparators
                )
            ):
                return None
        if not isinstance(statement, (ast.Assign, ast.Try, ast.If)):
            return None
        for call in (
            node for node in ast.walk(statement) if isinstance(node, ast.Call)
        ):
            name = ast.unparse(call.func)
            if name not in SAFE_PRELUDE_CALLS:
                return None
            if name == "self.headers.get" and (
                not call.args
                or not isinstance(call.args[0], ast.Constant)
                or call.args[0].value not in ("Origin", "Content-Length")
            ):
                return None
    return last_boundary if origin_seen and body_seen else None


def source_and_sink(route):
    calls = [node for node in ast.walk(route) if isinstance(node, ast.Call)]
    reads = [node for node in calls if ast.unparse(node) == "body.get('command')"]
    if len(reads) != 1:
        return None
    read = reads[0]
    sinks = [
        node
        for node in calls
        if ast.unparse(node.func) == "subprocess.run"
        and node.args
        and named(node.args[0], "cmd")
        and any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )
    ]
    if len(sinks) != 1 or read.lineno >= sinks[0].lineno:
        return None
    sink = sinks[0]
    execution_block = (
        route.body[0].body
        if route.body and isinstance(route.body[0], ast.Try)
        else route.body
    )
    if not any(
        isinstance(node, ast.Assign) and node.value is sink for node in execution_block
    ):
        return None
    assignments = [
        node
        for node in ast.walk(route)
        if isinstance(node, ast.Assign) and node.lineno < sink.lineno
    ]
    commands = [
        node
        for node in assignments
        if any(named(target, "cmd") for target in node.targets)
    ]
    payloads = [
        node
        for node in assignments
        if any(named(target, "body") for target in node.targets)
    ]
    if len(commands) != 1 or len(payloads) != 1:
        return None
    if ast.unparse(commands[0].value) != "(body.get('command') or '').strip()":
        return None
    if ast.unparse(payloads[0].value) not in (
        "json.loads(body_raw)",
        "json.loads(body_raw) if body_raw else {}",
    ):
        return None
    for node in ast.walk(route):
        if not hasattr(node, "lineno") or not route.lineno < node.lineno <= sink.lineno:
            continue
        if isinstance(node, ast.If) and ast.unparse(node.test) not in (
            "not cmd",
            "repo_name",
            "os.path.commonpath([str(repo_root), str(candidate_dir)]) != str(repo_root)",
        ):
            return None
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func)
            if name not in SAFE_ROUTE_CALLS and name not in (
                "(body.get('command') or '').strip",
                "body.get",
                "(body.get('repo') or '').strip",
            ):
                return None
            if name == "body.get" and ast.unparse(node) not in (
                "body.get('command')",
                "body.get('repo')",
            ):
                return None
        if isinstance(
            node, (ast.Assert, ast.Raise, ast.With, ast.While, ast.For, ast.Match)
        ):
            return None
    return read, sink


def trace(source):
    tree = ast.parse(source)
    for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
        if not any(
            ast.unparse(base).split(".")[-1]
            in ("BaseHTTPRequestHandler", "SimpleHTTPRequestHandler")
            for base in cls.bases
        ):
            continue
        for handler in (
            node
            for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name == "do_POST"
        ):
            for index, route in enumerate(handler.body):
                path = route_path(route)
                if not path:
                    continue
                boundary = prelude_is_known(handler.body[:index], path)
                flow = source_and_sink(route)
                if boundary is not None and flow:
                    read, sink = flow
                    yield (
                        route,
                        [
                            ("entry", handler.lineno),
                            ("boundary", boundary.lineno),
                            ("input", read.lineno),
                            ("privileged_effect", sink.lineno),
                        ],
                    )


def proposed_patch(source, filepath, route):
    lines = source.splitlines(keepends=True)
    indent = " " * (route.col_offset + 4)
    newline = "\r\n" if lines[route.lineno - 1].endswith("\r\n") else "\n"
    block = [
        indent
        + 'self._send_json(410, {"error": "This privileged route is disabled."})'
        + newline,
        indent + "return" + newline,
    ]
    if route.orelse:
        return ""
    fixed = lines[: route.lineno] + block + lines[route.end_lineno :]
    try:
        after = list(trace("".join(fixed)))
        if any(route_path(node) == route_path(route) for node, _ in after):
            return ""
    except (SyntaxError, ValueError, RecursionError):
        return ""
    return "".join(difflib.unified_diff(lines, fixed, f"a/{filepath}", f"b/{filepath}"))


def scan_authorization(root, revision, match_component):
    """Return findings and explicit local scope. No endpoint is invoked."""
    if revision.get("kind") != "github_commit":
        return [], {"status": "requires_github_pin", "files_checked": 0}
    candidates = []
    for directory, folders, files in os.walk(root):
        folders[:] = sorted(
            name
            for name in folders
            if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink()
        )
        for name in files:
            if name.endswith(".py"):
                candidate = Path(directory) / name
                relative = candidate.relative_to(root).as_posix()
                if SAFE_PATH.fullmatch(relative):
                    candidates.append(
                        (
                            name not in ("server.py", "app.py", "main.py"),
                            relative,
                            candidate,
                        )
                    )
    findings = []
    checked = skipped = 0
    for _, relative, path in sorted(candidates)[:FILE_LIMIT]:
        try:
            content = read_small_file(path)
            if content is None:
                skipped += 1
                continue
            source = content.decode("utf-8")
            matches = list(trace(source))
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            skipped += 1
            continue
        checked += 1
        for route, steps in matches:
            diff = proposed_patch(source, relative, route)
            if not diff:
                continue
            entry, boundary, input_line, effect = (number for _, number in steps)
            link = (
                f"https://github.com/{revision['repository']}/blob/{revision['commit_sha']}/"
                f"{quote(relative)}#L{route.lineno}"
            )
            findings.append(
                {
                    "id": RULE_ID,
                    "scanner": "authorization-evidence",
                    "severity": "high",
                    "title": "認可なしで到達するローカルAPIの高権限処理",
                    "title_en": "Local API privileged operation lacks caller authorization",
                    "file": f"{relative}:{route.lineno}",
                    "target_node": match_component(relative),
                    "desc": f"入口 {entry}行 → 認可境界 {boundary}行 → リクエスト由来の値 {input_line}行 → 高権限処理 {effect}行。\n"
                    "Originの検査は送信元の制限です。この経路で呼び出し元の権限を検証する処理は確認できません。"
                    "修正案は該当ルートを無効化します。静的確認の結果です。",
                    "desc_en": f"Entry L{entry} → authorization boundary L{boundary} → request value L{input_line} → privileged effect L{effect}.\n"
                    "The Origin check limits browser origins. This handler path does not verify caller authorization. "
                    "The proposed patch disables the privileged route. Evidence is static.",
                    "official_source": link,
                    "diff": diff,
                    "weakness_reference": CWE,
                    "evidence_chain": [
                        {
                            "kind": kind,
                            "file": relative,
                            "line": line,
                            "commit": revision["commit_sha"],
                        }
                        for kind, line in steps
                    ],
                    "patch_verification": "python_syntax_and_rule_checked",
                }
            )
    return findings, {
        "status": "partial" if len(candidates) > FILE_LIMIT or skipped else "checked",
        "files_checked": checked,
        "files_skipped": skipped,
        "rule": RULE_ID,
        "matches": len(findings),
    }
