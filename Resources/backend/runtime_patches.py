"""Compare repository runtime pins to official upstream security releases."""

import json
import operator
import os
import re
import subprocess
import tempfile
import time
from datetime import date, datetime, timezone
from functools import lru_cache
from html import unescape
from pathlib import Path

from workflow_audit import read_small_file

PHP_FEED = "https://api.github.com/repos/php/php-src/security-advisories?per_page=50"
PHP_ADVISORIES = "https://github.com/php/php-src/security/advisories"
PHP_EOL = "https://www.php.net/eol.php"
GO_FEED = "https://go.dev/doc/devel/release"
POSTGRES_FEED = "https://www.postgresql.org/support/security/"
NGINX_FEED = "https://nginx.org/en/security_advisories.html"
NODE_FEED = "https://nodejs.org/dist/index.json"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
NODE_RELEASES = "https://nodejs.org/en/about/previous-releases"
NODE_SECURITY = "https://nodejs.org/en/blog/vulnerability"

VERSION = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}")
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")
OFFICIAL_IMAGE = (
    r"(?:(?:docker\.io|index\.docker\.io)/)?(?:library/)?"
    r"(php|nginx|node|golang|postgres)"
)
IMAGE = re.compile(rf"{OFFICIAL_IMAGE}(?::([\w][\w.-]*))?(@\S+)?")
SUFFIX = (
    r"(?:alpine(?:[0-9.]+)?|bookworm|bullseye|trixie|slim|fpm|apache|cli|zts|perl|otel)"
)
VARIANT = re.compile(rf"({VERSION})(?:-{SUFFIX})*")
POSTGRES_TAG = re.compile(rf"([0-9]{{1,3}}\.[0-9]{{1,3}})(?:-{SUFFIX})*")
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s#]+)", re.IGNORECASE)
ARG = re.compile(r"\s*(?i:ARG)\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?")
ARG_TAG = re.compile(rf"[0-9]{{1,3}}(?:\.[0-9]{{1,3}}){{0,2}}(?:-{SUFFIX})*")
TAG_REFERENCE = re.compile(rf"{OFFICIAL_IMAGE}:([^@]+)(@\S+)?")
ARG_REFERENCE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
YAML_IMAGE = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?([^\s#'\"]+)['\"]?\s*(?:#.*)?$")
CI_VERSION = re.compile(
    r"^\s*(node|php|go|python|ruby|java|rust)-version:\s*['\"]?([\w.*-]+)['\"]?\s*(?:#.*)?$"
)
PRODUCTS = {
    "php": "PHP",
    "node": "Node.js",
    "nginx": "nginx",
    "go": "Go",
    "postgres": "PostgreSQL",
}
FEEDS = {
    "php": PHP_FEED,
    "nginx": NGINX_FEED,
    "node": NODE_FEED,
    "go": GO_FEED,
    "postgres": POSTGRES_FEED,
}
SOURCES = {
    "php": PHP_ADVISORIES,
    "node": NODE_SECURITY,
    "nginx": NGINX_FEED,
    "go": GO_FEED,
    "postgres": POSTGRES_FEED,
}
VERSION_FILES = {
    ".nvmrc": "node",
    ".node-version": "node",
    ".php-version": "php",
    ".python-version": "python",
    ".ruby-version": "ruby",
    ".java-version": "java",
    ".go-version": "go",
}
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}(?:::[A-Za-z_][A-Za-z0-9_]{0,79})?")
IGNORE_DIRS = {
    ".git",
    "vendor",
    "node_modules",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".next",
}


def version(value):
    if isinstance(value, str) and re.fullmatch(VERSION, value):
        return tuple(map(int, value.split(".")))
    return None


def format_version(value):
    return ".".join(map(str, value))


def without_tags(value):
    return " ".join(unescape(re.sub(r"<[^>]+>", "", value)).split())


def candidate_files(root):
    for directory, folders, files in os.walk(root):
        folders[:] = sorted(
            f
            for f in folders
            if f not in IGNORE_DIRS and not (Path(directory) / f).is_symlink()
        )
        for name in sorted(files):
            yield Path(directory) / name


def read_text(path):
    try:
        content = read_small_file(path)
        return content.decode("utf-8") if content is not None else None
    except (OSError, UnicodeError):
        return None


def docker_arg_image(ref, defaults):
    """Resolve only version-like ARG defaults used in an official image tag."""
    image = TAG_REFERENCE.fullmatch(ref)
    if not image:
        return None, [], None
    sources = {}

    def substitute(match):
        name = match[1] or match[2]
        if name not in defaults:
            return match[0]
        value, line = defaults[name]
        sources[name] = line
        return value

    tag = ARG_REFERENCE.sub(substitute, image[2])
    resolved = ref[: image.start(2)] + tag + (image[3] or "")
    return IMAGE.fullmatch(resolved), list(sources.values()), image[1]


def repository_evidence(root):
    evidence = []
    checked = 0
    skipped = False
    for path in candidate_files(root):
        name = path.name
        lower = name.lower()
        dockerfile = (
            lower == "dockerfile"
            or lower.startswith("dockerfile.")
            or lower.endswith(".dockerfile")
        )
        yaml = lower.endswith((".yml", ".yaml"))
        if not (
            dockerfile
            or yaml
            or name in VERSION_FILES
            or name in ("package.json", "composer.json", "go.mod", ".tool-versions")
        ):
            continue
        if checked >= 200 or len(evidence) >= 300:
            return evidence, True
        checked += 1
        relative = path.relative_to(root).as_posix()
        text = read_text(path)
        if text is None:
            skipped = True
            continue

        def add(
            product,
            declared,
            line,
            exact=None,
            kind="version_file",
            arg_lines=(),
            *,
            filename=relative,
        ):
            if (
                len(declared) > 180
                or len(evidence) >= 300
                or any(ord(c) < 32 for c in declared)
            ):
                return
            evidence.append(
                {
                    "product": product,
                    "declared": declared,
                    "version": exact,
                    "file": filename,
                    "line": line,
                    "kind": kind,
                    **({"arg_lines": arg_lines} if arg_lines else {}),
                }
            )

        if name in VERSION_FILES:
            value = text.strip().removeprefix("v")
            if re.fullmatch(r"[A-Za-z0-9_.*/-]{1,40}", value):
                add(VERSION_FILES[name], value, 1, value if version(value) else None)
        elif name in ("package.json", "composer.json"):
            try:
                meta = json.loads(text)
                product, field = (
                    ("node", "engines")
                    if name == "package.json"
                    else ("php", "require")
                )
                value = (meta.get(field) or {}).get(product)
                if isinstance(value, str) and re.fullmatch(
                    r"[v0-9.xX*~^<>=|, /-]{1,100}", value
                ):
                    add(product, value, None, kind="constraint")
            except (ValueError, AttributeError):
                continue
        elif name == "go.mod":
            for number, line in enumerate(text.splitlines(), 1):
                toolchain = re.fullmatch(
                    r"\s*toolchain\s+go(" + VERSION + r")\s*", line
                )
                minimum = re.fullmatch(r"\s*go\s+([0-9.]+)\s*", line)
                if toolchain:
                    add("go", toolchain[1], number, toolchain[1])
                elif minimum:
                    add("go", minimum[1], number, kind="constraint")
        elif name == ".tool-versions":
            for number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"^\s*([A-Za-z][\w-]*)\s+([\w.*-]+)", line)
                if match:
                    product = {"nodejs": "node", "golang": "go"}.get(match[1], match[1])
                    add(
                        product,
                        match[2],
                        number,
                        match[2] if version(match[2]) else None,
                    )
        else:
            aliases = set()
            defaults = {}
            in_global_scope = dockerfile
            pattern = FROM if dockerfile else YAML_IMAGE
            for number, line in enumerate(text.splitlines(), 1):
                if in_global_scope and (argument := ARG.fullmatch(line)):
                    name, value = argument.groups()
                    if value is not None and ARG_TAG.fullmatch(value):
                        defaults[name] = (value, number)
                    else:
                        defaults.pop(name, None)
                declaration = pattern.match(line)
                if declaration:
                    in_global_scope = False
                    ref = declaration[1]
                    if ref not in aliases and ref != "scratch":
                        image = IMAGE.fullmatch(ref)
                        arg_lines = []
                        unresolved_product = None
                        if not image and dockerfile and "$" in ref:
                            image, arg_lines, unresolved_product = docker_arg_image(
                                ref, defaults
                            )
                        if image:
                            product = "go" if image[1] == "golang" else image[1]
                            tag = image[2] or "latest"
                            variant = (
                                POSTGRES_TAG if product == "postgres" else VARIANT
                            ).fullmatch(tag)
                            add(
                                product,
                                ref,
                                number,
                                variant[1]
                                if variant
                                and not image[3]
                                and (
                                    product != "postgres"
                                    or int(variant[1].split(".")[0]) >= 10
                                )
                                else None,
                                "image_arg_default" if arg_lines else "image",
                                arg_lines,
                            )
                        elif unresolved_product:
                            product = (
                                "go"
                                if unresolved_product == "golang"
                                else unresolved_product
                            )
                            add(product, ref, number, kind="image")
                        elif "$" in ref or re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,179}", ref
                        ):
                            add("image", ref, number, kind="image")
                    alias = (
                        re.search(r"\s+AS\s+([\w.-]+)\s*(?:#.*)?$", line, re.IGNORECASE)
                        if dockerfile
                        else None
                    )
                    if alias:
                        aliases.add(alias[1])
                if (
                    yaml
                    and relative.startswith(".github/workflows/")
                    and (setting := CI_VERSION.match(line))
                ):
                    value = setting[2]
                    add(
                        setting[1],
                        value,
                        number,
                        value if version(value) else None,
                        "ci",
                    )
    return evidence, skipped or len(evidence) >= 300


@lru_cache(maxsize=12)
def fetch(url, hour):
    del hour  # Cache key supplied by the caller.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            [
                "/usr/bin/curl",
                "--disable",
                "--fail",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--max-time",
                "8",
                "--max-filesize",
                "2000000",
                "--url",
                url,
            ],
            stdout=output,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("Official runtime feed unavailable")
        output.seek(0)
        raw = output.read(2_000_001)
        if not raw or len(raw) > 2_000_000:
            raise ValueError("Unexpected runtime feed size")
        return raw.decode("utf-8"), datetime.now(timezone.utc).isoformat()


OPS = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "=": operator.eq,
}


def in_range(installed, expression):
    if not isinstance(expression, str) or not expression:
        return False
    for constraint in expression.split(","):
        match = re.fullmatch(rf"\s*(>=|<=|=|>|<)?\s*({VERSION})\s*", constraint)
        if not match or not OPS[match[1] or "="](installed, version(match[2])):
            return False
    return True


def php_matches(raw, installed):
    feed = json.loads(raw)
    if not isinstance(feed, list) or any(not isinstance(row, dict) for row in feed):
        raise ValueError("Unexpected PHP advisory format")
    matches = []
    for row in feed:
        ghsa = row.get("ghsa_id") or ""
        if not GHSA.fullmatch(ghsa) or row.get("withdrawn_at"):
            continue
        cve = row.get("cve_id") or ""
        identifier = cve if CVE.fullmatch(cve) else ghsa
        for affected in row.get("vulnerabilities") or []:
            package = affected.get("package") or {}
            component = package.get("name") or "PHP"
            patch = version(affected.get("patched_versions"))
            if package.get("ecosystem") != "php" or not in_range(
                installed, affected.get("vulnerable_version_range")
            ):
                continue
            if patch and (patch[:2] != installed[:2] or patch <= installed):
                patch = None
            safe_component = (
                component
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,70}", component)
                else "PHP component"
            )
            matches.append(
                {
                    "id": identifier,
                    "severity": row.get("severity") or "medium",
                    "fixed_versions": [format_version(patch)] if patch else [],
                    "component": safe_component,
                    "symbols": [
                        name
                        for name in affected.get("vulnerable_functions") or []
                        if isinstance(name, str) and SYMBOL.fullmatch(name)
                    ][:15],
                    "url": PHP_ADVISORIES + "/" + ghsa,
                }
            )
            break
    return matches


def nginx_matches(raw, installed):
    matches = []
    recognized = 0
    for block in re.findall(r"<li\b[^>]*>(.*?)</li>", raw, re.IGNORECASE | re.DOTALL):
        plain = unescape(
            re.sub(
                r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", block, flags=re.IGNORECASE)
            )
        )
        identifier = CVE.search(plain)
        affected = re.search(r"^\s*Vulnerable:\s*([^\n]+)", plain, re.MULTILINE)
        fixed = re.search(r"^\s*Not vulnerable:\s*([^\n]+)", plain, re.MULTILINE)
        if not identifier or not affected or not fixed:
            continue
        recognized += 1
        patches = [
            (version(item[1]), bool(item[2]))
            for item in re.finditer(rf"\b({VERSION})(\+)?", fixed[1])
        ]
        # The vendor's explicit fixed points override its broad vulnerable range
        # within the same minor branch, never across a different release branch.
        if any(
            installed == patch
            or (plus and installed[:2] == patch[:2] and installed >= patch)
            for patch, plus in patches
        ):
            continue
        hit = False
        for segment in affected[1].split(","):
            match = re.fullmatch(
                rf"\s*({VERSION})(?:\s*[-–]\s*({VERSION}))?\s*", segment
            )
            if match and version(match[1]) <= installed <= version(
                match[2] or match[1]
            ):
                hit = True
                break
        if not hit:
            continue
        recorded = re.search(r"Severity:\s*(\w+)", plain, re.IGNORECASE)
        severity = {
            "major": "high",
            "medium": "medium",
            "minor": "low",
            "low": "low",
        }.get(recorded[1].lower() if recorded else "", "medium")
        candidates = sorted(
            {patch for patch, _ in patches if patch >= installed},
            key=lambda p: (p[:2] != installed[:2], p),
        )
        matches.append(
            {
                "id": identifier[0],
                "severity": severity,
                "fixed_versions": [format_version(p) for p in candidates],
                "url": NGINX_FEED,
            }
        )
    if not recognized:
        raise ValueError("Unexpected nginx advisory format")
    return matches


def node_matches(raw, schedule, installed, today):
    releases, support = json.loads(raw), json.loads(schedule)
    if not isinstance(releases, list) or not releases or not isinstance(support, dict):
        raise ValueError("Unexpected Node.js release format")
    branch = support.get(f"v{installed[0]}")
    major_releases = []
    for row in releases:
        if not isinstance(row, dict):
            continue
        candidate = version(str(row.get("version", "")).removeprefix("v"))
        release_date = row.get("date")
        if (
            candidate
            and candidate[0] == installed[0]
            and isinstance(release_date, str)
            and release_date <= today
        ):
            major_releases.append((candidate, row.get("security") is True))
    if branch and isinstance(branch.get("end"), str) and branch["end"] <= today:
        return [
            {
                "id": "EOL",
                "severity": "medium",
                "fixed_versions": [],
                "url": NODE_RELEASES,
            }
        ]
    if not major_releases:
        raise ValueError("Node.js release line unavailable")
    security = max(
        (candidate for candidate, secure in major_releases if secure), default=None
    )
    if not security or installed >= security:
        return []
    latest = max(candidate for candidate, _ in major_releases)
    return [
        {
            "id": "security-release",
            "severity": "medium",
            "security_release": format_version(security),
            "latest_release": format_version(latest),
            "fixed_versions": [],
            "url": "https://nodejs.org/dist/v" + format_version(security) + "/",
        }
    ]


def postgres_matches(raw, installed):
    recognized = 0
    matches = []
    for row in re.findall(r"<tr\b[^>]*>(.*?)</tr>", raw, re.IGNORECASE | re.DOTALL):
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, re.IGNORECASE | re.DOTALL)
        cve = CVE.search(cells[0]) if len(cells) >= 4 else None
        if not cve:
            continue
        recognized += 1
        affected = {part.strip() for part in without_tags(cells[1]).split(",")}
        if str(installed[0]) not in affected:
            continue
        for item in without_tags(cells[2]).split(","):
            patched = item.strip()
            if not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}", patched):
                continue
            fixed = tuple(map(int, patched.split(".")))
            if fixed[0] != installed[0] or fixed <= installed:
                continue
            matches.append(
                {
                    "id": cve[0],
                    "severity": "medium",
                    "fixed_versions": [patched],
                    "url": POSTGRES_FEED + cve[0] + "/",
                }
            )
            break
    if not recognized:
        raise ValueError("Unexpected PostgreSQL advisory format")
    return matches


def go_matches(raw, installed, today):
    entries = []
    for row in re.finditer(r'<p id="go(' + VERSION + r')">(.*?)</p>', raw, re.DOTALL):
        text = without_tags(row[2])
        released = re.search(r"released\s+(\d{4}-\d{2}-\d{2})", text)
        candidate = version(row[1])
        if released and released[1] <= today and candidate[:2] == installed[:2]:
            entries.append((candidate, "security fix" in text.lower()))
    if not entries:
        raise ValueError("Go release line unavailable")
    patch = max((candidate for candidate, secure in entries if secure), default=None)
    if not patch or installed >= patch:
        return []
    return [
        {
            "id": "security-release",
            "severity": "medium",
            "fixed_versions": [],
            "security_release": format_version(patch),
            "latest_release": format_version(max(x[0] for x in entries)),
            "url": GO_FEED + "#go" + format_version(patch),
        }
    ]


def php_eol_matches(raw, installed):
    unsupported = set(re.findall(r"<td>\s*([0-9]+\.[0-9]+)\s*</td>", raw))
    return (
        [
            {
                "id": "EOL",
                "severity": "medium",
                "fixed_versions": [],
                "url": PHP_EOL,
            }
        ]
        if format_version(installed[:2]) in unsupported
        else []
    )


def php_symbol_candidates(root, names):
    """Lexical candidate locations, not an execution or reachability check."""
    if not names:
        return {}
    by_name = {}
    for name in sorted(names):
        by_name.setdefault(name.rsplit("::", 1)[-1].lower(), []).append(name)
    results = {}
    for index, path in enumerate(
        p for p in candidate_files(root) if p.suffix == ".php"
    ):
        if index >= 120:
            break
        text = read_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("//", "#", "*")):
                continue
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line):
                for name in by_name.get(match[1].lower(), []):
                    items = results.setdefault(name, [])
                    if len(items) < 4:
                        items.append(
                            {
                                "file": path.relative_to(root).as_posix(),
                                "line": number,
                                "symbol": name,
                            }
                        )
    return results


def issue_for(evidence, advisory, match_component):
    product = PRODUCTS[evidence["product"]]
    identifier = advisory["id"]
    pin = evidence["declared"]
    if evidence["kind"] == "image_arg_default":
        pin = evidence["version"]
    title = title_en = f"[{product}] {identifier}"
    if identifier == "security-release":
        title = f"[{product}] 同系列のセキュリティ更新"
        title_en = f"[{product}] Security release available"
        summary = (
            f"宣言値 {pin}。同系列のセキュリティリリース: {advisory['security_release']}。"
            f"同系列の最新安定版: {advisory['latest_release']}。個別CVEの該当性は公式情報で確認してください。"
        )
        summary_en = (
            f"Declared: {pin}. Security release in the same branch: {advisory['security_release']}. "
            f"Latest stable release in that branch: {advisory['latest_release']}. "
            "Check official details for individual CVE applicability."
        )
    elif identifier == "EOL":
        summary = f"宣言値 {pin} の系列は公式サポートが終了しています。サポート中の系列への移行を検討してください。"
        summary_en = f"The branch declared by {pin} is out of upstream support. Plan a move to a supported branch."
    else:
        patches = " / ".join(advisory["fixed_versions"])
        symbols = ", ".join(advisory.get("symbols") or [])
        symbol_hits = ", ".join(
            f"{hit['file']}:{hit['line']}" for hit in advisory.get("possible_usage", [])
        )
        component = advisory.get("component", "")
        summary = (
            f"宣言値 {pin} が公式アドバイザリの影響範囲に含まれます。公式の修正版: {patches or '公式情報を参照'}。"
            "利用モジュールと実際の稼働版を確認し、サポート中の修正版へ更新してください。"
        )
        summary_en = (
            f"Declared version {pin} is in the official affected range. Documented fixed release: {patches or 'see advisory'}. "
            "Verify the component and deployed version before selecting a supported update."
        )
        if component:
            summary += f" 対象コンポーネント: {component}。"
            summary_en += f" Component: {component}."
        if symbols:
            summary += f" 対象関数: {symbols}。名前が一致する箇所: {symbol_hits or '探索範囲では未確認'}。実行経路は未確認です。"
            summary_en += f" Named symbols: {symbols}. Lexical matches: {symbol_hits or 'none in scan scope'}. Reachability is unverified."
    if evidence["kind"] == "image_arg_default":
        lines = ", ".join(map(str, evidence["arg_lines"]))
        summary += f" DockerfileのARG既定値（行 {lines}）で照合しました。ビルド時の上書きは別途確認してください。"
        summary_en += f" Checked the Dockerfile ARG default (lines {lines}). Verify any build-time overrides."
    relative = evidence["file"]
    return {
        "severity": advisory["severity"],
        "title": title,
        "title_en": title_en,
        "file": f"{relative}:{evidence['line']}" if evidence["line"] else relative,
        "target_node": match_component(relative),
        "desc": summary,
        "desc_en": summary_en,
        "official_source": advisory["url"],
        "scanner": "runtime-patches",
        "runtime_patch": {**evidence, **advisory},
    }


INVENTORY_STATUS = {
    "checked": ("照合済み", "Checked"),
    "unavailable": ("公式情報を取得・解釈できません", "Official feed unavailable"),
    "version_unresolved": ("正確な版を特定できません", "Version unresolved"),
    "vendor_unmapped": ("公式フィード未対応", "Vendor feed not mapped"),
    "limit": ("照合上限に到達", "Lookup limit reached"),
}


def inventory_finding(scan):
    jp = ["リポジトリに記載された構成要素です。実際の稼働版は別途確認してください。"]
    en = [
        "Components declared in the repository. Verify the versions actually deployed."
    ]
    for entry in scan["evidence"]:
        product = entry["product"]
        status = scan["feeds"][product]["status"]
        record = {}
        if product in FEEDS and entry["version"]:
            record = scan["pins"].get(product, {}).get(entry["version"], {})
            status = record.get("status", status)
        elif product in FEEDS:
            status = "version_unresolved"
        location = entry["file"] + (f":{entry['line']}" if entry["line"] else "")
        line = f"{PRODUCTS.get(product, product)} · {entry['declared']} · {location}"
        label_jp, label_en = INVENTORY_STATUS[status]
        if entry["kind"] == "image_arg_default" and entry["version"]:
            label_jp = f"ARG既定値 {entry['version']} · {label_jp}"
            label_en = f"ARG default {entry['version']} · {label_en}"
        if status == "checked":
            advisories = record.get("advisories", [])
            number = len(advisories)
            label_jp += f"（該当・更新候補 {number}件）"
            label_en += f" ({number} advisory or update candidates)"
            if number > 15:
                label_jp += "、監査結果には先頭15件を表示"
                label_en += ", first 15 shown in audit"
        jp.append(f"• {line} · {label_jp}")
        en.append(f"• {line} · {label_en}")
    if scan["limited"]:
        jp.append("読み込めないファイルか範囲上限があるため、結果は部分的です。")
        en.append(
            "Some files were unreadable or a scan limit was reached. Results are partial."
        )
    return {
        "severity": "info",
        "title": "使用コンポーネントとセキュリティ更新の調査",
        "title_en": "Component inventory and security updates",
        "desc": "\n".join(jp),
        "desc_en": "\n".join(en),
        "file": "Docker / runtime declarations",
        "scanner": "runtime-inventory",
    }


def scan_runtime_patches(root, match_component):
    evidence, limited = repository_evidence(root)
    result = {"evidence": evidence, "feeds": {}, "pins": {}, "limited": limited}
    findings = []
    hour = int(time.time() // 3600)
    today = date.today().isoformat()
    errors = (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.TimeoutExpired,
    )
    parsed_hits = []
    for product in dict.fromkeys(item["product"] for item in evidence):
        if product not in FEEDS:
            result["feeds"][product] = {"status": "vendor_unmapped"}
            continue
        declarations = [item for item in evidence if item["product"] == product]
        pinned = {}
        for entry in declarations:
            pin = entry["version"]
            if not pin:
                continue
            previous = pinned.setdefault(pin, entry)
            if (
                previous["kind"] == "image_arg_default"
                and entry["kind"] != "image_arg_default"
            ):
                pinned[pin] = entry
        if not pinned:
            result["feeds"][product] = {
                "status": "version_unresolved",
                "source": SOURCES[product],
            }
            continue
        url = FEEDS[product]
        try:
            raw, checked_at = fetch(url, hour)
            schedule = fetch(NODE_SCHEDULE, hour)[0] if product == "node" else None
        except errors:
            result["feeds"][product] = {
                "status": "unavailable",
                "source": SOURCES[product],
            }
            continue
        php_support = None
        support_status = {}
        if product == "php":
            try:
                php_support = fetch(PHP_EOL, hour)[0]
                support_status["support_status"] = "checked"
            except errors:
                support_status["support_status"] = "unavailable"
        result["feeds"][product] = {
            "status": "checked",
            "checked_at": checked_at,
            "source": url,
            **support_status,
        }
        result["pins"][product] = records = {}
        for index, (pin, item) in enumerate(pinned.items()):
            if index >= 16:
                records[pin] = {"status": "limit"}
                continue
            current = (
                tuple(map(int, pin.split(".")))
                if product == "postgres"
                else version(pin)
            )
            try:
                if product == "php":
                    advisories = php_matches(raw, current)
                    if php_support:
                        advisories = php_eol_matches(php_support, current) + advisories
                elif product == "nginx":
                    advisories = nginx_matches(raw, current)
                elif product == "postgres":
                    advisories = postgres_matches(raw, current)
                elif product == "go":
                    advisories = go_matches(raw, current, today)
                else:
                    advisories = node_matches(raw, schedule, current, today)
            except errors:
                records[pin] = {"status": "unavailable"}
                continue
            records[pin] = {"status": "checked", "advisories": advisories}
            parsed_hits.extend((item, adv) for adv in advisories[:15])
    candidates = php_symbol_candidates(
        root, {name for _, adv in parsed_hits for name in adv.get("symbols", [])}
    )
    for item, advisory in parsed_hits:
        if advisory.get("symbols"):
            advisory["possible_usage"] = [
                hit for name in advisory["symbols"] for hit in candidates.get(name, [])
            ][:8]
        findings.append(issue_for(item, advisory, match_component))
    if evidence:
        findings.insert(0, inventory_finding(result))
    return findings, result
