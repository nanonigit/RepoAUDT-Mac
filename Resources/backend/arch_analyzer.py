"""Static dependency graph & execution-flow analyzer for Mermaid architecture and sequence diagrams."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

NON_RUNTIME_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".next",
    ".venv",
    "venv",
    "vendor",
    ".codex",
    ".idea",
    ".vscode",
    "docs",
    "doc",
    "tests",
    "test",
    "__tests__",
    "e2e",
    "load-tests",
    "fixtures",
    "mocks",
    "scripts",
    "examples",
    "coverage",
    ".github",
}

EXTERNAL_SDK_CATALOG: Dict[str, Tuple[str, str, str]] = {
    "pg": ("PostgreSQL", "data", "PostgreSQL (pg)"),
    "psycopg2": ("PostgreSQL", "data", "PostgreSQL (psycopg2)"),
    "asyncpg": ("PostgreSQL", "data", "PostgreSQL (asyncpg)"),
    "mysql2": ("MySQL", "data", "MySQL (mysql2)"),
    "pymysql": ("MySQL", "data", "MySQL (pymysql)"),
    "prisma": ("PrismaORM", "data", "Prisma ORM"),
    "@prisma/client": ("PrismaORM", "data", "Prisma ORM"),
    "knex": ("KnexDB", "data", "Knex Query Builder"),
    "typeorm": ("TypeORM", "data", "TypeORM"),
    "drizzle-orm": ("DrizzleORM", "data", "Drizzle ORM"),
    "sqlalchemy": ("SQLAlchemy", "data", "SQLAlchemy"),
    "mongoose": ("MongoDB", "data", "MongoDB (mongoose)"),
    "redis": ("RedisCache", "data", "Redis"),
    "ioredis": ("RedisCache", "data", "Redis (ioredis)"),
    "openai": ("OpenAIAPI", "infra", "OpenAI API"),
    "@anthropic-ai/sdk": ("ClaudeAPI", "infra", "Anthropic Claude API"),
    "anthropic": ("ClaudeAPI", "infra", "Anthropic Claude API"),
    "@auth0/": ("Auth0", "infra", "Auth0 Identity"),
    "@aws-sdk/": ("AWSServices", "infra", "AWS SDK"),
    "boto3": ("AWSServices", "infra", "AWS SDK (boto3)"),
    "ws": ("WebSocket", "ui", "WebSocket Server"),
    "socket.io": ("WebSocket", "ui", "Socket.IO"),
    "slack": ("SlackAPI", "infra", "Slack API"),
    "@slack/": ("SlackAPI", "infra", "Slack SDK"),
    "slack_sdk": ("SlackAPI", "infra", "Slack SDK"),
    "@supabase/": ("Supabase", "data", "Supabase"),
}

_TS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[\s\S]*?\s+from\s+)?|export\s+[\s\S]*?\s+from\s+|require\s*\(\s*)['"]([^'"]+)['"]"""
)
_ROUTE_EXPRESS_RE = re.compile(r"""\b(?:app|router)\.(get|post|put|patch|delete|use)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_ROUTE_NEST_CTRL_RE = re.compile(r"""@Controller\s*\(\s*['"]([^'"]*)['"]\s*\)""")
_ROUTE_NEST_METHOD_RE = re.compile(r"""@(Get|Post|Put|Patch|Delete)\s*\(\s*['"]?([^'")\s]*)['"]?\s*\)""")
_ROUTE_FASTAPI_RE = re.compile(r"""@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""")

_TF_MODULE_BLOCK_RE = re.compile(r"""module\s+"([^"]+)"\s*\{([\s\S]*?)\n\}""")
_TF_SOURCE_RE = re.compile(r"""source\s*=\s*"([^"]+)\"""")
_TF_MOD_REF_RE = re.compile(r"""\bmodule\.([A-Za-z0-9_-]+)\.""")
_TF_RESOURCE_RE = re.compile(r"""resource\s+"(aws_[a-z0-9_]+)"\s+"([^"]+)" """)


def sanitize_mermaid_label(text: str) -> str:
    """Escape characters that break Mermaid node/participant/edge syntax."""
    cleaned = re.sub(r'["\[\]{}()<>|]', " ", str(text or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or "Module"


def _is_runtime_path(rel_path: Path) -> bool:
    return not any(part in NON_RUNTIME_DIRS or part.startswith(".") for part in rel_path.parts)


def _match_external_sdk(imp: str) -> Optional[Tuple[str, str, str]]:
    low = imp.strip().lower()
    if low in EXTERNAL_SDK_CATALOG:
        return EXTERNAL_SDK_CATALOG[low]
    for prefix, info in EXTERNAL_SDK_CATALOG.items():
        if prefix.endswith("/") and low.startswith(prefix):
            return info
        if "/" in low and low.split("/", 1)[0] == prefix:
            return info
    return None


def _load_ts_aliases(repo_dir: Path) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    tsconfig = repo_dir / "tsconfig.json"
    if not tsconfig.exists():
        return aliases
    try:
        raw = re.sub(r"//.*", "", tsconfig.read_text(encoding="utf-8", errors="ignore"))
        data = json.loads(raw)
        paths = ((data.get("compilerOptions") or {}).get("paths")) or {}
        for k, v in paths.items():
            if isinstance(v, list) and v:
                prefix = str(k).rstrip("*")
                target = str(v[0]).rstrip("*").lstrip("./")
                aliases[prefix] = target
    except Exception:
        pass
    if "@/" not in aliases and (repo_dir / "src").is_dir():
        aliases["@/"] = "src/"
    return aliases


def _module_key_for_file(rel_path: Path, has_src: bool) -> str:
    parts = rel_path.parts
    if has_src and len(parts) >= 2 and parts[0] == "src":
        return f"src/{parts[1]}" if len(parts) >= 3 else "src"
    if len(parts) >= 2:
        return parts[0]
    return "root"


def _make_node_id(prefix: str, name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_") or "Node"
    return f"{prefix}_{slug}"


def _layer_for_name(name: str) -> Tuple[str, str]:
    low = name.lower()
    if any(k in low for k in ("route", "controller", "api", "handler", "page", "view", "app", "ui", "ws", "socket")):
        return "ui", "Routing & Presentation Module"
    if any(k in low for k in ("db", "model", "schema", "migration", "store", "data", "repo", "prisma")):
        return "data", "Data Access & Persistence Layer"
    if any(k in low for k in ("infra", "module", "vpc", "ecs", "alb", "rds", "terraform")):
        return "infra", "Infrastructure Module"
    return "service", "Core Business & Service Module"


def _analyze_terraform(repo_dir: Path, repo_name: str, tf_files: List[Path]) -> Dict[str, Any]:
    modules: Dict[str, Dict[str, Any]] = {}
    edges: List[Tuple[str, str, str]] = []
    seen_edges: Set[Tuple[str, str, str]] = set()
    aws_resources: Set[str] = set()

    for rel in tf_files:
        content = (repo_dir / rel).read_text(encoding="utf-8", errors="ignore")
        for m_res in _TF_RESOURCE_RE.finditer(content):
            aws_resources.add(m_res.group(1))
        for m_mod in _TF_MODULE_BLOCK_RE.finditer(content):
            mod_name = m_mod.group(1).strip()
            block = m_mod.group(2)
            src_m = _TF_SOURCE_RE.search(block)
            src_path = src_m.group(1) if src_m else str(rel)
            if mod_name not in modules:
                modules[mod_name] = {
                    "id": _make_node_id("TfMod", mod_name),
                    "name": f"module.{mod_name}",
                    "path": src_path,
                    "layer": "infra",
                    "category": "Terraform Infrastructure Module",
                    "tech": "Terraform / HCL",
                    "desc": f"Terraform モジュール `{mod_name}` ({src_path})。",
                    "steps": [f"`{src_path}` のリソース定義を適用"],
                    "files": [str(rel)],
                }
            for ref_m in _TF_MOD_REF_RE.finditer(block):
                dep_mod = ref_m.group(1).strip()
                if dep_mod != mod_name:
                    src_id = _make_node_id("TfMod", dep_mod)
                    dst_id = _make_node_id("TfMod", mod_name)
                    ek = (src_id, dst_id, "output ref")
                    if ek not in seen_edges:
                        seen_edges.add(ek)
                        edges.append(ek)

    if not modules and aws_resources:
        for rtype in sorted(aws_resources)[:8]:
            nid = _make_node_id("TfRes", rtype)
            modules[rtype] = {
                "id": nid,
                "name": rtype,
                "path": str(tf_files[0]),
                "layer": "infra",
                "category": "AWS Terraform Resource",
                "tech": "Terraform / AWS",
                "desc": f"Terraform AWS リソース `{rtype}`。",
                "steps": [],
                "files": [str(tf_files[0])],
            }

    # Ensure referenced dependency modules exist in modules dict
    for src_id, dst_id, _ in list(edges):
        if not any(m["id"] == src_id for m in modules.values()):
            mod_label = src_id.removeprefix("TfMod_")
            modules[mod_label] = {
                "id": src_id,
                "name": f"module.{mod_label}",
                "path": f"./modules/{mod_label}",
                "layer": "infra",
                "category": "Terraform Infrastructure Module",
                "tech": "Terraform / HCL",
                "desc": f"Terraform 参照モジュール `{mod_label}`。",
                "steps": [],
                "files": [str(tf_files[0])],
            }

    comp_list = list(modules.values())[:10]
    valid_ids = {c["id"] for c in comp_list}
    valid_edges = [(s, d, lbl) for s, d, lbl in edges if s in valid_ids and d in valid_ids]

    sequences: List[Dict[str, str]] = []
    if len(comp_list) >= 2 and valid_edges:
        participants = [f"    participant {c['id']} as {sanitize_mermaid_label(c['name'])}" for c in comp_list[:6]]
        seq_lines = ["sequenceDiagram", "    autonumber", "    actor Ops as Terraform CLI"] + participants
        for s, d, lbl in valid_edges[:10]:
            seq_lines.append(f"    {s}->>{d}: {sanitize_mermaid_label(lbl)} (main.tf)")
        if not valid_edges:
            for c in comp_list[:5]:
                seq_lines.append(f"    Ops->>{c['id']}: apply {sanitize_mermaid_label(c['path'])}")
        seq_str = "\n".join(seq_lines)
        sequences.append({
            "id": f"seq-{re.sub(r'[^a-zA-Z0-9]', '', repo_name).lower()}-tf-deploy",
            "short_title": f"{repo_name} インフラ構築依存フロー",
            "title": f"{repo_name} インフラ構築依存フロー (Terraform)",
            "desc": "main.tf 内の module 参照関係から抽出したプロビジョニング依存順序です。",
            "diagram": seq_str,
            "mermaid": seq_str,
        })

    return {"components": comp_list, "edges": valid_edges, "sequences": sequences, "kind": "terraform"}


def analyze_repo_architecture(repo_dir: Path, repo_name: str) -> Dict[str, Any]:
    """Build real static dependency components, edges, and grounded sequence diagrams."""
    all_files = [
        p.relative_to(repo_dir)
        for p in repo_dir.rglob("*")
        if p.is_file() and _is_runtime_path(p.relative_to(repo_dir))
    ]
    ts_js_files = [p for p in all_files if p.suffix.lower() in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}]
    py_files = [p for p in all_files if p.suffix.lower() == ".py"]
    tf_files = [p for p in all_files if p.suffix.lower() == ".tf"]

    if tf_files and len(tf_files) >= len(ts_js_files) + len(py_files):
        return _analyze_terraform(repo_dir, repo_name, tf_files)

    has_src = (repo_dir / "src").is_dir()
    mod_files: Dict[str, List[Path]] = defaultdict(list)
    for f in ts_js_files + py_files:
        mod_files[_module_key_for_file(f, has_src)].append(f)

    if not mod_files:
        return {"components": [], "edges": [], "sequences": [], "kind": "minimal"}

    aliases = _load_ts_aliases(repo_dir)
    mod_edges: Counter[Tuple[str, str]] = Counter()
    mod_ext_edges: Dict[str, Set[Tuple[str, str, str]]] = defaultdict(set)
    file_imports: Dict[str, List[str]] = defaultdict(list)
    file_exts: Dict[str, Set[Tuple[str, str, str]]] = defaultdict(set)
    in_degree: Counter[str] = Counter()

    def _resolve_ts_target(src_file: Path, spec: str) -> Optional[str]:
        if spec.startswith("."):
            try:
                resolved = (repo_dir / src_file.parent / spec).resolve().relative_to(repo_dir.resolve())
                if _is_runtime_path(resolved):
                    return _module_key_for_file(resolved, has_src)
            except Exception:
                return None
        for prefix, target in aliases.items():
            if spec.startswith(prefix):
                rel_str = target + spec[len(prefix):]
                p = Path(rel_str)
                if _is_runtime_path(p):
                    return _module_key_for_file(p, has_src)
        return None

    for rel in ts_js_files:
        src_mod = _module_key_for_file(rel, has_src)
        content = (repo_dir / rel).read_text(encoding="utf-8", errors="ignore")
        for m in _TS_IMPORT_RE.finditer(content):
            spec = m.group(1).strip()
            ext = _match_external_sdk(spec)
            if ext:
                mod_ext_edges[src_mod].add(ext)
                file_exts[str(rel)].add(ext)
                continue
            dst_mod = _resolve_ts_target(rel, spec)
            if dst_mod and dst_mod != src_mod and dst_mod in mod_files:
                mod_edges[(src_mod, dst_mod)] += 1
                in_degree[dst_mod] += 1
                file_imports[str(rel)].append(dst_mod)

    for rel in py_files:
        src_mod = _module_key_for_file(rel, has_src)
        content = (repo_dir / rel).read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(content)
        except Exception:
            continue
        for node in ast.walk(tree):
            specs: List[str] = []
            if isinstance(node, ast.Import):
                specs = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                specs = [node.module]
            for spec in specs:
                ext = _match_external_sdk(spec.split(".")[0])
                if ext:
                    mod_ext_edges[src_mod].add(ext)
                    file_exts[str(rel)].add(ext)
                    continue
                top_pkg = spec.split(".")[0]
                cand = f"src/{top_pkg}" if has_src and f"src/{top_pkg}" in mod_files else top_pkg
                if cand != src_mod and cand in mod_files:
                    mod_edges[(src_mod, cand)] += 1
                    in_degree[cand] += 1
                    file_imports[str(rel)].append(cand)

    # Rank modules by in-degree * 3 + file count, keep top 6..10
    ranked_mods = sorted(
        mod_files.keys(),
        key=lambda mk: (in_degree[mk] * 3 + len(mod_files[mk]), len(mod_files[mk])),
        reverse=True,
    )[:10]
    kept_set = set(ranked_mods)

    components: List[Dict[str, Any]] = []
    id_by_mod: Dict[str, str] = {}
    for mk in ranked_mods:
        short_name = mk.split("/")[-1]
        nid = _make_node_id("Mod", mk)
        id_by_mod[mk] = nid
        layer, cat = _layer_for_name(short_name)
        flist = [str(f) for f in mod_files[mk][:6]]
        components.append({
            "id": nid,
            "name": short_name,
            "path": f"{mk}/" if mk != "root" else "./",
            "layer": layer,
            "category": cat,
            "tech": "TypeScript / JavaScript" if ts_js_files else "Python",
            "desc": f"`{mk}` モジュール（{len(mod_files[mk])}ファイル, 被参照 {in_degree[mk]}件）。",
            "steps": [],
            "files": flist,
        })

    edges: List[Tuple[str, str, str]] = []
    seen_edges: Set[Tuple[str, str]] = set()
    for (src_m, dst_m), cnt in mod_edges.most_common():
        if src_m in kept_set and dst_m in kept_set:
            s_id, d_id = id_by_mod[src_m], id_by_mod[dst_m]
            if (s_id, d_id) not in seen_edges:
                seen_edges.add((s_id, d_id))
                edges.append((s_id, d_id, f"imports ({cnt})"))

    ext_nodes_added: Set[str] = set()
    for src_m in ranked_mods:
        s_id = id_by_mod[src_m]
        for ext_id, ext_layer, ext_label in sorted(mod_ext_edges.get(src_m, set())):
            if ext_id not in ext_nodes_added:
                ext_nodes_added.add(ext_id)
                components.append({
                    "id": ext_id,
                    "name": ext_label,
                    "path": "External / SDK",
                    "layer": ext_layer,
                    "category": "External Service & Persistence",
                    "tech": ext_label,
                    "desc": f"コード内の import 解析により検出された外部/DB連携 ({ext_label})。",
                    "steps": [],
                    "files": [],
                })
            if (s_id, ext_id) not in seen_edges:
                seen_edges.add((s_id, ext_id))
                edges.append((s_id, ext_id, "SDK"))

    # Grounded execution sequences from real routes/entrypoints
    sequences = _extract_grounded_sequences(repo_dir, repo_name, ts_js_files + py_files, file_imports, file_exts, id_by_mod, has_src)

    return {"components": components, "edges": edges, "sequences": sequences, "kind": "app"}


def _nextjs_page_route_from_rel(rel_str: str) -> Optional[str]:
    """Derive a clean Next.js page route from App Router (page.tsx) or Pages Router (pages/*.tsx)."""
    norm = rel_str.replace("\\", "/")
    fname = Path(norm).name.lower()
    # App Router: app/**/page.{tsx,ts,jsx,js} or src/app/**/page.{tsx,ts,jsx,js}
    if fname in ("page.tsx", "page.ts", "page.jsx", "page.js"):
        for prefix in ("src/app/", "app/"):
            if norm.startswith(prefix):
                sub = norm[len(prefix):].rsplit("/", 1)[0] if "/" in norm[len(prefix):] else ""
                # Strip route groups like (marketing)
                segs = [s for s in sub.split("/") if s and not (s.startswith("(") and s.endswith(")"))]
                return "/" + "/".join(segs)
    # Pages Router: pages/**/*.{tsx,ts,jsx,js} or src/pages/**/*.{tsx,ts,jsx,js}
    if Path(norm).suffix.lower() in (".tsx", ".ts", ".jsx", ".js"):
        stem = Path(norm).stem
        if stem.startswith("_"):
            return None
        for prefix in ("src/pages/", "pages/"):
            if norm.startswith(prefix):
                sub = norm[len(prefix):]
                if sub.startswith("api/"):
                    return None
                no_ext = sub.rsplit(".", 1)[0]
                if no_ext == "index":
                    return "/"
                if no_ext.endswith("/index"):
                    no_ext = no_ext[:-6]
                return "/" + no_ext.lstrip("/")
    return None


def _extract_grounded_sequences(
    repo_dir: Path,
    repo_name: str,
    code_files: List[Path],
    file_imports: Dict[str, List[str]],
    file_exts: Dict[str, Set[Tuple[str, str, str]]],
    id_by_mod: Dict[str, str],
    has_src: bool,
) -> List[Dict[str, str]]:
    routes: List[Tuple[str, str, str]] = []  # (method_route, file_rel, mod_key)
    page_routes: List[Tuple[str, str, str]] = []
    middleware_entry: Optional[Tuple[str, str]] = None  # (rel_str, mod_key)

    for rel in code_files:
        rel_str = str(rel).replace("\\", "/")
        mk = _module_key_for_file(rel, has_src)
        if rel_str in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"):
            middleware_entry = (rel_str, mk)
        if "/api/" in rel_str and rel.name in ("route.ts", "route.js", "route.tsx"):
            route_path = "/" + rel_str.split("/api/", 1)[1].rsplit("/", 1)[0]
            routes.append((f"API /api{route_path}", rel_str, mk))
            continue
        page_path = _nextjs_page_route_from_rel(rel_str)
        if page_path is not None:
            page_routes.append((f"PAGE {page_path}", rel_str, mk))
            continue
        content = (repo_dir / rel).read_text(encoding="utf-8", errors="ignore")
        for m in _ROUTE_EXPRESS_RE.finditer(content):
            routes.append((f"{m.group(1).upper()} {m.group(2)}", rel_str, mk))
        for m in _ROUTE_FASTAPI_RE.finditer(content):
            routes.append((f"{m.group(1).upper()} {m.group(2)}", rel_str, mk))
        ctrl = _ROUTE_NEST_CTRL_RE.search(content)
        if ctrl:
            base = ctrl.group(1).strip("/")
            meth = _ROUTE_NEST_METHOD_RE.search(content)
            sub = meth.group(2).strip("/") if meth else ""
            mname = meth.group(1).upper() if meth else "REQ"
            routes.append((f"{mname} /{base}/{sub}".rstrip("/"), rel_str, mk))

    is_frontend_page_flow = False
    if not routes and page_routes:
        # Prioritize pages that have real imports or external integrations
        page_routes.sort(
            key=lambda r: (
                -(len(file_imports.get(r[1], [])) + len(file_exts.get(r[1], set()))),
                len(r[0]),
                r[0],
            )
        )
        routes = page_routes
        is_frontend_page_flow = True

    if not routes:
        return []

    seq_lines = ["sequenceDiagram", "    autonumber", "    actor Client as Client"]
    participants_added: Set[str] = set()
    interactions: List[str] = []

    mw_id: Optional[str] = None
    if is_frontend_page_flow and middleware_entry is not None:
        mw_rel, mw_mk = middleware_entry
        mw_id = _make_node_id("Entry", "Middleware")
        participants_added.add(mw_id)
        seq_lines.append(f"    participant {mw_id} as Middleware ({sanitize_mermaid_label(Path(mw_rel).name)})")
        interactions.append(f"    Client->>{mw_id}: HTTP Request")
        for dst_mk in list(dict.fromkeys(file_imports.get(mw_rel, [])))[:2]:
            dst_id = id_by_mod.get(dst_mk, _make_node_id("Mod", dst_mk))
            if dst_id not in participants_added:
                participants_added.add(dst_id)
                seq_lines.append(f"    participant {dst_id} as {sanitize_mermaid_label(dst_mk)}")
            interactions.append(f"    {mw_id}->>{dst_id}: route / guard ({sanitize_mermaid_label(dst_mk)})")

    for route_label, rel_str, src_mk in routes[:4]:
        src_id = id_by_mod.get(src_mk, _make_node_id("Entry", Path(rel_str).stem))
        if src_id not in participants_added:
            participants_added.add(src_id)
            seq_lines.append(f"    participant {src_id} as {sanitize_mermaid_label(src_mk)}")
        caller = mw_id if mw_id else "Client"
        interactions.append(f"    {caller}->>{src_id}: {sanitize_mermaid_label(route_label)} ({sanitize_mermaid_label(Path(rel_str).name)})")

        for dst_mk in list(dict.fromkeys(file_imports.get(rel_str, [])))[:3]:
            dst_id = id_by_mod.get(dst_mk, _make_node_id("Mod", dst_mk))
            if dst_id not in participants_added:
                participants_added.add(dst_id)
                seq_lines.append(f"    participant {dst_id} as {sanitize_mermaid_label(dst_mk)}")
            interactions.append(f"    {src_id}->>{dst_id}: call {sanitize_mermaid_label(dst_mk)}")

        for ext_id, _layer, ext_label in sorted(file_exts.get(rel_str, set()))[:2]:
            if ext_id not in participants_added:
                participants_added.add(ext_id)
                seq_lines.append(f"    participant {ext_id} as {sanitize_mermaid_label(ext_label)}")
            interactions.append(f"    {src_id}->>{ext_id}: query / request")

    if not interactions:
        return []

    seq_str = "\n".join(seq_lines + interactions)
    flow_title = (
        f"{repo_name} ページルート・モジュール呼び出しフロー"
        if is_frontend_page_flow
        else f"{repo_name} 実ルート・依存呼び出しフロー"
    )
    return [{
        "id": f"seq-{re.sub(r'[^a-zA-Z0-9]', '', repo_name).lower()}-routes",
        "short_title": flow_title,
        "title": flow_title,
        "desc": "ソースコード内の実ルート定義（API / ページ / Middleware）と import 依存関係から抽出した実行シーケンスです。",
        "diagram": seq_str,
        "mermaid": seq_str,
    }]


def render_mermaid_flowchart(components: List[Dict[str, Any]], edges: Optional[List[Tuple[str, str, str]]] = None) -> str:
    """Render Mermaid flowchart LR using ONLY real dependency edges (never linear chain fallback for multi-module)."""
    if not components:
        return 'flowchart LR\n  Empty["No runtime modules detected"]'
    lines = ["flowchart LR"]
    for comp in components:
        cid = comp["id"]
        name = sanitize_mermaid_label(comp["name"])
        path = sanitize_mermaid_label(comp["path"])
        lines.append(f'  {cid}["{name}<br/>{path}"]')

    if edges:
        for src, dst, label in edges:
            lines.append(f"  {src} -->|{sanitize_mermaid_label(label)}| {dst}")

    for comp in components:
        cid = comp["id"]
        layer = comp.get("layer", "service")
        if layer == "entry":
            lines.append(f"  style {cid} fill:#1e3a8a,stroke:#60a5fa,stroke-width:2px,color:#fff")
        elif layer == "ui":
            lines.append(f"  style {cid} fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#fff")
        elif layer == "service":
            lines.append(f"  style {cid} fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#fff")
        elif layer == "data":
            lines.append(f"  style {cid} fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff")
        else:
            lines.append(f"  style {cid} fill:#1f2937,stroke:#9ca3af,stroke-width:2px,color:#fff")

    return "\n".join(lines)
