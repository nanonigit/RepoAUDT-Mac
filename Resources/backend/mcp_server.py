#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Model Context Protocol (MCP) Server for RepoAUDT Mac.
Supports both stdio JSON-RPC 2.0 (for Claude Code, Claude Desktop, Cursor, Antigravity)
and HTTP JSON-RPC 2.0 via /api/mcp in Resources/backend/server.py.
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Keep the signed app bundle immutable when launched by an external MCP client.
sys.dont_write_bytecode = True

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import security_audit_engine  # noqa: E402

MCP_SERVER_NAME = "repoaudt-mac-mcp"
MCP_SERVER_VERSION = "1.2.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


def get_mcp_tools() -> List[Dict[str, Any]]:
    """Return the MCP tool definitions exposed by RepoAUDT Mac."""
    return [
        {
            "name": "list_analyzed_repositories",
            "description": (
                "List all GitHub repositories and ecosystems analyzed in RepoAUDT Mac, "
                "including category, latest commit, CodeRabbit quality score, and CVE/SAST alert counts."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Optional category filter (e.g. 'Ecosystem', 'Frontend', 'Backend').",
                    },
                    "only_action_required": {
                        "type": "boolean",
                        "description": "If true, return only repositories that have urgent security or quality alerts.",
                    },
                },
            },
        },
        {
            "name": "get_repository_architecture",
            "description": (
                "Retrieve the Mermaid architecture diagram, execution sequence diagrams, "
                "dependencies, database tables, API endpoints, and component specs for a repository."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name, slug, or diagram ID (e.g. 'RepoAUDT-Mac', 'nanonigit/RepoAUDT-Mac').",
                    }
                },
                "required": ["repo"],
            },
        },
        {
            "name": "get_security_audit_report",
            "description": (
                "Retrieve the consolidated security & code quality audit report (OSV.dev CVEs, "
                "runtime EOL warnings, OWASP Top 10 SAST/AST findings, and remediation diffs/commands) "
                "for a specific repository or across all analyzed repositories."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Optional repository name or ID. Omit to aggregate across all repositories.",
                    }
                },
            },
        },
        {
            "name": "analyze_github_repository",
            "description": (
                "Analyze a GitHub repository URL, owner/repo slug, organization URL, or local directory path "
                "and persist its architecture diagram, sequence flows, OSV CVEs, and SAST findings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "GitHub URL (https://github.com/owner/repo), slug (owner/repo), or local path.",
                    }
                },
                "required": ["target"],
            },
        },
        {
            "name": "scan_code_snippet_security",
            "description": (
                "Run RepoAUDT Mac's OWASP Top 10 SAST and Python AST security analyzer on a source code snippet "
                "and return detected vulnerabilities with line numbers and remediation diffs."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Source code content to inspect for security and code-quality issues.",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Filename with extension to determine language (e.g. 'app.py', 'index.ts', 'auth.php', 'View.swift').",
                    },
                },
                "required": ["code", "filename"],
            },
        },
        {
            "name": "export_cyclonedx_sbom",
            "description": (
                "Generate an industry-standard CycloneDX 1.5 JSON Software Bill of Materials (SBOM) "
                "with Package URLs (purl), components, and CVE/EPSS vulnerability ratings for a repository."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name or ID (e.g. 'RepoAUDT-Mac').",
                    }
                },
                "required": ["repo"],
            },
        },
        {
            "name": "export_sarif_report",
            "description": (
                "Generate a GitHub Code Scanning compatible SARIF 2.1.0 JSON report containing "
                "all OWASP SAST/AST findings, CodeRabbit action items, and CVE advisories for a repository."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name or ID (e.g. 'RepoAUDT-Mac').",
                    }
                },
                "required": ["repo"],
            },
        },
    ]


def get_mcp_resources() -> List[Dict[str, Any]]:
    """Return the MCP resource definitions exposed by RepoAUDT Mac."""
    return [
        {
            "uri": "repoaudt://repositories/summary",
            "name": "Analyzed Repositories Summary",
            "description": "JSON summary of all repositories managed by RepoAUDT Mac with scores and alert counts.",
            "mimeType": "application/json",
        },
        {
            "uri": "repoaudt://security/action-items",
            "name": "Urgent Security & Code Quality Action Items",
            "description": "Consolidated list of all CVE advisories and SAST/CodeRabbit action items across repositories.",
            "mimeType": "application/json",
        },
    ]


def get_mcp_prompts() -> List[Dict[str, Any]]:
    """Return the MCP prompt templates exposed by RepoAUDT Mac."""
    return [
        {
            "name": "remediate_repository_vulnerabilities",
            "description": "Generate a structured remediation plan for all security and quality findings in a repository.",
            "arguments": [
                {
                    "name": "repo",
                    "description": "Target repository name or ID.",
                    "required": True,
                }
            ],
        }
    ]


def get_client_mcp_config() -> Dict[str, Any]:
    """Return the copy-ready mcpServers configuration JSON for Claude Code / Cursor / Antigravity."""
    installed_script = Path("/Applications/RepoAUDT Mac.app/Contents/Resources/backend/mcp_server.py")
    script_path = str(installed_script if installed_script.exists() else Path(__file__).resolve())
    return {
        "mcpServers": {
            "repoaudt-mac": {
                "command": "python3",
                "args": ["-B", script_path],
            }
        }
    }


def get_mcp_server_metadata() -> Dict[str, Any]:
    """Return server metadata, tool schemas, resource list, and client config for WebUI display."""
    return {
        "name": MCP_SERVER_NAME,
        "version": MCP_SERVER_VERSION,
        "protocol_version": DEFAULT_PROTOCOL_VERSION,
        "status": "ONLINE",
        "tools": get_mcp_tools(),
        "resources": get_mcp_resources(),
        "prompts": get_mcp_prompts(),
        "client_config": get_client_mcp_config(),
    }


def _find_diagram(diagrams: List[Dict[str, Any]], query: str) -> Optional[Dict[str, Any]]:
    q = query.strip().lower()
    if not q:
        return diagrams[0] if diagrams else None
    for d in diagrams:
        if (
            str(d.get("id", "")).lower() == q
            or str(d.get("repo", "")).lower() == q
            or str(d.get("repo_slug", "")).lower() == q
        ):
            return d
    for d in diagrams:
        if (
            q in str(d.get("id", "")).lower()
            or q in str(d.get("repo", "")).lower()
            or q in str(d.get("github_url", "")).lower()
        ):
            return d
    return None


def _summarize_diagram_item(d: Dict[str, Any]) -> Dict[str, Any]:
    deps = d.get("deps") or {}
    advisories = deps.get("security_advisories") or []
    cr = d.get("coderabbit") or {}
    action_items = cr.get("action_items") or []
    return {
        "id": d.get("id"),
        "repo": d.get("repo"),
        "category": d.get("category"),
        "github_url": d.get("github_url"),
        "updated_at": d.get("pushedAt") or d.get("updatedAt"),
        "commit_hash": d.get("commit_hash"),
        "commit_subject": d.get("commit_subject"),
        "coderabbit_score": cr.get("score", 90),
        "coderabbit_status": cr.get("status", "PASSED"),
        "cve_count": len(advisories),
        "action_item_count": len(action_items),
        "has_action_required": bool(advisories or action_items),
    }


def execute_mcp_tool(name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute one of RepoAUDT Mac's MCP tools and return an MCP CallToolResult dict."""
    args = arguments or {}
    state = analyzer.load_saved_analyses()
    diagrams: List[Dict[str, Any]] = state.get("diagrams", [])

    if name == "list_analyzed_repositories":
        category_filter = str(args.get("category") or "").strip().lower()
        only_action = bool(args.get("only_action_required", False))
        summaries = []
        for d in diagrams:
            if category_filter and category_filter not in str(d.get("category", "")).lower():
                continue
            item = _summarize_diagram_item(d)
            if only_action and not item["has_action_required"]:
                continue
            summaries.append(item)
        payload = {
            "total": len(summaries),
            "repositories": summaries,
        }
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    if name == "get_repository_architecture":
        repo_query = str(args.get("repo") or "").strip()
        if not repo_query:
            return {
                "content": [{"type": "text", "text": "Error: 'repo' parameter is required."}],
                "isError": True,
            }
        matched = _find_diagram(diagrams, repo_query)
        if not matched:
            return {
                "content": [{"type": "text", "text": f"Repository '{repo_query}' not found in analyzed list."}],
                "isError": True,
            }
        arch_payload = {
            "id": matched.get("id"),
            "repo": matched.get("repo"),
            "category": matched.get("category"),
            "github_url": matched.get("github_url"),
            "description": matched.get("description"),
            "diagram": matched.get("diagram"),
            "sequences": matched.get("sequences") or [],
            "deps": matched.get("deps") or {},
            "node_specs": matched.get("node_specs") or {},
        }
        return {
            "content": [{"type": "text", "text": json.dumps(arch_payload, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    if name == "get_security_audit_report":
        repo_query = str(args.get("repo") or "").strip()
        targets = [d for d in ([_find_diagram(diagrams, repo_query)] if repo_query else diagrams) if d is not None]
        if repo_query and not targets:
            return {
                "content": [{"type": "text", "text": f"Repository '{repo_query}' not found."}],
                "isError": True,
            }
        reports = []
        for d in targets:
            deps = d.get("deps") or {}
            cr = d.get("coderabbit") or {}
            reports.append({
                "repo": d.get("repo"),
                "github_url": d.get("github_url"),
                "source_revision": d.get("source_revision"),
                "score": cr.get("score", 90),
                "status": cr.get("status", "PASSED"),
                "summary": cr.get("summary", ""),
                "workflow_scan": cr.get("workflow_scan"),
                "source_scan": cr.get("source_scan"),
                "runtime_patch_scan": cr.get("runtime_patch_scan"),
                "authorization_scan": cr.get("authorization_scan"),
                "security_advisories": deps.get("security_advisories") or [],
                "action_items": cr.get("action_items") or [],
                "findings": cr.get("findings") or [],
            })
        payload = {
            "repository_count": len(reports),
            "reports": reports,
        }
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    if name == "analyze_github_repository":
        target = str(args.get("target") or "").strip()
        if not target:
            return {
                "content": [{"type": "text", "text": "Error: 'target' parameter is required."}],
                "isError": True,
            }
        try:
            result = analyzer.analyze_any_github_target(target)
            saved_state = analyzer.save_analysis_result(result)
            new_diagrams = result.get("diagrams") if "diagrams" in result else [result]
            summary = {
                "status": "success",
                "analyzed_target": target,
                "added_or_updated_count": len(new_diagrams),
                "total_saved_repositories": len(saved_state.get("diagrams", [])),
                "repositories": [_summarize_diagram_item(d) for d in new_diagrams if isinstance(d, dict)],
            }
            return {
                "content": [{"type": "text", "text": json.dumps(summary, ensure_ascii=False, indent=2)}],
                "isError": False,
            }
        except Exception as exc:
            return {
                "content": [{"type": "text", "text": f"Analysis failed for '{target}': {exc}"}],
                "isError": True,
            }

    if name == "scan_code_snippet_security":
        code = str(args.get("code") or "")
        filename = str(args.get("filename") or "snippet.py").strip() or "snippet.py"
        safe_name = Path(filename).name or "snippet.py"
        with tempfile.TemporaryDirectory(prefix="repoaudt_mcp_scan_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            target_file = tmp_path / safe_name
            target_file.write_text(code, encoding="utf-8")
            sast_res = security_audit_engine.scan_php_and_nodejs_and_polyglot_vulnerabilities(
                tmp_path,
                [{"name": "Snippet", "path": safe_name, "layer": "service", "files": [safe_name]}],
                force_sast=True,
            )
        findings = sast_res.get("sast_findings", [])
        advisories = sast_res.get("security_advisories", [])
        payload = {
            "filename": safe_name,
            "sast_findings": findings,
            "security_advisories": advisories,
            "total_issues": len(findings) + len(advisories),
        }
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    if name == "export_cyclonedx_sbom":
        repo_query = str(args.get("repo") or "").strip()
        matched = _find_diagram(diagrams, repo_query)
        if not matched:
            return {
                "content": [{"type": "text", "text": f"Repository '{repo_query}' not found."}],
                "isError": True,
            }
        sbom = security_audit_engine.generate_cyclonedx_sbom(matched)
        return {
            "content": [{"type": "text", "text": json.dumps(sbom, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    if name == "export_sarif_report":
        repo_query = str(args.get("repo") or "").strip()
        matched = _find_diagram(diagrams, repo_query)
        if not matched:
            return {
                "content": [{"type": "text", "text": f"Repository '{repo_query}' not found."}],
                "isError": True,
            }
        sarif = security_audit_engine.generate_sarif_report(matched)
        return {
            "content": [{"type": "text", "text": json.dumps(sarif, ensure_ascii=False, indent=2)}],
            "isError": False,
        }

    return {
        "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
        "isError": True,
    }


def read_mcp_resource(uri: str) -> Dict[str, Any]:
    """Read an MCP resource by URI."""
    state = analyzer.load_saved_analyses()
    diagrams: List[Dict[str, Any]] = state.get("diagrams", [])

    if uri == "repoaudt://repositories/summary":
        data = {
            "total": len(diagrams),
            "repositories": [_summarize_diagram_item(d) for d in diagrams],
        }
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data, ensure_ascii=False, indent=2),
                }
            ]
        }

    if uri == "repoaudt://security/action-items":
        items = []
        for d in diagrams:
            repo_name = d.get("repo")
            deps = d.get("deps") or {}
            cr = d.get("coderabbit") or {}
            for adv in deps.get("security_advisories") or []:
                items.append({"repo": repo_name, "type": "cve", "item": adv})
            for act in cr.get("action_items") or []:
                items.append({"repo": repo_name, "type": "action_item", "item": act})
        data = {
            "total_action_items": len(items),
            "items": items,
        }
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data, ensure_ascii=False, indent=2),
                }
            ]
        }

    raise ValueError(f"Resource not found: {uri}")


def get_mcp_prompt(name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate an MCP prompt response."""
    args = arguments or {}
    if name != "remediate_repository_vulnerabilities":
        raise ValueError(f"Unknown prompt: {name}")
    repo_query = str(args.get("repo") or "").strip()
    state = analyzer.load_saved_analyses()
    diagrams: List[Dict[str, Any]] = state.get("diagrams", [])
    matched = _find_diagram(diagrams, repo_query)
    if not matched:
        prompt_text = f"Repository '{repo_query}' was not found. Please run analyze_github_repository first."
    else:
        cr = matched.get("coderabbit") or {}
        deps = matched.get("deps") or {}
        prompt_text = (
            f"Please review and remediate the following security and code quality issues for repository '{matched.get('repo')}':\n\n"
            f"1. Security Advisories (CVEs):\n{json.dumps(deps.get('security_advisories') or [], ensure_ascii=False, indent=2)}\n\n"
            f"2. CodeRabbit / SAST Action Items:\n{json.dumps(cr.get('action_items') or [], ensure_ascii=False, indent=2)}\n"
        )
    return {
        "description": f"Remediation prompt for {repo_query or 'repository'}",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": prompt_text,
                },
            }
        ],
    }


def handle_jsonrpc_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP message and return a response dict (or None for notifications)."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id") if isinstance(request, dict) else None,
            "error": {"code": JSONRPC_INVALID_REQUEST, "message": "Invalid JSON-RPC 2.0 request"},
        }

    method = str(request.get("method") or "")
    req_id = request.get("id")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}

    # Notifications have no 'id' and expect no response
    if "id" not in request or method.startswith("notifications/"):
        return None

    try:
        if method == "initialize":
            client_proto = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": client_proto,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": MCP_SERVER_NAME,
                        "version": MCP_SERVER_VERSION,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": get_mcp_tools()},
            }

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": JSONRPC_INVALID_PARAMS, "message": "Missing tool 'name'"},
                }
            result = execute_mcp_tool(tool_name, tool_args)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": get_mcp_resources()},
            }

        if method == "resources/read":
            uri = str(params.get("uri") or "")
            if not uri:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": JSONRPC_INVALID_PARAMS, "message": "Missing resource 'uri'"},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": read_mcp_resource(uri),
            }

        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"prompts": get_mcp_prompts()},
            }

        if method == "prompts/get":
            prompt_name = str(params.get("name") or "")
            prompt_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": get_mcp_prompt(prompt_name, prompt_args),
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": JSONRPC_METHOD_NOT_FOUND, "message": f"Method not found: {method}"},
        }
    except ValueError as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": JSONRPC_INVALID_PARAMS, "message": str(exc)},
        }
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": JSONRPC_INTERNAL_ERROR, "message": str(exc)},
        }


def run_stdio_server() -> None:
    """Run the MCP JSON-RPC 2.0 server over stdin/stdout (supports both Content-Length and newline framing)."""
    stdin_buf = sys.stdin.buffer
    stdout_buf = sys.stdout.buffer

    while True:
        first_line = stdin_buf.readline()
        if not first_line:
            break

        stripped = first_line.strip()
        if not stripped:
            continue

        use_content_length = False
        raw_payload = b""

        if stripped.lower().startswith(b"content-length:"):
            use_content_length = True
            try:
                content_length = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                continue
            # Consume remaining headers until empty line
            while True:
                header_line = stdin_buf.readline()
                if not header_line or header_line in (b"\r\n", b"\n"):
                    break
            raw_payload = stdin_buf.read(content_length)
        else:
            raw_payload = stripped

        try:
            request_obj = json.loads(raw_payload.decode("utf-8"))
        except Exception:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": JSONRPC_PARSE_ERROR, "message": "Parse error"},
            }
            out_bytes = json.dumps(err_resp, ensure_ascii=False).encode("utf-8")
            if use_content_length:
                stdout_buf.write(f"Content-Length: {len(out_bytes)}\r\n\r\n".encode("ascii") + out_bytes)
            else:
                stdout_buf.write(out_bytes + b"\n")
            stdout_buf.flush()
            continue

        response_obj = handle_jsonrpc_request(request_obj)
        if response_obj is not None:
            out_bytes = json.dumps(response_obj, ensure_ascii=False).encode("utf-8")
            if use_content_length:
                stdout_buf.write(f"Content-Length: {len(out_bytes)}\r\n\r\n".encode("ascii") + out_bytes)
            else:
                stdout_buf.write(out_bytes + b"\n")
            stdout_buf.flush()


if __name__ == "__main__":
    run_stdio_server()
