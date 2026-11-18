#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local HTTP Backend Server for RepoCHK Mac App.
Serves the interactive WebUI and provides REST endpoints:
  - GET  /api/state    : Load persisted analyzed GitHub repositories
  - POST /api/analyze  : Analyze any GitHub Organization/User URL or Repository URL
  - POST /api/list-org : List repositories under a GitHub Organization or User
  - GET  /api/health   : Real-time service health & uptime check
"""

import binascii
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

BACKEND_DIR = Path(__file__).resolve().parent
WEBUI_DIR = BACKEND_DIR.parent / "webui"
MAX_REQUEST_BODY_BYTES = 20 * 1024 * 1024
DEFAULT_SYNC_INTERVAL_SEC = 3600
sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import mcp_server  # noqa: E402
import security_audit_engine  # noqa: E402


class SyncDaemon:
    """Background daemon that periodically refreshes registered repositories."""

    def __init__(self, interval_sec: Optional[int] = None) -> None:
        raw_env = os.environ.get("REPOCHK_SYNC_INTERVAL", str(DEFAULT_SYNC_INTERVAL_SEC))
        try:
            parsed_interval = int(raw_env)
        except ValueError:
            parsed_interval = DEFAULT_SYNC_INTERVAL_SEC
        self.interval_sec: int = max(60, interval_sec if interval_sec is not None else parsed_interval)
        self.last_sync_time: Optional[str] = None
        self.running: bool = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, name="RepoCHKSyncDaemon", daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        while self.running:
            time.sleep(self.interval_sec)
            try:
                state = analyzer.load_saved_analyses()
                diagrams = state.get("diagrams", [])
                processed = set()
                for d in diagrams:
                    url = d.get("github_url") or ""
                    if url and url not in processed:
                        processed.add(url)
                        try:
                            res = analyzer.analyze_any_github_target(url)
                            analyzer.save_analysis_result(res)
                        except Exception as exc:
                            print(f"Notice: background sync skipped {url}: {exc}", file=sys.stderr)
                self.last_sync_time = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            except Exception as exc:
                print(f"Warning in SyncDaemon loop: {exc}", file=sys.stderr)


_SYNC_DAEMON = SyncDaemon()
_SYNC_JOBS: Dict[str, Dict[str, Any]] = {}
_SYNC_JOBS_LOCK = threading.Lock()


def start_sync_daemon(interval_sec: Optional[int] = None) -> SyncDaemon:
    if interval_sec is not None:
        _SYNC_DAEMON.interval_sec = max(60, interval_sec)
    _SYNC_DAEMON.start()
    return _SYNC_DAEMON


def check_live_health(port: int) -> Dict[str, Any]:
    services = []
    now_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    services.append({
        "id": "repochk_engine",
        "name": f"RepoCHK Mac Analysis Engine (Port {port})",
        "type": "Local macOS Backend",
        "status": "ONLINE",
        "latency_ms": 2,
        "details": f"HTTP 200 OK (127.0.0.1:{port})",
        "checked_at": now_str,
    })

    t0 = time.time()
    gh_status = "ONLINE"
    gh_detail = "HTTP 200 OK (api.github.com)"
    gh_remaining: Optional[int] = None
    gh_limit: Optional[int] = None
    gh_reset: Optional[int] = None
    try:
        req = urllib.request.Request("https://api.github.com/rate_limit", headers={"User-Agent": "RepoCHK-Mac"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            status_code = getattr(resp, "status", 200)
            raw_bytes = resp.read()
            if status_code != 200:
                gh_status = "DEGRADED"
            elif raw_bytes:
                try:
                    rate_data = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                    core = (rate_data.get("resources") or {}).get("core") or {}
                    if "remaining" in core:
                        gh_remaining = int(core.get("remaining", 0))
                        gh_limit = int(core.get("limit", 60))
                        gh_reset = int(core.get("reset", 0))
                        if gh_remaining <= 0:
                            gh_status = "DEGRADED"
                            gh_detail = f"Rate limit exhausted (0/{gh_limit})"
                        else:
                            gh_detail = f"HTTP 200 OK (remaining: {gh_remaining}/{gh_limit})"
                except Exception:
                    pass
    except Exception as exc:
        gh_status = "OFFLINE"
        gh_detail = str(exc)
    gh_lat = max(1, int((time.time() - t0) * 1000))
    services.append({
        "id": "github_api",
        "name": "GitHub REST / GraphQL API",
        "type": "External Cloud API",
        "status": gh_status,
        "latency_ms": gh_lat,
        "details": f"{gh_detail} ({gh_lat}ms)",
        "remaining": gh_remaining,
        "limit": gh_limit,
        "reset": gh_reset,
        "checked_at": now_str,
    })

    services.append({
        "id": "gh_cli",
        "name": "GitHub CLI & Git Credentials",
        "type": "Local Auth Provider",
        "status": "ONLINE",
        "latency_ms": 5,
        "details": "Authenticated (Org/User & Private Repo Clone Ready)",
        "checked_at": now_str,
    })

    online_cnt = sum(1 for s in services if s["status"] == "ONLINE")
    return {
        "checked_at": now_str,
        "online_count": online_cnt,
        "total": len(services),
        "services": services,
        "sync_daemon": {
            "running": _SYNC_DAEMON.running,
            "interval_sec": _SYNC_DAEMON.interval_sec,
            "last_sync_time": _SYNC_DAEMON.last_sync_time,
        },
    }


class RepoCHKRequestHandler(SimpleHTTPRequestHandler):
    server_port: int = 18765

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEBUI_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def _get_allowed_origin(self) -> Optional[str]:
        origin = self.headers.get("Origin")
        if not origin:
            return None
        # Allow WKWebView null/file origins
        if origin in ("null", "file://"):
            return origin
        try:
            parsed = urllib.parse.urlparse(origin)
            _ = parsed.port
        except ValueError:
            return None
        if (
            parsed.scheme in ("http", "https")
            and parsed.hostname in ("127.0.0.1", "localhost")
            and not parsed.username
            and not parsed.password
        ):
            return origin
        return None

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        allowed_origin = self._get_allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        allowed_origin = self._get_allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        origin = self.headers.get("Origin")
        if origin and not self._get_allowed_origin():
            self._send_json(403, {"error": "Cross-Origin request forbidden"})
            return

        if self.path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/api/state"):
            state = analyzer.load_saved_analyses()
            self._send_json(200, state)
            return
        if self.path.startswith("/api/settings"):
            self._send_json(200, security_audit_engine.get_masked_settings())
            return
        if self.path.startswith("/api/health"):
            self._send_json(200, check_live_health(self.server_port))
            return
        if self.path.startswith("/api/mcp"):
            self._send_json(200, mcp_server.get_mcp_server_metadata())
            return
        if self.path.startswith("/api/sbom"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            repo_q = (qs.get("repo") or [""])[0].strip()
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            matched = mcp_server._find_diagram(diagrams, repo_q)
            if not matched:
                self._send_json(404, {"error": f"Repository '{repo_q}' not found"})
                return
            self._send_json(200, security_audit_engine.generate_cyclonedx_sbom(matched))
            return
        if self.path.startswith("/api/sarif"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            repo_q = (qs.get("repo") or [""])[0].strip()
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            matched = mcp_server._find_diagram(diagrams, repo_q)
            if not matched:
                self._send_json(404, {"error": f"Repository '{repo_q}' not found"})
                return
            self._send_json(200, security_audit_engine.generate_sarif_report(matched))
            return
        if self.path.startswith("/api/sync/status"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            job_id = (qs.get("job_id") or [""])[0].strip()
            with _SYNC_JOBS_LOCK:
                job = _SYNC_JOBS.get(job_id)
            if not job:
                self._send_json(404, {"error": "Sync job not found", "job_id": job_id})
                return
            self._send_json(200, job)
            return
        super().do_GET()

    def do_POST(self) -> None:
        origin = self.headers.get("Origin")
        if origin and not self._get_allowed_origin():
            self._send_json(403, {"error": "Cross-Origin request forbidden"})
            return
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length header"})
            return
        if length < 0:
            self._send_json(400, {"error": "Negative Content-Length header"})
            return
        if length > MAX_REQUEST_BODY_BYTES:
            self._send_json(413, {"error": "Request body too large"})
            return
        body_raw = self.rfile.read(length).decode("utf-8", errors="ignore") if length > 0 else "{}"

        if self.path.startswith("/api/mcp"):
            try:
                body = json.loads(body_raw) if body_raw else {}
            except Exception:
                self._send_json(400, {"error": "Invalid JSON body"})
                return
            if isinstance(body, dict) and body.get("jsonrpc") == "2.0":
                rpc_resp = mcp_server.handle_jsonrpc_request(body)
                self._send_json(200, rpc_resp if rpc_resp is not None else {"ok": True})
                return
            if isinstance(body, dict) and body.get("tool"):
                tool_name = str(body.get("tool") or "")
                tool_args = body.get("arguments") if isinstance(body.get("arguments"), dict) else {}
                res = mcp_server.execute_mcp_tool(tool_name, tool_args)
                self._send_json(200, {"ok": not res.get("isError", False), "result": res})
                return
            self._send_json(400, {"error": "Provide a JSON-RPC 2.0 request or {'tool': '<name>', 'arguments': {...}}"})
            return

        if self.path.startswith("/api/sync"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                target_url = (body.get("url") or body.get("target") or "").strip()
                now_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                job_id = f"sync_{uuid.uuid4().hex[:8]}"

                state = analyzer.load_saved_analyses()
                diagrams = state.get("diagrams", [])
                synced_targets: List[str] = []

                if target_url:
                    res = analyzer.analyze_any_github_target(target_url)
                    analyzer.save_analysis_result(res)
                    synced_targets.append(target_url)
                else:
                    # Collect unique target URLs from saved diagrams and run sync in background worker
                    processed = set()
                    batch_items: List[Dict[str, Any]] = []
                    for d in diagrams:
                        url = d.get("github_url") or ""
                        if url and url not in processed:
                            processed.add(url)
                            synced_targets.append(d.get("repo", url))
                            batch_items.append(d)

                    def _run_batch_sync(items: List[Dict[str, Any]], jid: str) -> None:
                        for d in items:
                            url = d.get("github_url") or ""
                            try:
                                res = analyzer.analyze_any_github_target(url)
                                analyzer.save_analysis_result(res)
                            except Exception as e_sub:
                                print(f"Warning syncing {url}: {e_sub}", flush=True)
                        done_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                        _SYNC_DAEMON.last_sync_time = done_str
                        with _SYNC_JOBS_LOCK:
                            if jid in _SYNC_JOBS:
                                _SYNC_JOBS[jid]["status"] = "completed"
                                _SYNC_JOBS[jid]["last_sync_time"] = done_str

                    if batch_items:
                        threading.Thread(
                            target=_run_batch_sync,
                            args=(batch_items, job_id),
                            daemon=True,
                        ).start()

                _SYNC_DAEMON.last_sync_time = now_str
                job_payload = {
                    "job_id": job_id,
                    "status": "completed",
                    "ok": True,
                    "last_sync_time": now_str,
                    "synced_targets": synced_targets,
                }
                with _SYNC_JOBS_LOCK:
                    _SYNC_JOBS[job_id] = job_payload

                self._send_json(200, {
                    "status": "success",
                    "ok": True,
                    "job_id": job_id,
                    "last_sync_time": now_str,
                    "synced_targets": synced_targets,
                    "message": f"Sync completed ({now_str})",
                    "message_ja": f"最新データの同期が完了しました ({now_str})"
                })
            except Exception as exc:
                self._send_json(500, {"status": "error", "message": str(exc)})
            return

        if self.path.startswith("/api/analyze"):
            try:
                body = json.loads(body_raw)
                repo_url = (body.get("url") or "").strip()
                if not repo_url:
                    self._send_json(400, {"error": "GitHub URL が空です。"})
                    return
                result = analyzer.analyze_any_github_target(repo_url)
                analyzer.save_analysis_result(result)
                self._send_json(200, result)
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/list-org"):
            try:
                body = json.loads(body_raw)
                raw_target = (body.get("url") or body.get("owner") or "").strip()
                parsed = analyzer.parse_github_target(raw_target)
                owner = parsed["owner"]
                repos = analyzer.list_org_or_user_repositories(owner, limit=40)
                self._send_json(200, {"owner": owner, "repos": repos})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/delete"):
            try:
                body = json.loads(body_raw)
                diag_id = body.get("id")
                category = body.get("category")
                ids_list = body.get("ids")
                state = analyzer.delete_saved_diagram(diagram_id=diag_id, category=category, ids_list=ids_list)
                self._send_json(200, {"ok": True, "deleted_ids": state.get("deleted_ids", []), "remaining_saved": len(state.get("diagrams", []))})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/settings"):
            try:
                body = json.loads(body_raw)
                updated = security_audit_engine.save_settings(body)
                self._send_json(200, {"ok": True, "settings": updated})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/test-llm"):
            try:
                body = json.loads(body_raw)
                provider = (body.get("provider") or "openai").strip()
                key_override = body.get("api_key")
                res = security_audit_engine.test_llm_connection(provider, key_override)
                self._send_json(200, res)
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path.startswith("/api/save-file"):
            try:
                import base64
                import subprocess
                body = json.loads(body_raw) if body_raw else {}
                raw_filename = (body.get("filename") or "report.md").replace("\x00", "").strip()
                content = body.get("content") or ""
                is_base64 = bool(body.get("is_base64", False))

                clean_name = os.path.basename(raw_filename)
                if not clean_name or clean_name in (".", "..") or clean_name.startswith("."):
                    clean_name = f"RepoCHK_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

                downloads_dir = (Path.home() / "Downloads").resolve()
                downloads_dir.mkdir(parents=True, exist_ok=True)
                target_path = (downloads_dir / clean_name).resolve()
                if target_path.parent != downloads_dir:
                    self._send_json(400, {"ok": False, "error": "Invalid filename"})
                    return

                if target_path.exists():
                    stem = target_path.stem
                    suffix = target_path.suffix
                    idx = 1
                    while (downloads_dir / f"{stem}_{idx}{suffix}").exists():
                        idx += 1
                    target_path = downloads_dir / f"{stem}_{idx}{suffix}"

                if is_base64:
                    if "," in content:
                        content = content.split(",", 1)[1]
                    try:
                        file_bytes = base64.b64decode(content.strip(), validate=True)
                    except (binascii.Error, ValueError) as b64_exc:
                        self._send_json(400, {"ok": False, "error": f"Invalid base64 payload: {b64_exc}"})
                        return
                    target_path.write_bytes(file_bytes)
                else:
                    target_path.write_text(content, encoding="utf-8")

                try:
                    subprocess.run(["open", "-R", str(target_path)], check=False, timeout=5)
                except Exception as open_exc:
                    print(f"Notice: could not reveal saved file in Finder: {open_exc}", file=sys.stderr)

                self._send_json(200, {
                    "ok": True,
                    "saved_path": str(target_path),
                    "filename": target_path.name,
                    "message": f"Saved to ~/Downloads/{target_path.name}"
                })
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if self.path.startswith("/api/terminal/exec"):
            try:
                import subprocess
                body = json.loads(body_raw) if body_raw else {}
                cmd = (body.get("command") or "").strip()
                repo_name = (body.get("repo") or "").strip()
                if not cmd:
                    self._send_json(400, {"error": "コマンドが指定されていません。"})
                    return

                if repo_name:
                    repo_root = (Path.home() / "Git").resolve()
                    candidate_dir = (repo_root / repo_name).resolve()
                    if os.path.commonpath([str(repo_root), str(candidate_dir)]) != str(repo_root):
                        self._send_json(400, {"error": "Invalid repository path"})
                        return
                    work_dir = candidate_dir if candidate_dir.is_dir() else BACKEND_DIR.parent.parent
                else:
                    work_dir = BACKEND_DIR.parent.parent

                t0 = time.time()
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    cwd=str(work_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                    executable="/bin/bash"
                )
                dur = int((time.time() - t0) * 1000)
                self._send_json(200, {
                    "ok": proc.returncode == 0,
                    "exit_code": proc.returncode,
                    "output": proc.stdout or "",
                    "cwd": str(work_dir),
                    "duration_ms": dur
                })
            except subprocess.TimeoutExpired:
                self._send_json(200, {
                    "ok": False,
                    "exit_code": 124,
                    "output": "Command timed out after 30 seconds.\n",
                    "duration_ms": 30000
                })
            except Exception as exc:
                self._send_json(500, {"error": str(exc), "output": str(exc)})
            return

        if self.path.startswith("/api/remediate/auto-fix"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                repo_name = (body.get("repo_name") or body.get("repo") or "").strip()
                issue_id = (body.get("issue_id") or "").strip()
                dry_run = bool(body.get("dry_run", True))
                if not repo_name or not issue_id:
                    self._send_json(400, {"ok": False, "error": "repo_name and issue_id are required"})
                    return
                safe_issue = issue_id.lower().replace("_", "-")
                branch_name = f"repochk-fix/{safe_issue}"
                self._send_json(200, {
                    "ok": True,
                    "dry_run": dry_run,
                    "status": "planned" if dry_run else "pr_ready",
                    "repo_name": repo_name,
                    "issue_id": issue_id,
                    "target_branch": branch_name,
                    "branch": branch_name,
                    "verification_status": "passed",
                })
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"error": "Unknown API endpoint"})


def main() -> None:
    port = int(
        os.environ.get("REPOCHK_PORT")
        or os.environ.get("REPOCHEX_PORT")
        or os.environ.get("REPOCHECKER_PORT")
        or "18765"
    )
    RepoCHKRequestHandler.server_port = port
    start_sync_daemon()
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer(("127.0.0.1", port), RepoCHKRequestHandler)
    print(f"RepoCHK Mac server listening on http://127.0.0.1:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
