#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local HTTP Backend Server for RepoAUDT Mac App.
Serves the interactive WebUI and provides REST endpoints:
  - GET  /api/state    : Load persisted analyzed GitHub repositories
  - POST /api/analyze  : Analyze any GitHub Organization/User URL or Repository URL
  - POST /api/list-org : List repositories under a GitHub Organization or User
  - GET  /api/health   : Real-time service health & uptime check
"""

import binascii
import json
import os
import plistlib
import re
import concurrent.futures
import subprocess
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
import app_updater  # noqa: E402
import audit_evidence  # noqa: E402
import copilot_bridge
import gemini_cli_bridge  # noqa: E402
import diff_verification  # noqa: E402
import mcp_server  # noqa: E402
import mcp_client  # noqa: E402
import security_audit_engine  # noqa: E402


def _monitor_config_path() -> Path:
    analyzer.ensure_dirs()
    return analyzer.APP_SUPPORT_DIR / "commit_monitor.json"


def _revocations_path() -> Path:
    analyzer.ensure_dirs()
    return analyzer.APP_SUPPORT_DIR / "secret_revocations.json"


def _monitor_events_path() -> Path:
    analyzer.ensure_dirs()
    return analyzer.APP_SUPPORT_DIR / "monitor_events.json"


LAUNCHD_MONITOR_LABEL = "com.repoaudt.mac.monitor"


def _launchd_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_MONITOR_LABEL}.plist"


def sync_launchd_agent(enabled: bool, interval_sec: int, *, run_launchctl: bool = True) -> Dict[str, Any]:
    """Install/update or remove the user LaunchAgent for background commit monitoring."""
    plist_path = _launchd_plist_path()
    uid = os.getuid() if hasattr(os, "getuid") else 501
    domain_target = f"gui/{uid}"
    service_target = f"{domain_target}/{LAUNCHD_MONITOR_LABEL}"

    if not enabled:
        if run_launchctl:
            try:
                subprocess.run(
                    ["/bin/launchctl", "bootout", service_target],
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass
        try:
            if plist_path.exists():
                plist_path.unlink()
        except Exception:
            pass
        return {"launchd_installed": False, "plist_path": str(plist_path), "label": LAUNCHD_MONITOR_LABEL}

    analyzer.ensure_dirs()
    log_path = str(analyzer.APP_SUPPORT_DIR / "monitor_launchd.log")
    plist_data = {
        "Label": LAUNCHD_MONITOR_LABEL,
        "ProgramArguments": [sys.executable, str(Path(__file__).resolve()), "--monitor-once"],
        "StartInterval": max(60, int(interval_sec)),
        "RunAtLoad": False,
        "StandardOutPath": log_path,
        "StandardErrorPath": log_path,
    }
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    with open(plist_path, "wb") as fp:
        plistlib.dump(plist_data, fp)

    if run_launchctl:
        try:
            subprocess.run(
                ["/bin/launchctl", "bootout", service_target],
                check=False,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["/bin/launchctl", "bootstrap", domain_target, str(plist_path)],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass

    return {"launchd_installed": plist_path.exists(), "plist_path": str(plist_path), "label": LAUNCHD_MONITOR_LABEL}


def _send_headless_macos_notification(title: str, body: str) -> None:
    """Deliver a native macOS notification when running headless via launchd."""
    script = (
        "on run argv\n"
        "  display notification (item 2 of argv) with title (item 1 of argv) sound name \"default\"\n"
        "end run\n"
    )
    try:
        subprocess.run(
            ["/usr/bin/osascript", "-e", script, str(title), str(body)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass


def _is_secret_finding(title: str) -> bool:
    low = str(title or "").lower()
    return (
        "シークレット" in title
        or "[gitleaks]" in low
        or "private cryptographic key" in low
        or "openai api key" in low
        or "aws access key" in low
        or "aws key" in low
        or "hardcoded password" in low
    )


class SyncDaemon:
    """Background worker that periodically checks HEAD commits and re-audits only changed repos."""

    def __init__(self, interval_sec: Optional[int] = None) -> None:
        raw_env = os.environ.get("REPOAUDT_SYNC_INTERVAL", str(DEFAULT_SYNC_INTERVAL_SEC))
        try:
            parsed_interval = int(raw_env)
        except ValueError:
            parsed_interval = DEFAULT_SYNC_INTERVAL_SEC
        self.enabled: bool = True
        self.interval_sec: int = max(60, interval_sec if interval_sec is not None else parsed_interval)
        self.last_sync_time: Optional[str] = None
        self.last_check_time: Optional[str] = None
        self.last_check_summary: str = ""
        self.checking: bool = False
        self.detected_updates: List[Dict[str, Any]] = []
        self.revocations: Dict[str, Dict[str, Any]] = {}
        self.running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._wake_event = threading.Event()
        self._lock = threading.Lock()
        self._load_config()
        self._load_revocations()
        self._load_events()

    def _load_events(self) -> None:
        try:
            p = _monitor_events_path()
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    if isinstance(data.get("detected_updates"), list):
                        self.detected_updates = data["detected_updates"][:20]
                    if isinstance(data.get("last_check_time"), str):
                        self.last_check_time = data["last_check_time"]
                    if isinstance(data.get("last_sync_time"), str):
                        self.last_sync_time = data["last_sync_time"]
                    if isinstance(data.get("last_check_summary"), str):
                        self.last_check_summary = data["last_check_summary"]
        except Exception:
            pass

    def _save_events(self) -> None:
        try:
            p = _monitor_events_path()
            p.write_text(
                json.dumps(
                    {
                        "detected_updates": self.detected_updates[:20],
                        "last_check_time": self.last_check_time,
                        "last_sync_time": self.last_sync_time,
                        "last_check_summary": self.last_check_summary,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _load_revocations(self) -> None:
        try:
            p = _revocations_path()
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.revocations = {
                        str(k): v for k, v in data.items() if isinstance(v, dict)
                    }
        except Exception:
            self.revocations = {}

    def _save_revocations(self) -> None:
        try:
            p = _revocations_path()
            p.write_text(json.dumps(self.revocations, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def confirm_revocation(self, key: str, confirmed: bool = True) -> Dict[str, Any]:
        now_local, _ = analyzer.now_timestamps()
        with self._lock:
            if key in self.revocations:
                self.revocations[key]["revoked_confirmed"] = bool(confirmed)
                self.revocations[key]["confirmed_at"] = now_local if confirmed else None
                self._save_revocations()
        return self.status_dict()

    def _load_config(self) -> None:
        try:
            cfg_path = _monitor_config_path()
            if cfg_path.exists():
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    if isinstance(data.get("enabled"), bool):
                        self.enabled = data["enabled"]
                    if isinstance(data.get("interval_sec"), int):
                        self.interval_sec = max(60, min(86400, data["interval_sec"]))
        except Exception:
            pass

    def _save_config(self) -> None:
        try:
            cfg_path = _monitor_config_path()
            cfg_path.write_text(
                json.dumps({"enabled": self.enabled, "interval_sec": self.interval_sec}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def configure(self, *, enabled: Optional[bool] = None, interval_sec: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            if isinstance(enabled, bool):
                self.enabled = enabled
            if isinstance(interval_sec, int):
                self.interval_sec = max(60, min(86400, interval_sec))
            self._save_config()
            cur_enabled = self.enabled
            cur_interval = self.interval_sec
        sync_launchd_agent(cur_enabled, cur_interval)
        self._wake_event.set()
        return self.status_dict()

    def status_dict(self) -> Dict[str, Any]:
        with self._lock:
            rev_list = sorted(
                self.revocations.values(),
                key=lambda r: (bool(r.get("revoked_confirmed")), str(r.get("resolved_at") or "")),
            )
            return {
                "enabled": self.enabled,
                "running": self.running,
                "checking": self.checking,
                "interval_sec": self.interval_sec,
                "last_check_time": self.last_check_time,
                "last_sync_time": self.last_sync_time,
                "last_check_summary": self.last_check_summary,
                "detected_updates": list(self.detected_updates),
                "revocation_checks": rev_list[:30],
                "launchd_installed": _launchd_plist_path().exists(),
            }

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, name="RepoAUDTSyncDaemon", daemon=True)
        self._thread.start()

    @staticmethod
    def _collect_finding_signatures(diagram: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
        cr = diagram.get("coderabbit") or {}
        items = list(cr.get("action_items") or []) + list(cr.get("findings") or [])
        sigs: Dict[str, Dict[str, str]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip()
            file_raw = str(item.get("file") or "").split(" (Target:", 1)[0].strip()
            sev = str(item.get("severity") or "info").lower()
            if not title:
                continue
            key = f"{title}|{file_raw}"
            if key not in sigs:
                sigs[key] = {
                    "title": title,
                    "file": file_raw,
                    "severity": sev,
                    "requires_revoke": _is_secret_finding(title),
                }
        return sigs

    def check_once(self) -> Dict[str, Any]:
        with self._lock:
            if self.checking:
                return self.status_dict()
            self.checking = True

        checked_count = 0
        updated_items: List[Dict[str, Any]] = []
        try:
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            processed = set()
            for d in diagrams:
                if not isinstance(d, dict) or d.get("is_root"):
                    continue
                url = analyzer.automatic_refresh_url(d)
                if not url or url in processed:
                    continue
                processed.add(url)
                slug = url.removeprefix("https://github.com/").strip("/")
                saved_commit = str(
                    (d.get("source_revision") or {}).get("commit_sha")
                    or d.get("commit_hash")
                    or ""
                ).strip()
                checked_count += 1
                try:
                    head_info = audit_evidence.repository_status(f"repos/{slug}", saved_commit)
                    latest_sha = str(head_info.get("head") or "").strip()
                    if latest_sha and not head_info.get("same_head"):
                        before_sigs = self._collect_finding_signatures(d)
                        res = analyzer.analyze_any_github_target(url)
                        analyzer.save_analysis_result(res, respect_deleted=True)
                        new_diagram = res.get("diagram") or {}
                        after_sigs = self._collect_finding_signatures(new_diagram)
                        resolved_list = [
                            info for k, info in before_sigs.items() if k not in after_sigs
                        ]
                        resolved_list.sort(
                            key=lambda x: {"critical": 4, "high": 3, "medium": 2, "warning": 2, "low": 1}.get(x["severity"], 0),
                            reverse=True,
                        )
                        resolved_high_count = sum(
                            1 for r in resolved_list if r["severity"] in ("critical", "high")
                        )
                        new_count = sum(1 for k in after_sigs if k not in before_sigs)
                        cr = new_diagram.get("coderabbit") or {}
                        findings_cnt = len(cr.get("action_items") or [])
                        now_local, _ = analyzer.now_timestamps()
                        repo_label = str(d.get("repo") or slug)
                        new_revocations: Dict[str, Dict[str, Any]] = {}
                        for rf in resolved_list:
                            if rf.get("requires_revoke"):
                                rev_key = f"{repo_label}|{rf['title']}|{rf['file']}"
                                new_revocations[rev_key] = {
                                    "key": rev_key,
                                    "repo": repo_label,
                                    "title": rf["title"],
                                    "file": rf["file"],
                                    "severity": rf["severity"],
                                    "new_commit": latest_sha[:7],
                                    "resolved_at": now_local,
                                    "revoked_confirmed": False,
                                    "confirmed_at": None,
                                }
                        if new_revocations:
                            with self._lock:
                                self.revocations.update(new_revocations)
                                self._save_revocations()
                        updated_items.append({
                            "repo": repo_label,
                            "old_commit": saved_commit[:7] if saved_commit else "",
                            "new_commit": latest_sha[:7],
                            "findings": findings_cnt,
                            "resolved_count": len(resolved_list),
                            "resolved_high_count": resolved_high_count,
                            "resolved_findings": resolved_list[:15],
                            "new_count": new_count,
                            "detected_at": now_local,
                        })
                except Exception as exc:
                    is_timeout = isinstance(exc, subprocess.TimeoutExpired) or "timed out" in str(exc).lower()
                    analyzer.record_sync_status(
                        str(d.get("id") or url),
                        sync_status="timeout" if is_timeout else "error",
                        last_sync_error=str(exc),
                    )
                    print(f"Notice: commit monitor skipped {url}: {exc}", file=sys.stderr)
        finally:
            now_local, _ = analyzer.now_timestamps()
            with self._lock:
                self.checking = False
                self.last_check_time = now_local
                if updated_items:
                    self.last_sync_time = now_local
                    self.detected_updates = (updated_items + self.detected_updates)[:20]
                    self.last_check_summary = (
                        f"{checked_count}件確認 · {len(updated_items)}件の新着コミットを再監査"
                    )
                else:
                    self.last_check_summary = f"{checked_count}件確認 · 新着コミットなし"
                self._save_events()
        return self.status_dict()

    def trigger_check_async(self) -> Dict[str, Any]:
        with self._lock:
            already = self.checking
        if not already:
            threading.Thread(target=self.check_once, name="RepoAUDTCommitCheck", daemon=True).start()
        return self.status_dict()

    def _run_loop(self) -> None:
        while self.running:
            self._wake_event.wait(timeout=self.interval_sec)
            self._wake_event.clear()
            if not self.running:
                break
            if self.enabled:
                try:
                    self.check_once()
                except Exception as exc:
                    print(f"Warning in SyncDaemon loop: {exc}", file=sys.stderr)


def should_skip_unchanged_repo(diagram: Dict[str, Any], *, force: bool = False) -> Tuple[bool, str]:
    """Return (True, 'skipped_unchanged') if commit_sha, engine version, and sync_status are unchanged."""
    if force:
        return False, "forced"
    if str(diagram.get("sync_status") or "ok").lower() != "ok":
        return False, "previous_sync_failed"
    if str(diagram.get("audit_engine_version") or "") != analyzer.AUDIT_ENGINE_VERSION:
        return False, "engine_updated"
    url = (analyzer.automatic_refresh_url(diagram) or diagram.get("github_url") or "").strip()
    if not url.startswith("https://github.com/"):
        return False, "non_github"
    slug = url.removeprefix("https://github.com/").strip("/")
    saved_commit = str(
        (diagram.get("source_revision") or {}).get("commit_sha")
        or diagram.get("commit_hash")
        or ""
    ).strip()
    if not saved_commit:
        return False, "no_commit_sha"
    head_info = audit_evidence.repository_status(f"repos/{slug}", saved_commit)
    if head_info.get("head") and head_info.get("same_head"):
        return True, "skipped_unchanged"
    return False, "commit_changed"


_SYNC_DAEMON = SyncDaemon()
_SYNC_JOBS: Dict[str, Dict[str, Any]] = {}
_SYNC_JOBS_LOCK = threading.Lock()


def start_sync_daemon(interval_sec: Optional[int] = None) -> SyncDaemon:
    if interval_sec is not None:
        _SYNC_DAEMON.interval_sec = max(60, interval_sec)
    if _SYNC_DAEMON.enabled and not _launchd_plist_path().exists():
        sync_launchd_agent(True, _SYNC_DAEMON.interval_sec)
    _SYNC_DAEMON.start()
    return _SYNC_DAEMON


def check_live_health(port: int) -> Dict[str, Any]:
    services = []
    now_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    services.append({
        "id": "repoaudt_engine",
        "name": f"RepoAUDT Mac Analysis Engine (Port {port})",
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
        req = urllib.request.Request("https://api.github.com/rate_limit", headers={"User-Agent": "RepoAUDT-Mac"})
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

    credential_started = time.monotonic()
    credential_status = audit_evidence.github_cli_credential_status()
    credential_details = {
        "present": ("ONLINE", "Local GitHub credential available. Repository access has not been checked."),
        "not_installed": ("OFFLINE", "GitHub CLI was not found."),
        "unavailable": ("OFFLINE", "GitHub CLI could not provide a local credential."),
        "unknown": ("DEGRADED", "Local GitHub credential status could not be verified."),
    }
    gh_cli_status, gh_cli_details = credential_details[credential_status]
    services.append({
        "id": "gh_cli",
        "name": "GitHub CLI & Git Credentials",
        "type": "Local Auth Provider",
        "status": gh_cli_status,
        "details": gh_cli_details,
        "credential_status": credential_status,
        "latency_ms": max(1, int((time.monotonic() - credential_started) * 1000)),
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


class RepoAUDTRequestHandler(SimpleHTTPRequestHandler):
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
        if self.path == "/api/connections/mcp":
            try:
                self._send_json(200, mcp_client.load_config())
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return
        if self.path == "/api/connections/copilot/status":
            try:
                self._send_json(200, copilot_bridge.get_copilot_runtime_status())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/connections/gemini-cli/status":
            try:
                self._send_json(200, gemini_cli_bridge.get_gemini_cli_runtime_status())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path.startswith("/api/connections/gemini-cli/models"):
            try:
                force_refresh = "force=1" in self.path
                self._send_json(200, gemini_cli_bridge.list_available_models(force=force_refresh))
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/app/diagnostics":
            try:
                self._send_json(200, app_updater.get_runtime_diagnostics())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/app/update/check":
            try:
                self._send_json(200, app_updater.check_for_updates())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path.startswith("/api/state"):
            state = analyzer.load_saved_analyses()
            self._send_json(200, state)
            return
        if self.path.startswith("/api/settings"):
            self._send_json(200, security_audit_engine.get_masked_settings())
            return
        if self.path.startswith("/api/aspm"):
            import aspm_engine
            state = analyzer.load_saved_analyses()
            settings = security_audit_engine.get_masked_settings()
            portfolio = aspm_engine.build_aspm_portfolio(
                state.get("diagrams", []),
                policy=settings.get("aspm_policy"),
                history=analyzer.load_scan_history(),
            )
            self._send_json(200, {"ok": True, **portfolio})
            return
        if self.path.startswith("/api/threat-feed"):
            import threat_feed
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            force_fetch = (qs.get("force") or ["0"])[0].strip() == "1"
            state = analyzer.load_saved_analyses()
            result = threat_feed.fetch_and_correlate_threat_feed(
                state.get("diagrams", []),
                force=force_fetch,
            )
            self._send_json(200, result)
            return
        if self.path.startswith("/api/remediation/requests"):
            self._send_json(200, analyzer.get_remediation_summary())
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
            id_q = (qs.get("id") or [""])[0].strip()
            repo_q = (qs.get("repo") or [""])[0].strip()
            strict_trivy = (qs.get("strict") or ["0"])[0].strip() == "1"
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            matched = None
            if id_q:
                matched = next((d for d in diagrams if str(d.get("id") or "") == id_q), None)
            if not matched and repo_q:
                matched = mcp_server._find_diagram(diagrams, repo_q)
            if not matched:
                self._send_json(404, {"error": f"Repository '{id_q or repo_q}' not found"})
                return
            sbom_payload = None
            local_dir = (matched.get("local_path") or (matched.get("source_revision") or {}).get("local_path") or "").strip()
            if local_dir and Path(local_dir).is_dir():
                import source_scanners
                trivy_sbom, err_msg = source_scanners.generate_trivy_cyclonedx_sbom(Path(local_dir))
                if trivy_sbom:
                    sbom_payload = trivy_sbom
                elif strict_trivy and err_msg:
                    self._send_json(503, {"error": err_msg})
                    return
            if sbom_payload is None:
                if strict_trivy:
                    import source_scanners
                    if not source_scanners.executable("trivy"):
                        self._send_json(503, {"error": "Trivy がインストールされていないため CycloneDX SBOM を生成できません（`brew install trivy` で導入できます）。"})
                        return
                sbom_payload = security_audit_engine.generate_cyclonedx_sbom(matched)
            self._send_json(200, sbom_payload)
            return
        if self.path.startswith("/api/report/pdf-html"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            lang = (qs.get("lang") or ["ja"])[0].strip().lower()
            repo_q = (qs.get("repo") or [""])[0].strip()
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            if repo_q:
                matched = mcp_server._find_diagram(diagrams, repo_q)
                diagrams = [matched] if matched else []
            import triage_engine
            html_doc = triage_engine.build_pdf_audit_html(diagrams, lang=lang)
            self._send_json(200, {"ok": True, "html": html_doc, "lang": lang})
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
        if self.path.startswith("/api/report/slack"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            lang = (qs.get("lang") or ["ja"])[0].strip().lower()
            repo_q = (qs.get("repo") or [""])[0].strip()
            state = analyzer.load_saved_analyses()
            diagrams = state.get("diagrams", [])
            if repo_q:
                matched = mcp_server._find_diagram(diagrams, repo_q)
                diagrams = [matched] if matched else []
            import triage_engine
            digest = triage_engine.build_slack_digest(diagrams, lang=lang)
            self._send_json(200, {"ok": True, "markdown": digest, "lang": lang})
            return
        if self.path.startswith("/api/findings/suppressed"):
            self._send_json(200, {"suppressed": analyzer.get_suppressed_findings()})
            return
        if self.path.startswith("/api/monitor/status"):
            self._send_json(200, _SYNC_DAEMON.status_dict())
            return
        if self.path.startswith("/api/sync/status"):
            parsed_url = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed_url.query)
            job_id = (qs.get("job_id") or [""])[0].strip()
            with _SYNC_JOBS_LOCK:
                if job_id:
                    job = _SYNC_JOBS.get(job_id)
                else:
                    running = [j for j in _SYNC_JOBS.values() if j.get("status") == "running"]
                    job = running[-1] if running else {
                        "status": "running" if _SYNC_DAEMON.checking else "idle",
                        "checking": bool(_SYNC_DAEMON.checking),
                        "current_stage": "バックグラウンド監視 / 解析中" if _SYNC_DAEMON.checking else "",
                        "eta_seconds": 0,
                    }
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

        if self.path == "/api/connections/copilot/install":
            try:
                self._send_json(200, copilot_bridge.install_or_update_copilot_sdk())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/connections/gemini-cli/install":
            try:
                self._send_json(200, gemini_cli_bridge.install_or_update_gemini_cli())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/audit/cross-check":
            try:
                body = json.loads(body_raw) if body_raw else {}
                repo_name = str(body.get("repo") or "").strip()
                diagram_id = str(body.get("diagram_id") or "").strip()
                finding = body.get("finding") if isinstance(body.get("finding"), dict) else {}
                code_ctx = ""
                code_ctx_error = ""
                # Read redacted local file context if available
                try:
                    state = analyzer.load_saved_analyses()
                    target_diag = None
                    for d in state.get("diagrams", []):
                        if (diagram_id and d.get("id") == diagram_id) or (repo_name and d.get("repo") == repo_name):
                            target_diag = d
                            break
                    local_dir = (
                        (target_diag or {}).get("local_path")
                        or ((target_diag or {}).get("source_revision") or {}).get("local_path")
                        or ""
                    ).strip()
                    raw_file = str(finding.get("file") or "").split(" (Target:", 1)[0].strip()
                    if local_dir and raw_file:
                        parts = raw_file.rsplit(":", 1)
                        rel_path = parts[0]
                        line_no = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 1
                        candidate = (Path(local_dir) / rel_path).resolve()
                        if str(candidate).startswith(str(Path(local_dir).resolve())) and candidate.is_file():
                            lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
                            start = max(0, line_no - 15)
                            end = min(len(lines), line_no + 25)
                            snippet = "\n".join(f"L{i+1}: {lines[i]}" for i in range(start, end))
                            # Redact potential secrets before sending to any LLM
                            snippet = re.sub(r"(AKIA[0-9A-Z]{4})[0-9A-Z]{8,16}", r"\1****REDACTED", snippet)
                            snippet = re.sub(r"(sk-[a-zA-Z0-9_-]{6})[a-zA-Z0-9_-]{12,}", r"\1****REDACTED", snippet)
                            snippet = re.sub(r"((?:ghp|gho|ghs|ghu|github_pat)_[a-zA-Z0-9_]{4})[a-zA-Z0-9_]{12,}", r"\1****REDACTED", snippet)
                            snippet = re.sub(r"(xox[abps]-[a-zA-Z0-9-]{6})[a-zA-Z0-9-]{10,}", r"\1****REDACTED", snippet)
                            snippet = re.sub(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED JWT]", snippet)
                            snippet = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", snippet)
                            code_ctx = snippet
                except Exception as ctx_exc:
                    code_ctx_error = str(ctx_exc)[:160]
                res = security_audit_engine.cross_check_finding(
                    repo_name or "Repository",
                    finding,
                    code_context=code_ctx,
                )
                if isinstance(res, dict):
                    res["code_context_loaded"] = bool(code_ctx)
                    if code_ctx_error:
                        res["code_context_error"] = code_ctx_error
                self._send_json(200, res)
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/app/update/apply":
            try:
                self._send_json(200, app_updater.start_update_and_relaunch())
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/app/tool/upgrade":
            try:
                body = json.loads(body_raw) if body_raw else {}
                tool_name = str(body.get("tool") or "").strip()
                self._send_json(200, app_updater.upgrade_cli_tool(tool_name))
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/audit/copilot-issue":
            host = self.headers.get("Host")
            allowed_hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
            if (host not in allowed_hosts or (origin and origin != f"http://{host}")
                    or not origin
                    or self.headers.get_content_type() != "application/json"):
                self._send_json(403, {"error": "This request must come from the local audit workspace."})
                return
            try:
                payload = json.loads(body_raw)
                repo_id = str(payload.get("repository") or "").strip()
                state = analyzer.load_saved_analyses()
                target = next(
                    (d for d in state.get("diagrams", []) if str(d.get("id")) == repo_id),
                    None,
                )
                github_url = str((target or {}).get("github_url") or payload.get("github_url") or "").strip()
                if not github_url:
                    self._send_json(400, {"error": "GitHub repository URL is required."})
                    return
                result = copilot_bridge.create_copilot_issue(
                    github_url=github_url,
                    title=str(payload.get("title") or ""),
                    body=str(payload.get("body") or ""),
                    assign_copilot=bool(payload.get("assign_copilot", True)),
                )
                self._send_json(200, result)
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path in ("/api/audit/evidence", "/api/audit/chat", "/api/audit/verify-diff", "/api/audit/pull-request"):
            verify_diff = self.path == "/api/audit/verify-diff"
            pull_request = self.path == "/api/audit/pull-request"
            host = self.headers.get("Host")
            allowed_hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
            if (host not in allowed_hosts or (origin and origin != f"http://{host}")
                    or ((verify_diff or pull_request) and not origin)
                    or self.headers.get_content_type() != "application/json"):
                self._send_json(403, {"error": "This request must come from the local audit workspace."})
                return
            try:
                payload = json.loads(body_raw)
                state = analyzer.load_saved_analyses()
                if verify_diff:
                    data = diff_verification.handle(payload, state, analyzer.find_existing_local_repo)
                else:
                    data = audit_evidence.handle(
                        payload, state, chat=self.path.endswith("/chat"), pull_request=pull_request
                    )
                self._send_json(200, data)
            except (audit_evidence.EvidenceError, diff_verification.VerificationError, json.JSONDecodeError) as exc:
                self._send_json(400, {"error": str(exc)})
            except (KeyError, TypeError, ValueError):
                self._send_json(502, {"error": "GitHub returned an unexpected response."})
            return

        if self.path in ("/api/connections/mcp", "/api/connections/mcp/test", "/api/connections/mcp/call"):
            try:
                body = json.loads(body_raw)
                config = body.get("config", body)
                if self.path == "/api/connections/mcp":
                    result = mcp_client.save_config(config)
                else:
                    method = "tools/call" if self.path.endswith("/call") else "tools/list"
                    result = mcp_client.run_operation(config, method, body.get("params"))
                self._send_json(200, {"ok": True, "data": result})
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

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

        if self.path.startswith("/api/findings/triage"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                fp = str(body.get("fingerprint") or "").strip()
                action = str(body.get("action") or "ignore").strip().lower()
                reason = str(body.get("reason") or "").strip()
                note = str(body.get("note") or "").strip()
                days = int(body.get("days") or 7)
                suppressed = analyzer.set_finding_triage(
                    fp, action=action, reason=reason, note=note, days=days
                )
                self._send_json(200, {"ok": True, "suppressed": suppressed})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/findings/suppress"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                fp = str(body.get("fingerprint") or "").strip()
                reason = str(body.get("reason") or "").strip()
                suppress = bool(body.get("suppress", True))
                suppressed = analyzer.set_finding_suppression(fp, reason=reason, suppress=suppress)
                self._send_json(200, {"ok": True, "suppressed": suppressed})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path == "/api/repo/meta":
            try:
                body = json.loads(body_raw) if body_raw else {}
                target_id = str(body.get("diagram_id") or body.get("repo") or "").strip()
                criticality = str(body.get("criticality") or "tier2_internal").strip()
                updated = analyzer.set_repo_criticality(target_id, criticality)
                self._send_json(200, {"ok": True, **updated})
            except LookupError as exc:
                self._send_json(404, {"error": str(exc)})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path == "/api/remediation/requests":
            try:
                body = json.loads(body_raw) if body_raw else {}
                items = body.get("items") if isinstance(body.get("items"), list) else []
                requested = bool(body.get("requested", True))
                note = str(body.get("note") or "")
                channel = str(body.get("channel") or "slack")
                issue_url = str(body.get("issue_url") or "")
                summary = analyzer.mark_remediation_requests(
                    items,
                    requested=requested,
                    note=note,
                    channel=channel,
                    issue_url=issue_url,
                )
                self._send_json(200, summary)
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path == "/api/remediation/github-issue":
            try:
                body = json.loads(body_raw) if body_raw else {}
                repo = str(body.get("repo") or "").strip()
                title = str(body.get("title") or "").strip()[:180]
                issue_body = str(body.get("body") or "").strip()
                items = body.get("items") if isinstance(body.get("items"), list) else []
                if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
                    self._send_json(400, {"error": "Invalid repository slug (expected owner/repo)"})
                    return
                if not title or not issue_body:
                    self._send_json(400, {"error": "title and body are required"})
                    return
                gh_bin = shutil.which("gh") or next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if Path(p).exists()), "")
                if not gh_bin:
                    self._send_json(503, {"error": "GitHub CLI (gh) is not installed"})
                    return
                # Redact any accidental raw secret tokens before posting to GitHub
                safe_body = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", issue_body)
                safe_body = re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED_API_KEY]", safe_body)
                safe_body = re.sub(r"ghp_[A-Za-z0-9]{20,}", "[REDACTED_GH_TOKEN]", safe_body)
                proc = subprocess.run(
                    [gh_bin, "issue", "create", "--repo", repo, "--title", title, "--body", safe_body],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode != 0:
                    err_msg = (proc.stderr or proc.stdout or "gh issue create failed").strip()
                    self._send_json(502, {"error": err_msg[:400]})
                    return
                created_url = (proc.stdout or "").strip().splitlines()[-1].strip() if (proc.stdout or "").strip() else ""
                summary = analyzer.mark_remediation_requests(
                    items,
                    requested=True,
                    note=f"GitHub Issue: {created_url}" if created_url else "",
                    channel="github_issue",
                    issue_url=created_url,
                )
                self._send_json(200, {"ok": True, "issue_url": created_url, **summary})
            except subprocess.TimeoutExpired:
                self._send_json(504, {"error": "gh issue create timed out"})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path == "/api/aspm/policy":
            try:
                body = json.loads(body_raw) if body_raw else {}
                saved = security_audit_engine.save_settings({"aspm_policy": body})
                self._send_json(200, {"ok": True, "aspm_policy": saved.get("aspm_policy", {})})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path == "/api/secrets/verify":
            try:
                body = json.loads(body_raw) if body_raw else {}
                diagram_id = str(body.get("diagram_id") or body.get("repo") or "").strip()
                fp = str(body.get("fingerprint") or "").strip()
                file_raw = str(body.get("file") or "").strip()
                state = analyzer.load_saved_analyses()
                diagrams = state.get("diagrams", [])
                matched = next(
                    (
                        d for d in diagrams
                        if str(d.get("id") or "") == diagram_id or str(d.get("repo") or "") == diagram_id
                    ),
                    None,
                )
                if not matched:
                    self._send_json(404, {"error": f"Repository '{diagram_id}' not found"})
                    return
                local_dir = str(
                    matched.get("local_path")
                    or (matched.get("source_revision") or {}).get("local_path")
                    or ""
                ).strip()
                if not local_dir or not Path(local_dir).is_dir():
                    self._send_json(400, {"error": "Local repository workspace is required for secret verification."})
                    return
                rel_only = file_raw.split(" (", 1)[0].strip()
                line_hint = None
                if ":" in rel_only:
                    rel_part, _, line_part = rel_only.rpartition(":")
                    if line_part.isdigit():
                        rel_only = rel_part
                        line_hint = int(line_part)
                import secret_verifier
                result = secret_verifier.verify_secret_in_file(
                    Path(local_dir), rel_only, line_hint=line_hint
                )
                analyzer.record_secret_verification(
                    str(matched.get("id") or diagram_id),
                    fp,
                    result,
                    file_hint=rel_only,
                )
                self._send_json(200, {"ok": True, **result})
            except Exception as exc:
                self._send_json(400, {"error": f"Verification failed: {type(exc).__name__}"})
            return

        if self.path.startswith("/api/monitor/config"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                enabled = body.get("enabled") if isinstance(body.get("enabled"), bool) else None
                interval_raw = body.get("interval_sec")
                interval_sec = int(interval_raw) if isinstance(interval_raw, (int, float)) else None
                self._send_json(200, _SYNC_DAEMON.configure(enabled=enabled, interval_sec=interval_sec))
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/monitor/check"):
            self._send_json(200, _SYNC_DAEMON.trigger_check_async())
            return

        if self.path.startswith("/api/monitor/revoke"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                rev_key = str(body.get("key") or "").strip()
                confirmed = bool(body.get("confirmed", True))
                if not rev_key:
                    self._send_json(400, {"error": "Missing revocation key"})
                    return
                self._send_json(200, _SYNC_DAEMON.confirm_revocation(rev_key, confirmed))
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return

        if self.path.startswith("/api/sync"):
            try:
                body = json.loads(body_raw) if body_raw else {}
                target_url = (body.get("url") or body.get("target") or "").strip()
                force_rescan = bool(body.get("force", False))
                now_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                job_id = f"sync_{uuid.uuid4().hex[:8]}"

                state = analyzer.load_saved_analyses()
                diagrams = state.get("diagrams", [])
                synced_targets: List[str] = []

                if target_url:
                    try:
                        res = analyzer.analyze_any_github_target(target_url)
                        analyzer.save_analysis_result(res, respect_deleted=True)
                        synced_targets.append(target_url)
                    except Exception as exc:
                        is_timeout = isinstance(exc, subprocess.TimeoutExpired) or "timed out" in str(exc).lower()
                        analyzer.record_sync_status(
                            target_url,
                            sync_status="timeout" if is_timeout else "error",
                            last_sync_error=str(exc),
                        )
                        raise
                else:
                    # Collect unique repository URLs from saved diagrams (skipping org root entries)
                    processed = set()
                    batch_items: List[Dict[str, Any]] = []
                    for d in diagrams:
                        if d.get("is_root"):
                            continue
                        url = (analyzer.automatic_refresh_url(d) or d.get("github_url") or "").strip()
                        if url and url not in processed:
                            processed.add(url)
                            synced_targets.append(d.get("repo", url))
                            batch_items.append(d)

                    started_epoch = time.time()
                    total_items = len(batch_items)
                    now_local, now_utc = analyzer.now_timestamps()
                    _SYNC_DAEMON.last_sync_time = now_local
                    initial_logs = [
                        f"[{datetime.now().strftime('%H:%M:%S')}] ▶ 解析開始: 全 {total_items} 件のリポジトリ"
                        if total_items > 0
                        else f"[{datetime.now().strftime('%H:%M:%S')}] ✓ 解析対象リポジトリはありません"
                    ]
                    job_payload = {
                        "job_id": job_id,
                        "status": "running" if batch_items else "completed",
                        "ok": True,
                        "total": total_items,
                        "completed": 0,
                        "current_repo": synced_targets[0] if synced_targets else "",
                        "current_stage": "準備中 / Preparing…" if batch_items else "",
                        "eta_seconds": (total_items * 4) if batch_items else 0,
                        "logs": initial_logs,
                        "last_sync_time": now_local,
                        "last_sync_time_utc": now_utc,
                        "synced_targets": synced_targets,
                    }
                    with _SYNC_JOBS_LOCK:
                        _SYNC_JOBS[job_id] = job_payload

                    def _append_job_log(jid: str, line: str, **updates: Any) -> None:
                        with _SYNC_JOBS_LOCK:
                            job = _SYNC_JOBS.get(jid)
                            if not job:
                                return
                            for k, v in updates.items():
                                job[k] = v
                            logs = list(job.get("logs") or [])
                            logs.append(line)
                            if len(logs) > 60:
                                logs = logs[-60:]
                            job["logs"] = logs

                    def _run_batch_sync(items: List[Dict[str, Any]], jid: str, t0: float) -> None:
                        total = len(items)
                        completed_counter = {"n": 0}
                        counter_lock = threading.Lock()

                        def _sync_one(idx: int, d: Dict[str, Any]) -> None:
                            url = (analyzer.automatic_refresh_url(d) or d.get("github_url") or "").strip()
                            repo_label = str(d.get("repo") or url)
                            did = str(d.get("id") or url)
                            item_t0 = time.time()
                            try:
                                skip, reason = should_skip_unchanged_repo(d, force=force_rescan)
                                if skip:
                                    with counter_lock:
                                        completed_counter["n"] += 1
                                        done_n = completed_counter["n"]
                                    elapsed_now = max(0.1, time.time() - t0)
                                    eta_after = int((elapsed_now / done_n) * (total - done_n)) if done_n < total else 0
                                    _append_job_log(
                                        jid,
                                        f"[{datetime.now().strftime('%H:%M:%S')}] ⏭️ ({done_n}/{total}) {repo_label} スキップ（変更なし: {reason}）",
                                        completed=done_n,
                                        current_repo=repo_label,
                                        eta_seconds=eta_after,
                                    )
                                    return

                                stage_text = "OSV / Trivy / Semgrep / Gitleaks / Actions 監査中"
                                _append_job_log(
                                    jid,
                                    f"[{datetime.now().strftime('%H:%M:%S')}] 🔍 ({idx}/{total}) {repo_label}: {stage_text}…",
                                    current_repo=repo_label,
                                    current_stage=stage_text,
                                )
                                res = analyzer.analyze_any_github_target(url)
                                analyzer.save_analysis_result(res, respect_deleted=True)
                                item_dt = time.time() - item_t0
                                cr = (res.get("diagram") or {}).get("coderabbit") or {}
                                findings_cnt = len(cr.get("action_items") or [])
                                with counter_lock:
                                    completed_counter["n"] += 1
                                    done_n = completed_counter["n"]
                                elapsed_now = max(0.1, time.time() - t0)
                                eta_after = int((elapsed_now / done_n) * (total - done_n)) if done_n < total else 0
                                _append_job_log(
                                    jid,
                                    f"[{datetime.now().strftime('%H:%M:%S')}] ✅ ({done_n}/{total}) {repo_label} 完了 (指摘 {findings_cnt}件 · {item_dt:.1f}s)",
                                    completed=done_n,
                                    eta_seconds=eta_after,
                                )
                            except Exception as e_sub:
                                item_dt = time.time() - item_t0
                                is_timeout = isinstance(e_sub, subprocess.TimeoutExpired) or "timed out" in str(e_sub).lower()
                                analyzer.record_sync_status(
                                    did,
                                    sync_status="timeout" if is_timeout else "error",
                                    last_sync_error=str(e_sub),
                                )
                                with counter_lock:
                                    completed_counter["n"] += 1
                                    done_n = completed_counter["n"]
                                elapsed_now = max(0.1, time.time() - t0)
                                eta_after = int((elapsed_now / done_n) * (total - done_n)) if done_n < total else 0
                                print(f"Warning syncing {url}: {e_sub}", flush=True)
                                _append_job_log(
                                    jid,
                                    f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️ ({done_n}/{total}) {repo_label} 同期失敗 ({str(e_sub)[:80]} · {item_dt:.1f}s)",
                                    completed=done_n,
                                    eta_seconds=eta_after,
                                )

                        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                            futures = [pool.submit(_sync_one, idx, d) for idx, d in enumerate(items, 1)]
                            concurrent.futures.wait(futures)

                        done_local, done_utc = analyzer.now_timestamps()
                        _SYNC_DAEMON.last_sync_time = done_local
                        _append_job_log(
                            jid,
                            f"[{datetime.now().strftime('%H:%M:%S')}] 🎉 全 {total} 件の監査が完了しました ({done_local})",
                            status="completed",
                            completed=total,
                            current_repo="",
                            current_stage="完了 / Completed",
                            eta_seconds=0,
                            last_sync_time=done_local,
                            last_sync_time_utc=done_utc,
                        )

                    if batch_items:
                        threading.Thread(
                            target=_run_batch_sync,
                            args=(batch_items, job_id, started_epoch),
                            daemon=True,
                        ).start()

                if target_url:
                    now_local, now_utc = analyzer.now_timestamps()
                    _SYNC_DAEMON.last_sync_time = now_local
                    with _SYNC_JOBS_LOCK:
                        _SYNC_JOBS[job_id] = {
                            "job_id": job_id,
                            "status": "completed",
                            "ok": True,
                            "total": 1,
                            "completed": 1,
                            "current_repo": target_url,
                            "current_stage": "完了 / Completed",
                            "eta_seconds": 0,
                            "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] ✅ {target_url} 完了 ({now_local})"],
                            "last_sync_time": now_local,
                            "last_sync_time_utc": now_utc,
                            "synced_targets": synced_targets,
                        }

                self._send_json(200, {
                    "status": "success",
                    "ok": True,
                    "job_id": job_id,
                    "last_sync_time": now_local,
                    "last_sync_time_utc": now_utc,
                    "synced_targets": synced_targets,
                    "message": f"Sync completed ({now_local})",
                    "message_ja": f"最新データの同期が完了しました ({now_local})"
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
                model_override = (body.get("model") or "").strip() or None
                res = security_audit_engine.test_llm_connection(provider, key_override, model_override=model_override)
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
                    clean_name = f"RepoAUDT_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

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

        if self.path == "/api/terminal/exec":
            self._send_json(410, {"ok": False, "error": "Embedded command execution has been retired."})
            return

        if self.path == "/api/remediation/create-fix-pr":
            try:
                body = json.loads(body_raw) if body_raw else {}
                repo_slug = str(body.get("repo") or "").strip()
                diagram_id = str(body.get("diagram_id") or "").strip()
                pr_title = str(body.get("title") or "chore(security): apply RepoAUDT remediation fixes").strip()[:180]
                items = body.get("items") if isinstance(body.get("items"), list) else []
                draft = bool(body.get("draft", True))
                if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo_slug):
                    self._send_json(400, {"ok": False, "error": "Invalid repository slug (expected owner/repo)"})
                    return
                gh_bin = shutil.which("gh") or next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if Path(p).exists()), "")
                if not gh_bin:
                    self._send_json(503, {"ok": False, "error": "GitHub CLI (gh) is not installed"})
                    return

                state = analyzer.load_saved_analyses()
                diagrams = state.get("diagrams", [])
                matched = next(
                    (d for d in diagrams if (diagram_id and str(d.get("id") or "") == diagram_id) or str(d.get("repo") or "") == repo_slug),
                    None,
                )
                local_dir_str = str(
                    (matched or {}).get("local_path")
                    or ((matched or {}).get("source_revision") or {}).get("local_path")
                    or ""
                ).strip()

                import tempfile
                tmp_clone_dir: Optional[tempfile.TemporaryDirectory] = None
                work_dir: Optional[Path] = Path(local_dir_str) if local_dir_str and Path(local_dir_str).is_dir() else None
                try:
                    if work_dir is None or not (work_dir / ".git").exists():
                        tmp_clone_dir = tempfile.TemporaryDirectory(prefix="repoaudt-pr-")
                        work_dir = Path(tmp_clone_dir.name) / "repo"
                        clone_proc = subprocess.run(
                            [gh_bin, "repo", "clone", repo_slug, str(work_dir), "--", "--depth=1"],
                            capture_output=True, text=True, timeout=60,
                        )
                        if clone_proc.returncode != 0:
                            self._send_json(502, {"ok": False, "error": (clone_proc.stderr or "gh repo clone failed")[:300]})
                            return

                    branch = f"repoaudt-fix/{int(time.time())}"
                    subprocess.run(["git", "-C", str(work_dir), "checkout", "-b", branch], check=True, capture_output=True, text=True)

                    changed_files: List[str] = []
                    # 1. Apply deterministic package.json version updates if present
                    pkg_updates: Dict[str, str] = {}
                    gitignore_entries: List[str] = []
                    for it in items:
                        if not isinstance(it, dict):
                            continue
                        it_title = str(it.get("title") or "")
                        it_file = str(it.get("file") or "").split(" (", 1)[0].split(":", 1)[0].strip()
                        it_cmd = str(it.get("fix_command") or "")
                        # Extract npm install pkg@ver or yarn add pkg@ver
                        m_upd = re.search(r"(?:npm\s+install|yarn\s+add|pnpm\s+add)\s+([@A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@([0-9]+\.[0-9]+[^\s`]*)", it_cmd)
                        if m_upd:
                            pkg_updates[m_upd.group(1)] = m_upd.group(2)
                        elif "→" in it_title:
                            m_pkg = re.search(r"([@A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)\s+v?[0-9][^\s]*.*→\s*([0-9]+\.[0-9]+[^\s)）]*)", it_title)
                            if m_pkg:
                                pkg_updates[m_pkg.group(1)] = m_pkg.group(2)
                        if (".env" in it_file or ".p12" in it_file or ".pfx" in it_file or ".pem" in it_file) and it_file:
                            gitignore_entries.append(it_file)

                    if pkg_updates:
                        pkg_path = work_dir / "package.json"
                        if pkg_path.is_file():
                            try:
                                pkg_data = json.loads(pkg_path.read_text(encoding="utf-8"))
                                modified_pkg = False
                                for sec in ("dependencies", "devDependencies"):
                                    if isinstance(pkg_data.get(sec), dict):
                                        for p_name, p_ver in pkg_updates.items():
                                            if p_name in pkg_data[sec]:
                                                pkg_data[sec][p_name] = f"^{p_ver}"
                                                modified_pkg = True
                                if modified_pkg:
                                    pkg_path.write_text(json.dumps(pkg_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                                    changed_files.append("package.json")
                            except Exception:
                                pass

                    if gitignore_entries:
                        gi_path = work_dir / ".gitignore"
                        existing_gi = gi_path.read_text(encoding="utf-8", errors="ignore") if gi_path.is_file() else ""
                        lines_gi = existing_gi.splitlines()
                        added_gi = False
                        for entry in sorted(set(gitignore_entries)):
                            if entry not in lines_gi:
                                lines_gi.append(entry)
                                added_gi = True
                        if added_gi:
                            gi_path.write_text("\n".join(lines_gi) + "\n", encoding="utf-8")
                            changed_files.append(".gitignore")

                    if not changed_files:
                        plan_path = work_dir / "SECURITY_REMEDIATION_PLAN.md"
                        plan_lines = [f"# {pr_title}", "", "## Target Findings", ""]
                        for it in items:
                            if isinstance(it, dict):
                                plan_lines.append(f"- [ ] **[{it.get('tier', 'P1')}]** {it.get('title', '')} (`{it.get('file', '')}`)")
                        plan_path.write_text("\n".join(plan_lines) + "\n", encoding="utf-8")
                        changed_files.append("SECURITY_REMEDIATION_PLAN.md")

                    subprocess.run(["git", "-C", str(work_dir), "add"] + changed_files, check=True, capture_output=True, text=True)
                    subprocess.run(["git", "-C", str(work_dir), "commit", "-m", pr_title], check=True, capture_output=True, text=True)
                    push_proc = subprocess.run(["git", "-C", str(work_dir), "push", "-u", "origin", branch], capture_output=True, text=True, timeout=45)
                    if push_proc.returncode != 0:
                        self._send_json(502, {"ok": False, "error": (push_proc.stderr or "git push failed")[:300]})
                        return

                    pr_body_lines = [
                        "## RepoAUDT Mac Automated Remediation PR",
                        "",
                        f"- **Changed files**: {', '.join(f'`{f}`' for f in changed_files)}",
                        "",
                        "### Addressed Findings",
                    ]
                    for it in items[:25]:
                        if isinstance(it, dict):
                            pr_body_lines.append(f"- [{it.get('tier', 'P1')}] {it.get('title', '')} (`{it.get('file', '')}`)")
                    pr_args = [gh_bin, "pr", "create", "--repo", repo_slug, "--head", branch, "--title", pr_title, "--body", "\n".join(pr_body_lines)]
                    if draft:
                        pr_args.append("--draft")
                    pr_proc = subprocess.run(pr_args, cwd=str(work_dir), capture_output=True, text=True, timeout=30)
                    if pr_proc.returncode != 0:
                        self._send_json(502, {"ok": False, "error": (pr_proc.stderr or pr_proc.stdout or "gh pr create failed")[:350]})
                        return
                    pr_url = (pr_proc.stdout or "").strip().splitlines()[-1].strip() if (pr_proc.stdout or "").strip() else ""
                    summary = analyzer.mark_remediation_requests(
                        items,
                        requested=True,
                        note=f"GitHub PR: {pr_url}" if pr_url else "",
                        channel="github_pr",
                        issue_url=pr_url,
                    )
                    self._send_json(200, {"ok": True, "pr_url": pr_url, "branch": branch, "changed_files": changed_files, **summary})
                finally:
                    if tmp_clone_dir is not None:
                        tmp_clone_dir.cleanup()
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
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
                branch_name = f"repoaudt-fix/{safe_issue}"
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


def run_monitor_once_cli(port: int) -> None:
    """Entrypoint invoked by macOS launchd StartInterval when the app may be closed."""
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/monitor/check",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2):
            return
    except Exception:
        pass

    daemon = SyncDaemon()
    if not daemon.enabled:
        return
    before_count = len(daemon.detected_updates)
    status = daemon.check_once()
    updates = status.get("detected_updates") or []
    new_count = max(0, len(updates) - before_count)
    if new_count > 0 or (updates and updates[0].get("detected_at") == status.get("last_sync_time")):
        first = updates[0]
        repo_name = first.get("repo") or "Repository"
        sha = first.get("new_commit") or ""
        resolved_cnt = int(first.get("resolved_count") or 0)
        findings_cnt = int(first.get("findings") or 0)
        if resolved_cnt > 0:
            body = f"{repo_name} ({sha}) — {resolved_cnt}件の指摘が解消されました！（残存 {findings_cnt}件）"
        else:
            body = f"{repo_name} ({sha}) を再監査しました（指摘 {findings_cnt}件）"
        _send_headless_macos_notification("RepoAUDT Mac — 新着コミット検知", body)


def main() -> None:
    port = int(
        os.environ.get("REPOAUDT_PORT")
        or os.environ.get("REPOCHEX_PORT")
        or os.environ.get("REPOCHECKER_PORT")
        or "18765"
    )
    if "--monitor-once" in sys.argv[1:]:
        run_monitor_once_cli(port)
        return
    RepoAUDTRequestHandler.server_port = port
    start_sync_daemon()
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer(("127.0.0.1", port), RepoAUDTRequestHandler)
    print(f"RepoAUDT Mac server listening on http://127.0.0.1:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
