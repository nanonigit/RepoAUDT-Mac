"""
Common test helper utilities for RepoAUDT Mac E2E Test Suite.
Provides file loaders, mock HTTP socket handling, temporary environment builders,
and HTML/AST analysis helpers.
"""

import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "Resources" / "backend"
WEBUI_DIR = REPO_ROOT / "Resources" / "webui"
SOURCES_DIR = REPO_ROOT / "Sources"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def get_webui_html() -> str:
    """Load the current Resources/webui/index.html contents."""
    index_path = WEBUI_DIR / "index.html"
    if not index_path.exists():
        return ""
    return index_path.read_text(encoding="utf-8", errors="ignore")


def get_portal_builder_source() -> str:
    """Load Resources/backend/portal_builder.py source code."""
    builder_path = BACKEND_DIR / "portal_builder.py"
    return builder_path.read_text(encoding="utf-8", errors="ignore")


def get_server_source() -> str:
    """Load Resources/backend/server.py source code."""
    server_path = BACKEND_DIR / "server.py"
    return server_path.read_text(encoding="utf-8", errors="ignore")


def get_analyzer_source() -> str:
    """Load Resources/backend/analyzer.py source code."""
    analyzer_path = BACKEND_DIR / "analyzer.py"
    return analyzer_path.read_text(encoding="utf-8", errors="ignore")


def get_security_audit_source() -> str:
    """Load Resources/backend/security_audit_engine.py source code."""
    sec_path = BACKEND_DIR / "security_audit_engine.py"
    return sec_path.read_text(encoding="utf-8", errors="ignore")


def get_swift_app_source() -> str:
    """Load Sources/RepoAUDTMacApp.swift source code."""
    swift_path = SOURCES_DIR / "RepoAUDTMacApp.swift"
    return swift_path.read_text(encoding="utf-8", errors="ignore")


class MockSocket:
    """In-memory mock socket simulating HTTP client connections."""

    def __init__(self, request_bytes: bytes):
        self._rfile = io.BytesIO(request_bytes)
        self.output = bytearray()

    def makefile(self, mode: str, *args: Any, **kwargs: Any) -> io.BytesIO:
        if "r" in mode:
            return self._rfile
        return io.BytesIO()

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)


def simulate_http_request(
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, str], Any]:
    """
    Executes a simulated HTTP request against server.RepoAUDTRequestHandler in-memory.
    Returns: (status_code, response_headers, parsed_json_or_text)
    """
    import server

    raw_body = json.dumps(body).encode("utf-8") if body is not None else b""
    hdr_lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1:18765"]
    if headers:
        for k, v in headers.items():
            hdr_lines.append(f"{k}: {v}")
    if raw_body:
        hdr_lines.append(f"Content-Length: {len(raw_body)}")
        hdr_lines.append("Content-Type: application/json")

    request_raw = ("\r\n".join(hdr_lines) + "\r\n\r\n").encode("utf-8") + raw_body
    sock = MockSocket(request_raw)

    server.RepoAUDTRequestHandler.server_port = 18765
    handler = server.RepoAUDTRequestHandler(sock, ("127.0.0.1", 54321), None)

    raw_response = bytes(sock.output)
    if b"\r\n\r\n" not in raw_response:
        return 500, {}, raw_response.decode("utf-8", errors="replace")

    headers_part, body_part = raw_response.split(b"\r\n\r\n", 1)
    status_line = headers_part.split(b"\r\n")[0].decode("utf-8", errors="ignore")
    status_code = int(status_line.split(" ")[1]) if " " in status_line else 200

    resp_headers = {}
    for line in headers_part.split(b"\r\n")[1:]:
        s = line.decode("utf-8", errors="ignore")
        if ": " in s:
            k, v = s.split(": ", 1)
            resp_headers[k.lower()] = v

    decoded_body = body_part.decode("utf-8", errors="replace")
    try:
        parsed_payload = json.loads(decoded_body)
    except Exception:
        parsed_payload = decoded_body

    return status_code, resp_headers, parsed_payload
