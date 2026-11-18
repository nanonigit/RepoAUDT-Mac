"""Explicit MCP client operations over newline stdio or Streamable HTTP (2025-11-25)."""

import contextlib
import json
import os
import queue
import re
import signal
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

from connection_utils import open_endpoint, validate_endpoint
import security_audit_engine

CONFIG_FILE = security_audit_engine.APP_SUPPORT_DIR / "mcp-client.json"
DEFAULT_CONFIG = {
    "transport": "stdio",
    "command": "/usr/bin/python3",
    "args": [str(Path(__file__).with_name("mcp_server.py"))],
    "url": "http://127.0.0.1:18765/api/mcp",
    "token_env": "",
}
PROTOCOL = "2025-11-25"
LIMIT = 2 * 1024 * 1024


def validate_config(config):
    if not isinstance(config, dict) or config.get("transport") not in ("stdio", "http"):
        raise ValueError("Choose stdio or HTTP transport")
    result = {key: config.get(key, default) for key, default in DEFAULT_CONFIG.items()}
    if result["transport"] == "http":
        result["url"] = validate_endpoint(result["url"])
    command, args, env_name = result["command"], result["args"], result["token_env"]
    if not isinstance(command, str) or not command.strip() or len(command) > 4096:
        raise ValueError("Enter an executable path or command")
    if (
        not isinstance(args, list)
        or len(args) > 100
        or not all(isinstance(arg, str) and len(arg) <= 8192 for arg in args)
    ):
        raise ValueError("Arguments must be a JSON array of strings")
    if not isinstance(env_name, str) or (
        env_name and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name)
    ):
        raise ValueError("Invalid token environment variable name")
    return result


def load_config():
    if not CONFIG_FILE.exists():
        return dict(DEFAULT_CONFIG)
    return validate_config(json.loads(CONFIG_FILE.read_text()))


def save_config(config):
    validated = validate_config(config)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = CONFIG_FILE.with_name("mcp-client." + str(threading.get_ident()) + ".tmp")
    try:
        with open(
            temp, "w", opener=lambda path, flags: os.open(path, flags, 0o600)
        ) as target:
            json.dump(validated, target, ensure_ascii=False)
        os.replace(temp, CONFIG_FILE)
    finally:
        temp.unlink(missing_ok=True)
    return validated


def checked_response(message, request_id):
    if (
        not isinstance(message, dict)
        or message.get("jsonrpc") != "2.0"
        or message.get("id") != request_id
    ):
        raise ValueError("MCP response ID or format is invalid")
    if "error" in message:
        raise RuntimeError(
            "MCP error: " + str(message["error"].get("message", "Unknown error"))
        )
    if "result" not in message:
        raise ValueError("MCP response has no result")
    return message["result"]


@contextlib.contextmanager
def stdio_transport(config):
    # Only the executable and argument array entered in the connection screen are run.
    process = subprocess.Popen(
        [config["command"], *config["args"]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    messages = queue.Queue(maxsize=128)
    stop = threading.Event()

    def read_messages():
        try:
            while not stop.is_set():
                line = process.stdout.readline(LIMIT + 1)
                if not line:
                    break
                if len(line) > LIMIT:
                    raise ValueError("MCP message exceeds size limit")
                message = json.loads(line)
                messages.put_nowait(message)
        except Exception as error:
            try:
                messages.put_nowait(error)
            except queue.Full:
                pass
        finally:
            try:
                messages.put_nowait(EOFError("MCP process closed stdout"))
            except queue.Full:
                pass

    reader = threading.Thread(target=read_messages, daemon=True)
    reader.start()

    def exchange(message):
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()
        if "id" not in message:
            return None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                incoming = messages.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty as error:
                raise TimeoutError("MCP request timed out") from error
            if isinstance(incoming, Exception):
                raise incoming
            if "method" in incoming and "id" in incoming:
                process.stdin.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": incoming["id"],
                            "error": {
                                "code": -32601,
                                "message": "Client capability not supported",
                            },
                        }
                    ).encode()
                    + b"\n"
                )
                process.stdin.flush()
            elif incoming.get("id") == message["id"]:
                return checked_response(incoming, message["id"])
        raise TimeoutError("MCP request timed out")

    try:
        yield exchange
    finally:
        stop.set()
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        process.stdin.close()
        reader.join(timeout=2)
        process.stdout.close()


@contextlib.contextmanager
def http_transport(config):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if config["token_env"]:
        token = os.environ.get(config["token_env"])
        if not token:
            raise ValueError("Token environment variable is not set")
        headers["Authorization"] = "Bearer " + token

    def exchange(message):
        request = urllib.request.Request(
            config["url"],
            data=json.dumps(message).encode(),
            headers=headers,
            method="POST",
        )
        with open_endpoint(request, timeout=30) as response:
            session = response.headers.get("Mcp-Session-Id")
            if session:
                headers["Mcp-Session-Id"] = session
            if "id" not in message:
                return None
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                consumed, data = 0, []
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    line = response.readline(LIMIT + 1)
                    consumed += len(line)
                    if consumed > LIMIT:
                        raise ValueError("MCP stream exceeds size limit")
                    if not line:
                        break
                    text = line.decode("utf-8").rstrip("\r\n")
                    if text.startswith("data:"):
                        data.append(text[5:].lstrip())
                    elif not text and data:
                        incoming = json.loads("\n".join(data))
                        data = []
                        if incoming.get("id") == message["id"]:
                            return checked_response(incoming, message["id"])
                raise TimeoutError("MCP stream ended without a matching response")
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("MCP response exceeds size limit")
            return checked_response(json.loads(raw), message["id"])

    try:
        yield exchange, headers
    finally:
        if headers.get("Mcp-Session-Id"):
            try:
                with open_endpoint(
                    urllib.request.Request(
                        config["url"], headers=headers, method="DELETE"
                    ),
                    timeout=5,
                ):
                    pass
            except Exception:
                # Servers may reject optional session termination. Operations already completed.
                pass


def run_operation(config, method="tools/list", params=None):
    config = validate_config(config)
    if method not in ("tools/list", "tools/call"):
        raise ValueError("Unsupported client operation")
    if params is not None and not isinstance(params, dict):
        raise ValueError("Tool parameters must be an object")
    if method == "tools/call" and (
        not params
        or not isinstance(params.get("name"), str)
        or not isinstance(params.get("arguments", {}), dict)
    ):
        raise ValueError("Enter a tool name and an arguments object")
    manager = (
        stdio_transport(config)
        if config["transport"] == "stdio"
        else http_transport(config)
    )
    with manager as transport:
        exchange, headers = (
            transport if isinstance(transport, tuple) else (transport, None)
        )
        initialize = exchange(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "RepoAUDT Mac", "version": "1.2.0"},
                },
            }
        )
        version = initialize.get("protocolVersion")
        if version not in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
            raise ValueError("Unsupported MCP protocol version: " + str(version))
        if headers is not None:
            headers["MCP-Protocol-Version"] = version
        exchange({"jsonrpc": "2.0", "method": "notifications/initialized"})
        result = exchange(
            {"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}}
        )
        if method == "tools/list":
            tools = list(result.get("tools", []))
            cursor = result.get("nextCursor")
            pages = 0
            while cursor:
                pages += 1
                if pages > 20:
                    raise ValueError("MCP tool list exceeds page limit")
                page = exchange(
                    {
                        "jsonrpc": "2.0",
                        "id": 2 + pages,
                        "method": method,
                        "params": {"cursor": cursor},
                    }
                )
                tools.extend(page.get("tools", []))
                cursor = page.get("nextCursor")
            result = {"tools": tools}
        return {
            "serverInfo": initialize.get("serverInfo", {}),
            "protocolVersion": version,
            "result": result,
        }
