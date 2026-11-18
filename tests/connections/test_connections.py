import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import connection_utils
import mcp_client
import mcp_server
import security_audit_engine as engine


class ConnectionTests(unittest.TestCase):
    def test_local_provider_is_selected_without_cloud_key(self):
        settings = json.loads(json.dumps(engine.DEFAULT_SETTINGS))
        settings["active_provider"] = "local"
        settings["models"]["local"] = "fixture-model"
        self.assertEqual(
            engine.choose_active_llm(settings), ("local", "", "fixture-model")
        )
        settings["skills"]["llm_deep_audit"] = False
        self.assertIsNone(engine.choose_active_llm(settings))

    def test_legacy_settings_survive_local_save(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with (
                patch.object(engine, "APP_SUPPORT_DIR", directory),
                patch.object(engine, "SETTINGS_FILE", directory / "settings.json"),
                patch.object(engine, "get_candidate_env_files", return_value=[]),
                patch.dict("os.environ", {}, clear=True),
            ):
                engine.save_settings(
                    {
                        "keys": {"claude": "fixture-test-key"},
                        "models": {"claude": "saved-model"},
                    }
                )
                engine.save_settings(
                    {
                        "active_provider": "local",
                        "models": {"local": "local-model"},
                        "local_base_url": "http://127.0.0.1:1234/v1",
                    }
                )
                loaded = engine.load_settings()
                self.assertEqual(loaded["keys"]["claude"], "fixture-test-key")
                self.assertEqual(loaded["models"]["claude"], "saved-model")
                self.assertTrue(
                    engine.get_masked_settings(loaded)["configured"]["local"]
                )
                self.assertNotIn(
                    "fixture-test-key", json.dumps(engine.get_masked_settings(loaded))
                )

    def test_endpoints_reject_remote_local_inference_and_plaintext_remote_mcp(self):
        for endpoint in (
            "http://example.com/v1",
            "https://example.com/v1",
            "http://localhost@evil.test/v1",
            "file:///tmp/llm",
        ):
            with self.assertRaises(ValueError):
                connection_utils.validate_endpoint(endpoint, local_only=True)
        with self.assertRaises(ValueError):
            connection_utils.validate_endpoint("http://example.com/mcp")

    def test_actual_local_completion_request(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(
                    (
                        self.path,
                        json.loads(
                            self.rfile.read(int(self.headers["Content-Length"]))
                        ),
                    )
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"choices": [{"message": {"content": '{"items":[]}'}}]}
                    ).encode()
                )

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = {"local_base_url": f"http://127.0.0.1:{server.server_port}/v1"}
            with patch.object(engine, "load_settings", return_value=settings):
                self.assertEqual(
                    engine.call_llm_provider(
                        "local", "", "fixture-model", "system", "user"
                    ),
                    '{"items":[]}',
                )
            self.assertEqual(received[0][0], "/v1/chat/completions")
            self.assertEqual(received[0][1]["model"], "fixture-model")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_stdio_initialize_list_and_real_tool_execution(self):
        config = dict(
            mcp_client.DEFAULT_CONFIG,
            command=sys.executable,
            args=[str(Path(mcp_server.__file__))],
        )
        listed = mcp_client.run_operation(config)
        names = [tool["name"] for tool in listed["result"]["tools"]]
        self.assertIn("scan_code_snippet_security", names)
        called = mcp_client.run_operation(
            config,
            "tools/call",
            {
                "name": "scan_code_snippet_security",
                "arguments": {
                    "code": 'import subprocess\nsubprocess.run("echo x", shell=True)',
                    "language": "python",
                },
            },
        )
        self.assertFalse(called["result"].get("isError", False))
        self.assertIn("content", called["result"])

    def test_http_initialize_session_sse_and_tool_call(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                message = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                received.append(
                    (
                        message,
                        self.headers.get("Mcp-Session-Id"),
                        self.headers.get("MCP-Protocol-Version"),
                    )
                )
                method = message["method"]
                if method == "notifications/initialized":
                    self.send_response(202)
                    self.end_headers()
                    return
                result = (
                    {"protocolVersion": "2025-11-25", "serverInfo": {"name": "fixture"}}
                    if method == "initialize"
                    else {"tools": [{"name": "fixture-tool"}]}
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Mcp-Session-Id", "fixture-session")
                self.end_headers()
                self.wfile.write(
                    (
                        "data: "
                        + json.dumps(
                            {"jsonrpc": "2.0", "id": message["id"], "result": result}
                        )
                        + "\n\n"
                    ).encode()
                )

            def do_DELETE(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = dict(
                mcp_client.DEFAULT_CONFIG,
                transport="http",
                url=f"http://127.0.0.1:{server.server_port}/mcp",
            )
            result = mcp_client.run_operation(config)
            self.assertEqual(result["result"]["tools"][0]["name"], "fixture-tool")
            self.assertEqual(received[2][1:], ("fixture-session", "2025-11-25"))
            self.assertIn(
                "notifications/initialized", [entry[0]["method"] for entry in received]
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_mcp_config_roundtrip_and_invalid_input(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            patch.object(mcp_client, "CONFIG_FILE", Path(temp) / "client.json"),
        ):
            saved = mcp_client.save_config(dict(mcp_client.DEFAULT_CONFIG))
            self.assertEqual(mcp_client.load_config(), saved)
            self.assertEqual(mcp_client.CONFIG_FILE.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            mcp_client.validate_config(
                dict(mcp_client.DEFAULT_CONFIG, args="not-an-array")
            )
        with self.assertRaises(RuntimeError):
            mcp_client.checked_response(
                {"jsonrpc": "2.0", "id": 1, "error": {"message": "fixture failure"}}, 1
            )

    def test_stdio_process_failure_is_reported(self):
        config = dict(
            mcp_client.DEFAULT_CONFIG, command=sys.executable, args=["-c", "pass"]
        )
        with self.assertRaises((EOFError, BrokenPipeError)):
            mcp_client.run_operation(config)


if __name__ == "__main__":
    unittest.main()
