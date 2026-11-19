import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import runtime_patches as runtime

PHP = json.dumps(
    [
        {
            "ghsa_id": "GHSA-abcd-abcd-abcd",
            "cve_id": "CVE-2026-9999",
            "severity": "high",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "php", "name": "core"},
                    "vulnerable_version_range": ">= 8.4.0, < 8.4.28",
                    "patched_versions": "8.4.28",
                    "vulnerable_functions": ["fixture_function"],
                }
            ],
        }
    ]
)
NGINX = "<li><p>Example<br>Severity: major<br>CVE-2026-9876<br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 0.6.18-1.31.8</p></li>"
POSTGRES = "<tr><td>CVE-2026-9877</td><td>18, 17</td><td>18.7, 17.12</td><td>core server</td></tr>"
GO = '<p id="go1.26.11">go1.26.11 (released 2026-11-10) includes <a href="/security">security\n\tfixes</a>.</p>'
NODE = json.dumps(
    [
        {"version": "v24.22.3", "security": True, "date": "2026-11-11"},
        {"version": "v24.25.0", "security": True, "date": "2099-01-01"},
        {"version": "v24.22.4", "security": False, "date": "2026-11-12"},
        {"version": "v26.13.1", "security": True, "date": "2026-11-11"},
    ]
)
SCHEDULE = json.dumps({"v24": {"end": "2028-04-30"}, "v20": {"end": "2026-04-30"}})


class RuntimePatchTests(unittest.TestCase):
    def test_inventory_distinguishes_a_pin_range_digest_and_unmapped_images(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text(
                "FROM node:24.19.0-bookworm-slim AS build\n"
                "FROM build AS test\nFROM php:8.4.20-fpm@sha256:deadbeef\n"
                "FROM ghcr.io/example/custom:1.2.3\nFROM nginx:stable\n"
            )
            (root / "package.json").write_text('{"engines":{"node":">=18 || >=22"}}')
            (root / "go.mod").write_text(
                "module fixture\ngo 1.26\ntoolchain go1.26.9\n"
            )
            (root / "compose.yml").write_text(
                "services:\n  db:\n    image: postgres:18.1-alpine\n"
            )
            evidence, limited = runtime.repository_evidence(root)
        self.assertFalse(limited)
        self.assertEqual(
            [(r["product"], r["version"]) for r in evidence],
            [
                ("node", "24.19.0"),
                ("php", None),
                ("image", None),
                ("nginx", None),
                ("postgres", "18.1"),
                ("go", None),
                ("go", "1.26.9"),
                ("node", None),
            ],
        )
        self.assertEqual(evidence[-1]["kind"], "constraint")

    def test_nginx_patched_stable_branch_overrides_broad_range(self):
        self.assertEqual(runtime.nginx_matches(NGINX, (1, 30, 7)), [])
        found = runtime.nginx_matches(NGINX, (1, 30, 6))
        self.assertEqual(found[0]["fixed_versions"], ["1.30.7", "1.31.9"])
        self.assertEqual(
            runtime.nginx_matches(NGINX, (1, 31, 8))[0]["fixed_versions"], ["1.31.9"]
        )

    def test_node_uses_own_major_and_skips_future_releases(self):
        item = runtime.node_matches(NODE, SCHEDULE, (24, 21, 0), "2026-11-19")[0]
        self.assertEqual(item["security_release"], "24.22.3")
        self.assertEqual(item["latest_release"], "24.22.4")
        self.assertEqual(item["fixed_versions"], [])
        self.assertEqual(
            runtime.node_matches(NODE, SCHEDULE, (20, 22, 0), "2026-11-19")[0]["id"],
            "EOL",
        )

    def test_go_and_postgres_report_only_the_matching_branch(self):
        self.assertEqual(
            runtime.go_matches(GO, (1, 26, 8), "2026-11-19")[0]["security_release"],
            "1.26.11",
        )
        self.assertEqual(
            runtime.postgres_matches(POSTGRES, (18, 1))[0]["fixed_versions"], ["18.7"]
        )
        self.assertEqual(runtime.postgres_matches(POSTGRES, (18, 7)), [])
        self.assertEqual(runtime.postgres_matches(POSTGRES, (16, 1)), [])

    def test_unsupported_or_unavailable_never_means_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text("FROM nginx:1.30.1\nFROM redis:7.4.6\n")
            with patch.object(runtime, "fetch", side_effect=ValueError("offline")):
                issues, scope = runtime.scan_runtime_patches(root, str)
        self.assertEqual(scope["feeds"]["nginx"]["status"], "unavailable")
        self.assertEqual(scope["feeds"]["image"]["status"], "vendor_unmapped")
        self.assertEqual([i["scanner"] for i in issues], ["runtime-inventory"])

    def test_php_fixed_version_and_lexical_symbol_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text("FROM php:8.4.20-fpm\n")
            (root / "example.php").write_text(
                "<?php\n// fixture_function();\nfixture_function();\n"
            )
            with patch.object(
                runtime, "fetch", side_effect=[(PHP, "now"), ("<td>8.1</td>", "now")]
            ):
                issues, scope = runtime.scan_runtime_patches(root, str)
        patch_record = issues[1]["runtime_patch"]
        self.assertEqual(patch_record["fixed_versions"], ["8.4.28"])
        self.assertEqual(
            patch_record["possible_usage"],
            [{"file": "example.php", "line": 3, "symbol": "fixture_function"}],
        )
        self.assertEqual(scope["pins"]["php"]["8.4.20"]["status"], "checked")
        self.assertEqual(runtime.php_matches(PHP, (8, 4, 28)), [])
        self.assertNotIn("fix_cmd", issues[1])
