"""Unit tests for Live Threat Feed (CISA KEV + GHSA Critical) and repository code/config correlation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import threat_feed  # noqa: E402


class TestThreatFeed(unittest.TestCase):
    def test_correlates_nginx_dockerfile_and_confirmed_cve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text("FROM nginx:1.25-alpine\nCOPY nginx.conf /etc/nginx/nginx.conf\n", encoding="utf-8")
            (root / "nginx.conf").write_text("events {}\nhttp {}\n", encoding="utf-8")

            diagrams = [
                {
                    "id": "r-nginx",
                    "repo": "acme/edge-proxy",
                    "local_path": str(root),
                    "deps": {"packages": [{"name": "next", "version": "14.0.1"}]},
                    "coderabbit": {
                        "action_items": [
                            {"cve": "CVE-2026-99991", "title": "Next.js RCE (CVE-2026-99991)", "priority_tier": "P1"}
                        ]
                    },
                }
            ]

            fake_kev = json.dumps({
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-88888",
                        "vendorProject": "F5",
                        "product": "NGINX",
                        "vulnerabilityName": "NGINX HTTP/3 Remote Code Execution",
                        "shortDescription": "Remote code execution in nginx worker",
                        "dateAdded": "2026-11-20",
                    },
                    {
                        "cveID": "CVE-2026-77777",
                        "vendorProject": "PHP Group",
                        "product": "PHP",
                        "vulnerabilityName": "PHP CGI Argument Injection",
                        "shortDescription": "RCE in PHP CGI",
                        "dateAdded": "2026-11-19",
                    },
                ]
            })
            fake_ghsa = json.dumps([
                {
                    "cve_id": "CVE-2026-99991",
                    "summary": "Next.js Image Optimization RCE",
                    "description": "Unauthenticated RCE in next.js",
                    "published_at": "2026-11-22T00:00:00Z",
                    "html_url": "https://github.com/advisories/GHSA-test-1",
                    "vulnerabilities": [{"package": {"name": "next"}}],
                }
            ])

            def fake_fetch(url: str) -> str:
                if "known_exploited_vulnerabilities" in url:
                    return fake_kev
                return fake_ghsa

            res = threat_feed.fetch_and_correlate_threat_feed(diagrams, force=True, fetcher=fake_fetch)
            self.assertTrue(res["ok"])
            self.assertEqual(res["scanned_repos"], 1)
            self.assertEqual(res["matched_count"], 2)
            self.assertEqual(res["unaffected_count"], 1)

            by_cve = {it["cve"]: it for it in res["items"]}
            self.assertEqual(by_cve["CVE-2026-99991"]["match_status"], "confirmed")
            self.assertEqual(by_cve["CVE-2026-88888"]["match_status"], "stack_match")
            self.assertIn("Dockerfile:1", by_cve["CVE-2026-88888"]["matched_repos"][0]["evidence"])
            self.assertEqual(by_cve["CVE-2026-77777"]["match_status"], "not_affected")

    def test_cisa_kev_falls_back_to_github_mirror_on_403(self) -> None:
        fake_kev = json.dumps({
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-55555",
                    "vendorProject": "F5",
                    "product": "NGINX",
                    "vulnerabilityName": "NGINX Mirror Fallback Test",
                    "shortDescription": "Test mirror fallback",
                    "dateAdded": "2026-11-20",
                }
            ]
        })

        def fake_fetch(url: str) -> str:
            if url == threat_feed.CISA_KEV_URL:
                raise RuntimeError("HTTP Error 403: Forbidden")
            if url == threat_feed.CISA_KEV_FALLBACK_URL:
                return fake_kev
            return "[]"

        res = threat_feed.fetch_and_correlate_threat_feed([], force=True, fetcher=fake_fetch)
        self.assertTrue(res["ok"])
        self.assertTrue(res["sources"]["cisa_kev"]["ok"])
        self.assertEqual(res["sources"]["cisa_kev"].get("mirror"), "github")
        self.assertEqual(res["sources"]["cisa_kev"]["count"], 1)
        self.assertEqual(res["items"][0]["cve"], "CVE-2026-55555")


if __name__ == "__main__":
    unittest.main()
