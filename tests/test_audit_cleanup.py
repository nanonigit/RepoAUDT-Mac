"""Unit tests for audit cleanup: honest scores, no fake PostgreSQL schema, state GC, and priority_tier guarantee."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import portal_builder  # noqa: E402


class TestAuditCleanup(unittest.TestCase):
    def test_p0_secret_repo_has_low_honest_score_and_no_fake_90_92_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.production").write_text("AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDF12\n", encoding="utf-8")
            (root / "app.ts").write_text("export const x = 1;\n", encoding="utf-8")

            deps = {
                "security_advisories": [],
                "sast_findings": [
                    {
                        "severity": "critical",
                        "priority_tier": "P0",
                        "category": "secrets",
                        "title": "🚨 [シークレット設定ファイル漏洩] `.env.production` がリポジトリにコミットされています",
                        "file": ".env.production:1 (Target: app)",
                        "target_node": "app",
                        "desc": "Secret file committed",
                    }
                ],
            }
            cr = analyzer.run_coderabbit_static_audit(root, "acme/secret-repo", [{"name": "app", "files": ["app.ts"]}], deps)
            self.assertLess(cr["score"], 72)
            self.assertLess(cr["stats"]["Security"], 75)
            self.assertIsNone(cr["stats"]["Maintainability"])
            self.assertIsNone(cr["stats"]["Performance"])

    def test_portal_builder_has_no_fake_postgresql_16_3_schema_fallback(self) -> None:
        html_path = Path(__file__).resolve().parents[1] / "Resources" / "webui" / "index.html"
        portal_builder.build_portal_html([], is_shareable=False)
        html_text = html_path.read_text(encoding="utf-8")
        self.assertNotIn("Business data model stored in PostgreSQL 16.3 / AWS RDS Multi-AZ.", html_text)
        self.assertNotIn("PostgreSQL 16.3 / AWS RDS Multi-AZ 上に格納される業務データモデルです。", html_text)
        self.assertIn("このテーブルのスキーマ定義は静的解析で検出されませんでした（未抽出）", html_text)

    def test_delete_diagram_gcs_orphaned_tech_specs_table_schemas_and_org_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "analyzed_repos.json"
            state_file.write_text(
                json.dumps(
                    {
                        "diagrams": [
                            {
                                "id": "gh-org-nanonigit-ecosystem",
                                "repo": "nanonigit (全体エコシステム)",
                                "is_root": True,
                            },
                            {
                                "id": "gh-nanonigit-demo-overall",
                                "repo": "nanonigit/demo",
                                "github_url": "https://github.com/nanonigit/demo",
                                "diagram": 'flowchart LR\n  Mod_src_api["api<br/>src/api/"]',
                                "tech_spec_keys": ["demo_api"],
                                "table_schema_keys": ["demo_users"],
                            },
                        ],
                        "techSpecs": {
                            "demo_api": {"title": "API"},
                            "stale_deleted_repo_mod": {"title": "Stale"},
                        },
                        "tableSchemas": {
                            "demo_users": {"name": "demo_users"},
                            "stale_deleted_table": {"name": "stale_deleted_table"},
                        },
                        "deleted_ids": [],
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.object(analyzer, "STATE_FILE", state_file):
                state = analyzer.delete_saved_diagram(diagram_id="gh-nanonigit-demo-overall")
                self.assertEqual(state["diagrams"], [])
                self.assertEqual(state["techSpecs"], {})
                self.assertEqual(state["tableSchemas"], {})

    def test_load_saved_analyses_guarantees_priority_tier_on_all_action_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "analyzed_repos.json"
            state_file.write_text(
                json.dumps(
                    {
                        "diagrams": [
                            {
                                "id": "gh-acme-job-portal-overall",
                                "repo": "acme/Job-Portal",
                                "coderabbit": {
                                    "action_items": [
                                        {"title": "Item without tier 1", "severity": "medium", "file": "a.ts:1"},
                                        {"title": "🚨 [シークレット漏洩検知] AWS Key", "severity": "critical", "file": ".env:1"},
                                    ]
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(analyzer, "STATE_FILE", state_file):
                loaded = analyzer.load_saved_analyses()
                items = loaded["diagrams"][0]["coderabbit"]["action_items"]
                self.assertEqual(len(items), 2)
                for it in items:
                    self.assertIn(it["priority_tier"], ("P0", "P1", "P2", "P3"))
                    self.assertTrue(bool(it.get("priority_reason")))
                self.assertEqual(items[1]["priority_tier"], "P0")


if __name__ == "__main__":
    unittest.main()
