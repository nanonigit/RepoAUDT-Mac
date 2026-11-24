"""Regression tests for real static dependency graph and grounded sequence diagram generation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "Resources" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import arch_analyzer  # noqa: E402


class TestArchDependencyGraphs(unittest.TestCase):
    def test_ts_js_real_dependency_graph_without_linear_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for d in ("src/config", "src/configs", "src/features", "src/external-services", "src/db"):
                (root / d).mkdir(parents=True, exist_ok=True)
            (root / "src/config/env.ts").write_text("export const PORT = 3000;\n", encoding="utf-8")
            (root / "src/configs/app.ts").write_text("export const APP_NAME = 'demo';\n", encoding="utf-8")
            (root / "src/external-services/openai.ts").write_text("import OpenAI from 'openai';\nexport const ai = new OpenAI();\n", encoding="utf-8")
            (root / "src/db/client.ts").write_text("import { Pool } from 'pg';\nexport const pool = new Pool();\n", encoding="utf-8")
            (root / "src/features/chat.ts").write_text(
                "import { ai } from '../external-services/openai';\n"
                "import { pool } from '../db/client';\n"
                "export async function runChat() { return { ai, pool }; }\n",
                encoding="utf-8",
            )

            arch = arch_analyzer.analyze_repo_architecture(root, "maice-backend")
            flowchart = analyzer.build_mermaid_flowchart(arch["components"], edges=arch["edges"])

            self.assertIn("Mod_src_features", flowchart)
            self.assertIn("Mod_src_external_services", flowchart)
            self.assertIn("Mod_src_db", flowchart)
            self.assertRegex(flowchart, r"Mod_src_features\s*-->\|[^|]+\|\s*Mod_src_external_services")
            self.assertRegex(flowchart, r"Mod_src_features\s*-->\|[^|]+\|\s*Mod_src_db")
            self.assertNotRegex(flowchart, r"Mod_src_config\s*-->.*Mod_src_configs")

    def test_terraform_repo_excludes_docs_and_load_tests_and_has_no_ui_render_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for d in ("docs", "load-tests", "modules/vpc", "modules/alb", "modules/ecs"):
                (root / d).mkdir(parents=True, exist_ok=True)
            (root / "docs/README.md").write_text("# Docs\n", encoding="utf-8")
            (root / "load-tests/k6.js").write_text("export default function() {}\n", encoding="utf-8")
            (root / "modules/vpc/main.tf").write_text('resource "aws_vpc" "main" {}\n', encoding="utf-8")
            (root / "modules/alb/main.tf").write_text('resource "aws_lb" "main" {}\n', encoding="utf-8")
            (root / "modules/ecs/main.tf").write_text('resource "aws_ecs_service" "app" {}\n', encoding="utf-8")
            (root / "main.tf").write_text(
                'module "vpc" {\n  source = "./modules/vpc"\n}\n'
                'module "alb" {\n  source = "./modules/alb"\n  vpc_id = module.vpc.vpc_id\n}\n'
                'module "ecs" {\n  source = "./modules/ecs"\n  alb_tg = module.alb.tg_arn\n}\n',
                encoding="utf-8",
            )

            arch = arch_analyzer.analyze_repo_architecture(root, "maice-infra")
            comp_names = [c["name"] for c in arch["components"]]
            comp_ids = [c["id"] for c in arch["components"]]
            self.assertNotIn("ClientEntry", comp_ids)
            self.assertFalse(any("docs" in n.lower() for n in comp_names))
            self.assertFalse(any("load-tests" in n.lower() for n in comp_names))

            flowchart = analyzer.build_mermaid_flowchart(arch["components"], edges=arch["edges"])
            self.assertIn("TfMod_vpc", flowchart)
            self.assertIn("TfMod_alb", flowchart)
            self.assertIn("TfMod_ecs", flowchart)

            sequences = arch["sequences"]
            self.assertTrue(len(sequences) >= 1)
            combined_seq = "\n".join(s["diagram"] for s in sequences)
            self.assertNotIn("UIレンダリング完了", combined_seq)
            self.assertNotIn("非同期バックグラウンドジョブ開始", combined_seq)

    def test_minimal_repo_does_not_fabricate_sequence_diagrams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/util.ts").write_text("export const add = (a: number, b: number) => a + b;\n", encoding="utf-8")

            arch = arch_analyzer.analyze_repo_architecture(root, "tiny-lib")
            self.assertEqual(arch["sequences"], [])
            seq_from_analyzer = analyzer.build_mermaid_sequences("tiny-lib", arch["components"], repo_dir=root)
            self.assertEqual(seq_from_analyzer, [])


if __name__ == "__main__":
    unittest.main()
