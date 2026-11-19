import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Resources/backend"))
import security_audit_engine as engine
import workflow_audit

WORKFLOW = """name: CI
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo fixture
"""
CLEAN = WORKFLOW.replace("permissions: write-all", "permissions: {}").replace(
    "      - uses: actions/checkout@v4\n", ""
)


class WorkflowAuditTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.repo = Path(directory)
        self.workflows = self.repo / workflow_audit.WORKFLOWS
        self.workflows.mkdir(parents=True)
        self.file = self.workflows / "ci.yml"

    def test_no_workflows_and_symlinks_are_skipped(self):
        outside = self.repo / "external.yml"
        outside.write_text(WORKFLOW)
        self.file.symlink_to(outside)
        files = workflow_audit.workflow_files(self.repo)
        self.assertEqual(files, [])
        self.assertEqual(workflow_audit.run_zizmor(files, str), ([], "no_workflows"))

    def test_builtin_still_runs_without_zizmor(self):
        self.file.write_text(WORKFLOW)
        with patch.object(workflow_audit, "ZIZMOR_PATHS", ()):
            result = engine.scan_php_and_nodejs_and_polyglot_vulnerabilities(
                self.repo, []
            )
        self.assertEqual(
            result["workflow_scan"], {"scanner": "builtin", "status": "not_installed"}
        )
        self.assertEqual(
            [f["rule_id"] for f in result["sast_findings"]], ["excessive-permissions"]
        )

    def test_parser_rejects_outside_paths_and_hides_raw_values(self):
        uri = ".github/workflows/ci.yml"
        location = {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}
        entry = {
            "ruleId": "zizmor/unpinned-uses",
            "level": "error",
            "message": {"text": "private fixture value"},
            "locations": [{"physicalLocation": location}],
        }
        report = {"version": "2.1.0", "runs": [{"results": [entry, entry]}]}
        result = workflow_audit.parse_sarif(json.dumps(report), {uri: 3}, str)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "high")
        self.assertNotIn("private fixture value", json.dumps(result))
        location["artifactLocation"]["uri"] = "../external.yml"
        with self.assertRaises(ValueError):
            workflow_audit.parse_sarif(json.dumps(report), {uri: 3}, str)

    @unittest.skipUnless(
        shutil.which("zizmor"), "Install zizmor for the real-tool integration check"
    )
    def test_real_zizmor_reports_and_handles_clean_and_invalid_files(self):
        self.file.write_text(WORKFLOW)
        result = engine.scan_php_and_nodejs_and_polyglot_vulnerabilities(self.repo, [])
        self.assertEqual(
            result["workflow_scan"], {"scanner": "builtin+zizmor", "status": "complete"}
        )
        rules = {item["rule_id"] for item in result["sast_findings"]}
        self.assertTrue(
            {"artipacked", "unpinned-uses", "excessive-permissions"} <= rules
        )
        self.file.write_text(CLEAN)
        self.assertEqual(workflow_audit.run_zizmor([self.file], str), ([], "complete"))
        self.file.write_text("jobs: {\n")
        self.assertEqual(
            workflow_audit.run_zizmor([self.file], str), (None, "tool_error")
        )
