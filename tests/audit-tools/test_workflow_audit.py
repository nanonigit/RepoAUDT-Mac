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
        with (
            patch.object(workflow_audit, "ZIZMOR_PATHS", ()),
            patch.object(workflow_audit, "ACTIONLINT_PATHS", ()),
        ):
            result = engine.scan_php_and_nodejs_and_polyglot_vulnerabilities(
                self.repo, []
            )
        self.assertEqual(
            result["workflow_scan"],
            {"scanner": "builtin", "status": "not_installed", "actionlint_status": "not_installed"},
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
        with patch.object(workflow_audit, "ACTIONLINT_PATHS", ()):
            result = engine.scan_php_and_nodejs_and_polyglot_vulnerabilities(self.repo, [])
        self.assertEqual(
            result["workflow_scan"],
            {"scanner": "builtin+zizmor", "status": "complete", "actionlint_status": "not_installed"},
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

    def test_template_injection_detects_run_and_generates_valid_yaml_diff(self):
        self.file.write_text(
            "name: PR Check\n"
            "on: pull_request\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n',
            encoding="utf-8",
        )
        findings = engine.scan_github_actions_workflows(self.repo, lambda _: "CI")
        inj = [f for f in findings if f["rule_id"] == "template-injection"]
        self.assertEqual(len(inj), 1)
        diff = inj[0]["diff"]
        self.assertNotIn("UNTRUSTED_INPUT", diff)
        self.assertIn("PR_TITLE: ${{ github.event.pull_request.title }}", diff)
        self.assertIn('run: echo "$PR_TITLE"', diff)

    def test_template_injection_excludes_safe_env_with_and_concurrency_contexts(self):
        self.file.write_text(
            "name: ${{ github.event.pull_request.title }}\n"
            "on: pull_request\n"
            "concurrency:\n"
            "  group: ci-${{ github.event.pull_request.number }}-${{ github.event.pull_request.head.ref }}\n"
            "jobs:\n"
            "  notify:\n"
            "    if: github.event.pull_request.title != ''\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          fetch-depth: 0\n"
            "          ref: ${{ github.event.pull_request.head.ref }}\n"
            "      - name: Post to Slack and capture thread_ts\n"
            "        uses: actions/github-script@v7\n"
            "        env:\n"
            "          PR_BODY: ${{ github.event.pull_request.body }}\n"
            "        with:\n"
            "          script: |\n"
            "            const prBody = process.env.PR_BODY || '';\n",
            encoding="utf-8",
        )
        findings = engine.scan_github_actions_workflows(self.repo, lambda _: "CI")
        inj = [f for f in findings if f["rule_id"] == "template-injection"]
        self.assertEqual(inj, [])

    def test_template_injection_detects_github_script_without_broken_run_diff(self):
        self.file.write_text(
            "name: Script\n"
            "on: pull_request\n"
            "jobs:\n"
            "  comment:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            '            const title = "${{ github.event.pull_request.title }}";\n',
            encoding="utf-8",
        )
        findings = engine.scan_github_actions_workflows(self.repo, lambda _: "CI")
        inj = [f for f in findings if f["rule_id"] == "template-injection"]
        self.assertEqual(len(inj), 1)
        self.assertNotIn("diff", inj[0])
        self.assertIn("process.env.PR_TITLE", inj[0]["remediation"])

    def test_template_injection_pwsh_multiline_run_diff(self):
        self.file.write_text(
            "name: Windows\n"
            "on: pull_request\n"
            "jobs:\n"
            "  win:\n"
            "    runs-on: windows-latest\n"
            "    steps:\n"
            "      - name: Print title\n"
            "        shell: pwsh\n"
            "        run: |\n"
            '          Write-Host "${{ github.event.pull_request.title }}"\n',
            encoding="utf-8",
        )
        findings = engine.scan_github_actions_workflows(self.repo, lambda _: "CI")
        inj = [f for f in findings if f["rule_id"] == "template-injection"]
        self.assertEqual(len(inj), 1)
        self.assertIn("$env:PR_TITLE", inj[0]["diff"])
        self.assertIn("PR_TITLE: ${{ github.event.pull_request.title }}", inj[0]["diff"])

    def test_parse_actionlint_normalizes_findings_and_ignores_outside_paths(self):
        uri = ".github/workflows/ci.yml"
        raw = json.dumps([
            {
                "filepath": uri,
                "line": 2,
                "column": 5,
                "kind": "shellcheck",
                "message": "SC2086: Double quote to prevent globbing",
            },
            {
                "filepath": "../outside.yml",
                "line": 1,
                "column": 1,
                "kind": "syntax-check",
                "message": "outside",
            },
        ]).encode("utf-8")
        findings = workflow_audit.parse_actionlint(raw, {uri: 10}, lambda _: "CI")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["scanner"], "actionlint")
        self.assertEqual(findings[0]["rule_id"], "actionlint-shellcheck")
        self.assertEqual(findings[0]["severity"], "medium")
