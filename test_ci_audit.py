import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import ci_audit

CLEAN_WORKFLOW = """
name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      - run: python3 -m unittest
"""

BAD_WORKFLOW = """
name: legacy
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
      - run: curl https://example.com/setup.sh | bash
      - uses: docker://alpine:3.20
      - uses: ./local/action
"""

SECRET_WORKFLOW = """
name: deploy
on: [push]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_SECRET_KEY: "abcd1234efgh5678"
    steps:
      - run: echo deploying
"""


class CiAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_workflow(self, content: str, name: str = "ci.yml") -> Path:
        path = self.root / ".github" / "workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def scan(self, content: str):
        path = self.write_workflow(content)
        return ci_audit.scan_workflow(path)

    def run_sarif(self, content: str = BAD_WORKFLOW) -> dict:
        self.write_workflow(content)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ci_audit.main([str(self.root), "--format", "sarif"])
        return json.loads(out.getvalue())

    def test_clean_workflow_has_no_findings(self):
        self.assertEqual(self.scan(CLEAN_WORKFLOW), [])

    def test_unpinned_action_flagged_but_sha_and_local_and_docker_pass(self):
        findings = self.scan(BAD_WORKFLOW)
        unpinned = [f for f in findings if f["rule"] == "unpinned-action"]
        self.assertEqual(len(unpinned), 1)
        self.assertEqual(unpinned[0]["line"], 9)

    def test_pull_request_target_flagged(self):
        rules = {f["rule"] for f in self.scan(BAD_WORKFLOW)}
        self.assertIn("pull-request-target", rules)

    def test_script_injection_flagged_in_run_block(self):
        rules = {f["rule"] for f in self.scan(BAD_WORKFLOW)}
        self.assertIn("script-injection-risk", rules)

    def test_curl_bash_flagged(self):
        rules = {f["rule"] for f in self.scan(BAD_WORKFLOW)}
        self.assertIn("curl-bash", rules)

    def test_missing_permissions_flagged_only_when_absent(self):
        self.assertIn("missing-permissions", {f["rule"] for f in self.scan(BAD_WORKFLOW)})
        self.assertNotIn("missing-permissions", {f["rule"] for f in self.scan(CLEAN_WORKFLOW)})

    def test_secret_in_env_flagged(self):
        rules = {f["rule"] for f in self.scan(SECRET_WORKFLOW)}
        self.assertIn("secret-in-env", rules)

    def test_expression_env_value_not_flagged(self):
        workflow = SECRET_WORKFLOW.replace('"abcd1234efgh5678"', '"${{ secrets.API_KEY }}"')
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertNotIn("secret-in-env", rules)

    def test_main_exit_codes(self):
        self.write_workflow(BAD_WORKFLOW)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci_audit.main([str(self.root)]), 1)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci_audit.main([str(self.root), "--severity-threshold", "low"]), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ci_audit.main([str(self.root / "nope")]), 2)

    def test_clean_repo_exits_zero(self):
        self.write_workflow(CLEAN_WORKFLOW)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci_audit.main([str(self.root)]), 0)

    def test_json_output_parses(self):
        self.write_workflow(BAD_WORKFLOW)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ci_audit.main([str(self.root), "--json"])
        parsed = json.loads(out.getvalue())
        self.assertTrue(any(f["rule"] == "unpinned-action" for f in parsed))

    def test_sarif_output_parses(self):
        parsed = self.run_sarif()
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(len(parsed["runs"]), 1)

    def test_sarif_required_keys_present(self):
        run = self.run_sarif()["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ci-audit")
        self.assertTrue(run["results"])
        for result in run["results"]:
            self.assertIn(result["ruleId"], ci_audit.RULES)
            self.assertIn(result["level"], ("error", "warning", "note"))
            self.assertTrue(result["message"]["text"])
            location = result["locations"][0]["physicalLocation"]
            self.assertTrue(location["artifactLocation"]["uri"].endswith(".github/workflows/ci.yml"))
            self.assertIsInstance(location["region"]["startLine"], int)

    def test_sarif_rules_array_covers_all_rules(self):
        rules = self.run_sarif()["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual({r["id"] for r in rules}, set(ci_audit.RULES))
        levels = {r["id"]: r["defaultConfiguration"]["level"] for r in rules}
        self.assertEqual(levels["unpinned-action"], "error")
        self.assertEqual(levels["missing-permissions"], "warning")
        self.assertEqual(levels["secret-in-env"], "note")

    def test_sarif_zero_findings_still_valid(self):
        parsed = self.run_sarif(CLEAN_WORKFLOW)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(parsed["runs"][0]["results"], [])

    def test_text_format_unchanged_by_default(self):
        self.write_workflow(BAD_WORKFLOW)
        default_out = io.StringIO()
        with contextlib.redirect_stdout(default_out):
            ci_audit.main([str(self.root)])
        explicit_out = io.StringIO()
        with contextlib.redirect_stdout(explicit_out):
            ci_audit.main([str(self.root), "--format", "text"])
        self.assertEqual(default_out.getvalue(), explicit_out.getvalue())
        self.assertIn("finding(s) across", default_out.getvalue())

    def test_sarif_output_is_valid_and_complete(self):
        self.write_workflow(BAD_WORKFLOW)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ci_audit.main([str(self.root), "--format", "sarif"])
        sarif = json.loads(out.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ci-audit")
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, set(ci_audit.RULES))
        self.assertTrue(any(r["ruleId"] == "unpinned-action" for r in run["results"]))
        self.assertEqual(run["results"][0]["level"], "error")
        region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertIn("startLine", region)

    def test_sarif_zero_findings_is_valid(self):
        self.write_workflow(CLEAN_WORKFLOW)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ci_audit.main([str(self.root), "--format", "sarif"])
        sarif = json.loads(out.getvalue())
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_text_format_unchanged(self):
        self.write_workflow(BAD_WORKFLOW)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ci_audit.main([str(self.root)])
        self.assertIn("[unpinned-action]", out.getvalue())

    def test_event_interpolation_outside_run_block_not_flagged(self):
        workflow = CLEAN_WORKFLOW.replace(
            "run: python3 -m unittest",
            "run: python3 -m unittest\n      # ${{ github.event.issue.title }} in a comment is still text",
        )
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertNotIn("script-injection-risk", rules)

    def test_quoted_local_action_not_flagged(self):
        workflow = CLEAN_WORKFLOW.replace(
            "- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8",
            "- uses: './.github/actions/local'",
        )
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertNotIn("unpinned-action", rules)

    def test_quoted_unpinned_action_still_flagged(self):
        workflow = CLEAN_WORKFLOW.replace(
            "- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8",
            "- uses: 'actions/checkout@v4'",
        )
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertIn("unpinned-action", rules)

    def test_numeric_event_field_not_flagged(self):
        workflow = CLEAN_WORKFLOW.replace(
            "run: python3 -m unittest",
            'run: echo "${{ github.event.pull_request.number }}" >> pr-info.txt',
        )
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertNotIn("script-injection-risk", rules)

    def test_repo_root_without_workflows_scans_nothing(self):
        (self.root / ".git").mkdir()
        (self.root / "config").mkdir()
        (self.root / "config" / "deploy.yaml").write_text("key: value\n")
        self.assertEqual(list(ci_audit.iter_workflow_files(self.root)), [])

    def test_plain_dir_of_yamls_still_scanned(self):
        (self.root / "ci.yml").write_text(CLEAN_WORKFLOW)
        self.assertEqual(len(list(ci_audit.iter_workflow_files(self.root))), 1)


if __name__ == "__main__":
    unittest.main()
