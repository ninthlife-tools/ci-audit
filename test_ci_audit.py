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

    def test_event_interpolation_outside_run_block_not_flagged(self):
        workflow = CLEAN_WORKFLOW.replace(
            "run: python3 -m unittest",
            "run: python3 -m unittest\n      # ${{ github.event.issue.title }} in a comment is still text",
        )
        rules = {f["rule"] for f in self.scan(workflow)}
        self.assertNotIn("script-injection-risk", rules)


if __name__ == "__main__":
    unittest.main()
