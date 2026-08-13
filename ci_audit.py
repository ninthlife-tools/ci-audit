#!/usr/bin/env python3
"""ci-audit: find supply-chain risks in GitHub Actions workflow files.

Zero dependencies. Line-oriented linter (NOT a YAML parser — honest
limitation): scans .github/workflows/*.yml|yaml or the files/dirs given.

Exit codes: 0 = no findings at/above the threshold, 1 = findings, 2 = usage error.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

RULES = {
    "unpinned-action": {
        "severity": "high",
        "message": "action referenced by tag/branch, not a commit SHA",
        "fix": "pin to the full 40-char commit SHA (keep the tag as a comment)",
    },
    "pull-request-target": {
        "severity": "high",
        "message": "pull_request_target runs fork code with repo secrets — dangerous with checkout of PR code",
        "fix": "prefer pull_request; if required, never check out the PR's code in the same job",
    },
    "missing-permissions": {
        "severity": "medium",
        "message": "no permissions: block — GITHUB_TOKEN gets broad defaults",
        "fix": "add an explicit least-privilege permissions: block",
    },
    "script-injection-risk": {
        "severity": "medium",
        "message": "github.event data interpolated directly into a run: block",
        "fix": "pass it through an env: var and quote it instead of inline ${{ }}",
    },
    "curl-bash": {
        "severity": "medium",
        "message": "piping a remote script straight into a shell",
        "fix": "download, verify the checksum, then execute",
    },
    "secret-in-env": {
        "severity": "low",
        "message": "env value looks like a hardcoded secret",
        "fix": "move it to GitHub secrets and reference via ${{ secrets.* }}",
    },
}

USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^(\s*)-?\s*run:\s*[|>]?")
EVENT_INJECT_RE = re.compile(r"\$\{\{\s*github\.event\.([\w.\[\]]+)")
# numeric event fields are not attacker-controlled text (e.g. pull_request.number)
NUMERIC_EVENT_FIELDS = (".number", ".id", ".run_id", ".run_attempt", ".run_number")
CURL_BASH_RE = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b")
SECRET_ENV_RE = re.compile(
    r"(?i)^\s*(?:[A-Z0-9_]*(?:key|secret|token|password)[A-Z0-9_]*)\s*:\s*[\"'][^\"'\s]{12,}[\"']\s*$"
)


def is_workflow_file(path: Path) -> bool:
    return path.suffix in (".yml", ".yaml") and path.is_file()


def iter_workflow_files(target: Path):
    if target.is_file() and is_workflow_file(target):
        yield target
    elif target.is_dir():
        workflows = target / ".github" / "workflows"
        if workflows.is_dir():
            yield from sorted(p for p in workflows.rglob("*") if is_workflow_file(p))
        elif not (target / ".git").exists() and not (target / ".github").exists():
            # plain directory of workflow files; a repo root without
            # .github/workflows has no workflows — don't scan every YAML in it
            yield from sorted(p for p in target.rglob("*") if is_workflow_file(p))


def check_uses_line(line: str) -> bool:
    match = USES_RE.match(line)
    if not match:
        return False
    ref = match.group(1).strip("'\"")
    if ref.startswith("./") or ref.startswith("docker://"):
        return False
    if "@" not in ref:
        return True
    return not SHA_RE.match(ref.rsplit("@", 1)[1])


def scan_workflow(path: Path) -> list:
    findings = []
    lines = path.read_text(errors="ignore").splitlines()
    has_permissions = any(re.match(r"^\s*permissions\s*:", line) for line in lines)
    in_run_block = False
    run_indent = 0

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        run_match = RUN_RE.match(line)
        if run_match:
            in_run_block = True
            run_indent = len(run_match.group(1))
        elif in_run_block and stripped and not line.startswith(" " * (run_indent + 1)):
            in_run_block = False

        if check_uses_line(line):
            findings.append(make_finding(path, lineno, "unpinned-action"))
        if re.match(r"^\s*pull_request_target\s*:", line):
            findings.append(make_finding(path, lineno, "pull-request-target"))
        if in_run_block:
            for event_match in EVENT_INJECT_RE.finditer(line):
                if not event_match.group(1).endswith(NUMERIC_EVENT_FIELDS):
                    findings.append(make_finding(path, lineno, "script-injection-risk"))
                    break
        if CURL_BASH_RE.search(line):
            findings.append(make_finding(path, lineno, "curl-bash"))
        if SECRET_ENV_RE.match(line) and "${{" not in line:
            findings.append(make_finding(path, lineno, "secret-in-env"))

    if not has_permissions:
        findings.append({
            "file": str(path), "line": 1, "rule": "missing-permissions",
            "severity": RULES["missing-permissions"]["severity"],
            "message": RULES["missing-permissions"]["message"],
            "fix": RULES["missing-permissions"]["fix"],
        })
    return findings


def make_finding(path: Path, lineno: int, rule_id: str) -> dict:
    rule = RULES[rule_id]
    return {
        "file": str(path), "line": lineno, "rule": rule_id,
        "severity": rule["severity"], "message": rule["message"], "fix": rule["fix"],
    }


def meets_threshold(finding: dict, threshold: str) -> bool:
    return SEVERITY_ORDER[finding["severity"]] >= SEVERITY_ORDER[threshold]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", default=["."], help="workflow files, repos, or dirs (default: current dir)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--severity-threshold", default="high", choices=list(SEVERITY_ORDER),
                        help="minimum severity that triggers exit 1 (default: high)")
    args = parser.parse_args(argv)

    files = []
    for raw in args.paths:
        target = Path(raw)
        if not target.exists():
            print(f"error: no such path: {target}", file=sys.stderr)
            return 2
        files.extend(iter_workflow_files(target))

    findings = []
    for path in files:
        findings.extend(scan_workflow(path))

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"{f['file']}:{f['line']}: [{f['rule']}] ({f['severity']}) {f['message']} — fix: {f['fix']}")
        print(f"---\n{len(findings)} finding(s) across {len(files)} workflow file(s)")
    return 1 if any(meets_threshold(f, args.severity_threshold) for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
