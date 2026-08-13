# ci-audit

Find supply-chain risks in GitHub Actions workflows before they find you.

Zero dependencies, Python 3.8+ stdlib only. A line-oriented linter for
`.github/workflows/*.yml` — built in the wake of the 2025–2026 Actions
supply-chain incident wave, where the same handful of patterns kept showing
up: unpinned actions, `pull_request_target` on fork code, event data
interpolated into shell commands.

## Usage

```bash
python3 ci_audit.py                  # scan ./.github/workflows (or any yml in cwd)
python3 ci_audit.py ~/code/myrepo    # scan another repo
python3 ci_audit.py --json           # machine-readable output
python3 ci_audit.py --format sarif   # SARIF 2.1.0 for code-scanning dashboards
python3 ci_audit.py --severity-threshold medium   # exit 1 on medium+ too
```

Exit codes: `0` clean at the threshold, `1` findings, `2` bad usage.

## SARIF output

`--format sarif` emits SARIF 2.1.0 — one run, full rule metadata, and one
result per finding — for GitHub code scanning and other SARIF viewers:

```bash
python3 ci_audit.py --format sarif > results.sarif
# then: github/codeql-action/upload-sarif with sarif_file: results.sarif
```

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "ci-audit", "rules": [...]}},
      "results": [
        {
          "ruleId": "unpinned-action",
          "level": "error",
          "message": {"text": "action referenced by tag/branch, not a commit SHA — fix: ..."},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ".github/workflows/ci.yml"},
            "region": {"startLine": 9}
          }}]
        }
      ]
    }
  ]
}
```

Severity mapping: high → `error`, medium → `warning`, low → `note`.
URIs are repo-relative when ci-audit runs from the repo root.

## Rules

| Rule | Severity | What it catches | Fix |
| --- | --- | --- | --- |
| `unpinned-action` | high | `uses:` by tag/branch instead of a 40-char commit SHA | pin to the SHA |
| `pull-request-target` | high | fork code running with repo secrets | use `pull_request`; never check out PR code in the same job |
| `missing-permissions` | medium | no `permissions:` block (broad token defaults) | add least-privilege `permissions:` |
| `script-injection-risk` | medium | `${{ github.event.* }}` inside a `run:` block | pass via `env:` and quote |
| `curl-bash` | medium | `curl ... \| bash` in a run block | download, verify checksum, then run |
| `secret-in-env` | low | hardcoded secret-looking `env:` values | use GitHub secrets |

## Honest limitations

- Line-oriented, not a YAML parser. It catches the dangerous patterns; it
  does not understand workflow semantics.
- Heuristic: false positives are possible (e.g. a `pull_request_target`
  workflow that never checks out PR code is fine). Each finding prints its
  fix so triage is fast.
- Not a substitute for GitHub's native controls — it complements them.

## Use it as a GitHub Action

```yaml
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v4, SHA-pinned
- uses: ninthlife-tools/ci-audit@master
  with:
    severity-threshold: high
```

No Marketplace listing needed — actions run straight from repos. (A
Marketplace listing needs a publisher agreement, a human step on our side.)

## Tests

```bash
python3 -m unittest -v
```

## Roadmap

- GitHub Action packaging (`action.yml`, Marketplace) — requires a publisher
  agreement, i.e. a human step
- ~~SARIF output for code-scanning dashboards~~ (shipped: `--format sarif`)
- Autofix suggestions

## Business context

Free distribution product by [Ninthlife](https://ninthlife-tools.surge.sh)
(experiment `ci-audit-launch`). A paid weekly multi-repo audit email is
planned; the CLI stays free and MIT-licensed.
