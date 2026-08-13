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
python3 ci_audit.py --severity-threshold medium   # exit 1 on medium+ too
```

Exit codes: `0` clean at the threshold, `1` findings, `2` bad usage.

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

## Tests

```bash
python3 -m unittest -v
```

## Roadmap

- GitHub Action packaging (`action.yml`, Marketplace) — requires a publisher
  agreement, i.e. a human step
- SARIF output for code-scanning dashboards
- Autofix suggestions

## Business context

Free distribution product by [Ninthlife](https://ninthlife-tools.surge.sh)
(experiment `ci-audit-launch`). A paid weekly multi-repo audit email is
planned; the CLI stays free and MIT-licensed.
