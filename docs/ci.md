# Keep it honest in CI (GitHub Action)

An audit is a snapshot. The PR guard keeps the snapshot from silently rotting. Commit `.consultant/` after your audit, then copy [`templates/pr-guard.yml`](../templates/pr-guard.yml) to `.github/workflows/`:

```yaml
on: pull_request
permissions: { contents: read, pull-requests: write }
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: adibM04/AI-Consultant@80ab978c2e5897de6b3ae248d4f5b14a4ecf8436  # v0.2.0
```

It uses **no model and no secrets**, runs safely on forked PRs, and compares the pull request to the last audit on the **base branch** (a PR cannot approve itself by editing `.consultant/`). It flags:

| Severity | Catches |
|---|---|
| high | a new dependency that does not exist on the registry or imitates a popular one; `.env`, keys or service-account files added; code cited as evidence for a passing control was **deleted** |
| medium | cited lines were changed or moved (re-audit those controls); the audit record, waivers or findings were edited; waivers the renderer would reject |
| low | waivers about to expire; the audit is far behind; no baseline audit yet |

It is a tripwire, not a review. It has run on real GitHub Actions, including a real pull request where it posted and then updated a single comment. A pull request from a fork has not been tried yet.

## Weekly full audit

[`templates/weekly-audit.yml`](../templates/weekly-audit.yml) runs the real consultant on a schedule. It needs an Anthropic API key stored as a repository secret and costs money. Use a dedicated key with a low spend limit, run it only on a schedule or by hand, and never trigger it from pull requests. Try it first with a manual run limited to one or two domains and a small budget.

Only the first half of this workflow has been verified on a real runner. See the [CHANGELOG](../CHANGELOG.md) for exactly what has and has not run.
