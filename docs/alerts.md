# Advisory watch: hear about new problems in your stack

An audit is a snapshot. New vulnerabilities and end-of-life dates appear the week after. The advisory watch checks your **exact versions** against published feeds and tells you only what applies to you.

It never asks a model what is vulnerable. Facts come from three feeds:

| Feed | Tells you |
|---|---|
| [OSV.dev](https://osv.dev) | Known vulnerabilities for an exact package version (npm, PyPI, Packagist and more) |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Flaws confirmed as exploited in the wild: the "act now" list |
| [endoflife.date](https://endoflife.date) | Runtimes and frameworks that no longer get security fixes (PHP, Node.js, Python, Django, Laravel, Symfony) |

It reads your lockfiles, `==` pins, Dockerfiles and version files to know what you run. It sends **package names, versions and ecosystem names to osv.dev, never code or file paths.**

## Three ways to use it

**1. Ask, any time.** In Claude Code: `/ai-consultant:consult-alerts`. It runs the check and explains the result in plain language: what is exploited, what to upgrade first, and what could not be checked.

**2. A reminder in your terminal.** Opt in per project and a hook checks at the start of each Claude Code session (at most once a day):

```
/ai-consultant:consult-alerts --watch
```

It stays silent unless something new applies, never blocks or fails a session, and does nothing at all until the project opts in by creating `.consultant/alerts.json` containing `{"enabled": true}`.

**3. An email to the team.** Copy [`templates/advisory-watch.yml`](../templates/advisory-watch.yml) to `.github/workflows/`. Once a day it keeps **one** GitHub issue up to date and adds a comment only when something *new* applies. GitHub emails everyone who watches the repository (Watch, Custom, Issues) when an issue or comment is created, so this needs no mail account and no secret. Sending to people who are not on GitHub would need a mail provider and a secret, which this does not do.

## What it will and won't say

- **A "possibly affected" is not an "affected".** CISA's list says a flaw in PHP, say, is being exploited, but not which versions. The watch shows it as *possibly affected, confirm your version* and links the advisory.
- **Unpinned packages are not guessed.** A dependency without a lockfile entry or `==` pin has no exact version, so it is counted and reported as *not checked* instead of being matched to a range.
- **A feed that is down is never an all-clear.** The result says which feed could not be reached and that it is incomplete.
- **It cannot tell you that you are safe.** It reports *published* advisories for the versions it could read.
- **Upgrade advice never points backwards.** OSV lists one fix per release branch; the watch picks the nearest fixed version above yours, prefers your major version, and labels a major-version jump.

## When the news says "everyone must patch"

Breaking news, including breathless news, is not a source. If a story names a vulnerability that this does not list, that means the feeds above do not carry it **yet**: the exploited list in particular can lag a new event by days. Do this: find the project's own announcement (for PHP, php.net), compare the affected versions with yours (`php -v`, your Dockerfile tag), patch if they match, and run the check again later. The tool will not repeat a claim it cannot trace to a feed, and neither should you.

## Verification status

The three feeds have been queried live from GitHub Actions (the `feeds-smoke` workflow runs weekly, so a changed API shows up as a red run). The session-start hook has been run in a real headless Claude Code session. The GitHub issue and email path is covered by unit tests against a fake GitHub API and has **not** yet run against a real repository. See the [CHANGELOG](../CHANGELOG.md).
