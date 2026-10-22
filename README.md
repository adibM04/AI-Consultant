# AI-Consultant

**An open-source IT consultant for founders. Install it in your repo and it tells you what stands between your weekend prototype and a paying customer.**

You vibe-coded the app. It works on your laptop. Before it touches a paying customer, someone has to ask the 170 boring questions: can user A read user B's invoices by changing a number in the URL? Do password reset links expire? Has anyone ever restored a backup? What happens when the card is charged twice?

AI-Consultant asks them, reads your code for the answers, and writes a report that says:

- **Verdict:** `NOT READY`, `NOT VERIFIED`, `CONDITIONAL` or `READY`, by fixed rules
- **What is broken**, with `file:line` evidence and the smallest fix
- **What it could not verify from code** (backups, DNS, vendor contracts, on-call) as concrete questions for you
- **Which humans you still need**, because some of this is not a code problem

It reviews. It does not rewrite your app, and it will not tell you your app is "secure" or "compliant". See [limits](#what-it-cannot-do).

## Install (Claude Code)

```
/plugin marketplace add adibM04/AI-Consultant
/plugin install ai-consultant@ai-consultant
```

Then, in your project:

```
/ai-consultant:consult
```

It detects your stack, asks a few questions about stage and data (patients? cards? EU customers? enterprise buyers?), audits 14 domains in parallel, and writes `.consultant/REPORT.md`.

Needs Python 3 (standard library only). Optional (gitleaks and semgrep output have been checked against the real tools; osv-scanner and trivy have not yet): [gitleaks](https://github.com/gitleaks/gitleaks), [osv-scanner](https://github.com/google/osv-scanner) and [trivy](https://github.com/aquasecurity/trivy) make the secret and dependency checks much stronger.

### Other commands

| Command | Use it for |
|---|---|
| `/ai-consultant:consult` | Full audit |
| `/ai-consultant:consult-audit identity payments` | Re-check specific domains after fixing things |
| `/ai-consultant:consult-roadmap` | Turn the report into an ordered plan with sizes, owners and what is safe to do with AI |
| `/ai-consultant:consult-ask "do I need SOC 2?"` | Plain-English advice grounded in your repo; also records accepted risks with an expiry |
| `/ai-consultant:consult-evidence` | Prove what code cannot show (a restore test, key rotation, who owns the registrar) as a signed, expiring attestation, to close the "unknown" items |
| `/ai-consultant:consult-questionnaire q.csv` | Draft answers to an enterprise buyer's security questionnaire, capped by what the audit can prove |

You can also just ask: "is my app ready for paying customers?"

## Try it in five minutes

You do not need your own project. After installing:

```
git clone https://github.com/adibM04/AI-Consultant
cd AI-Consultant/examples/vibe-coded-app
claude
> /ai-consultant:consult
```

Pick `launch` when asked, answer "yes" to payments, and let it run. You should get a `NOT READY` verdict with the SQL injection, the missing authentication on invoices, the MD5 passwords and the hard-coded key, each with a line number. It is a deliberately broken 50-line file, so nothing real is at stake. In our runs a five-domain audit cost about $0.70 and took about two minutes; auditing all 14 domains of a bigger project will cost more. Delete the generated `.consultant/` folder afterwards.

Prefer to read first? [`examples/real-run`](examples/real-run) is the unedited output of exactly that, plus a questionnaire draft.

## What it checks

170 items in 14 domains. Every item has a severity, a stage tier, the product traits it applies to, and an owner role.

| Domain | Examples |
|---|---|
| Identity | plus-sign emails, single-use expiring reset links, MFA recovery, session revocation, login rate limits, SSO/SAML/SCIM |
| Authorization | IDOR, tenant isolation, impersonation audit trail, mass assignment |
| Data | designed schema, safe migrations, indexes, pooling, **tested** restores, PITR, money as integers, timezones, pagination |
| Payments | idempotency keys, webhook signatures, tax, proration, dunning, refunds, reconciliation |
| Security | secrets in history, hallucinated packages, XSS/SQLi/CSRF/SSRF, uploads, CORS, headers, logs, disclosure process |
| Compliance | HIPAA and BAAs, GDPR deletion, residency, audit trails of reads, SOC 2 readiness, policies that match the code |
| Infrastructure | CI gates, rollbacks, zero-downtime deploys, queues, retries, DLQs, double-firing cron, SPF/DKIM/DMARC, cost alerts, DR |
| Observability | structured logs, error grouping, external uptime checks, on-call, runbooks, postmortems |
| Testing | tests that assert something, e2e on money paths, load tests, regression tests |
| Integrations | webhook delivery, API versioning and keys, OAuth refresh, third-party drift |
| AI features | prompt injection, PHI in prompts, spend caps, evals, provider fallback, human approval |
| UX | empty/error states, forms that keep input, email clients, accessibility, i18n |
| Maintainability | review, dead code, 2,000-line files, upgrades, a README that works |
| Operations | admin and support tooling, accounts in the company's name, bus factor |

Browse the source of truth in [`checklist/`](checklist/). Items are scoped by **stage** (`launch`, `growth`, `enterprise`) and **tags** (`payments`, `phi`, `eu`, `ai`, ...) so a day-one founder is not told to buy SOC 2, and a clinic is not told it can skip HIPAA.

## How it works

```
founder ──► consult skill ──► profile.json (stage + tags, detected and confirmed)
                │
                ├─► deterministic facts ──► facts/stacks.json     which playbooks apply
                │                           facts/packages.json   does every dependency exist?
                │                           facts/scanners.json   gitleaks / osv-scanner / trivy
                │
                ├─► domain-auditor × 14, in parallel, read-only ──► findings/<domain>.json
                │        (reads the facts and the matching stack playbooks)
                │
                └─► scripts/render_report.py (deterministic) ──► REPORT.md
```

### Deterministic facts under the model

Scripts produce facts; the model interprets them. Nothing here is installed or executed from your project.

| Script | What it establishes |
|---|---|
| `scripts/verify_packages.py` | Whether every npm / PyPI dependency exists, and flags hallucinated names (`NOT_FOUND`), look-alikes of popular packages (`TYPOSQUAT_SUSPECT`), brand-new or abandoned packages. Sends **package names only** to the public registries; `--offline` sends nothing. |
| `scripts/run_scanners.py` | Runs gitleaks, osv-scanner and trivy if you have them (semgrep with `--semgrep`), normalises the output, and strips secret values. Missing tools are reported with install hints, never installed. |
| `scripts/attest.py`, `scripts/questionnaire.py` | Attestations with validation and secret screening; honesty-capped questionnaire drafts |
| `scripts/pr_guard.py` | The deterministic pull-request checks behind the GitHub Action |
| `scripts/detect_stacks.py` | Detects Supabase, Firebase, Next.js, Stripe and AI-builder exports, so the auditors apply the right playbook |

### Stack playbooks

[`stacks/`](stacks/) holds concrete, checklist-mapped procedures for the platforms where vibe-coded apps fail most often: Supabase (RLS off, `service_role` in the browser), Firebase (open rules, "authenticated" mistaken for "authorised"), Next.js (Server Actions without auth, secrets in `NEXT_PUBLIC_`, middleware-only auth), Stripe (unverified webhooks, client-chosen prices), and AI-builder or agent-written codebases (prototype debris, secrets that passed through a chat). Two deliberately broken fixtures in [`examples/`](examples/) check that they work.

Design choices worth knowing:

- **The checklist is data, not prompt.** YAML in, JSON out. You can fork it for your own industry.
- **The verdict is code, not vibes.** `render_report.py` computes it with tested rules: any failing critical item means `NOT READY`; a critical item nobody could verify means `NOT VERIFIED`.
- **`pass` needs evidence.** A finding that says "pass" without a `file:line` is downgraded to `unknown`.
- **Defences live in code, not just prompts.** A `pass` must cite a real file and line, and waivers need a person, a creation date and a short expiry, so a hostile repo cannot plant its way to `READY`. [`evals/`](evals/) runs the real consultant against a deliberately hostile repository to check this.
- **Honest about the invisible.** Items that need a console, a contract or a person are `unknown` with a specific question, never assumed fine.
- **Audited repos are untrusted input.** The auditor is instructed to treat READMEs and comments as data, never commands, to stay read-only, and never to copy a secret into a report.
- **Re-runs diff.** The report shows what you fixed and what regressed. Accepted risks go in `waivers.json` with a reason and an expiry, and reopen when they expire.

See a real run in [`examples/real-run`](examples/real-run) (model-generated, against the deliberately broken [`examples/vibe-coded-app`](examples/vibe-coded-app)). [`examples/sample-output`](examples/sample-output) is a small hand-written file used only to test the renderer.

## Close the unknowns, answer the buyer

**Evidence.** Many items cannot be seen from code: has anyone restored a backup, were the leaked keys rotated, does the company own the domain registrar? `/ai-consultant:consult-evidence` walks you through doing it, helps you write an evidence note in `docs/evidence/` (it refuses text that looks like secrets), and records a signed attestation that expires within a year. Attestations can settle `unknown` items only. They never override a failing finding, never apply to anything checkable in code, and the report lists each one with who said it and when, as a human claim the tool did not verify.

**Questionnaires.** `/ai-consultant:consult-questionnaire` maps each question to checklist items and drafts an answer per row. The honesty is enforced in code (`scripts/questionnaire.py`), not by asking the model nicely:

- A stance cannot be stronger than the weakest backing item. One failed control makes "Yes" a "No" or "Partial", whatever the model wrote.
- When the audit overrules a draft, the prose is thrown away and replaced with deterministic text built from the checklist.
- The Evidence column lists only real files and named attestations, and "the audit did not look at this" is shown as *unknown*, never as *N/A*.
- Output is a CSV with the original columns plus the draft, basis, evidence and what you still owe, ready for a person to review. Nothing is sent anywhere.

The most useful part is often the "No" column: the specific gaps standing between you and the signature.

## Keep it honest in CI (GitHub Action)

An audit is a snapshot. The PR guard keeps the snapshot from silently rotting. Commit `.consultant/` after your audit, then copy [`templates/pr-guard.yml`](templates/pr-guard.yml) to `.github/workflows/`:

```yaml
on: pull_request
permissions: { contents: read, pull-requests: write }
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: adibM04/AI-Consultant@fa6dad20fa77836c602ca471d502943282c9af75  # v0.1.1
```

It uses **no model and no secrets**, runs safely on forked PRs, and compares the pull request to the last audit on the **base branch** (a PR cannot approve itself by editing `.consultant/`). It flags:

| Severity | Catches |
|---|---|
| high | a new dependency that does not exist on the registry or imitates a popular one; `.env`, keys or service-account files added; code cited as evidence for a passing control was **deleted** |
| medium | cited lines were changed or moved (re-audit those controls); the audit record, waivers or findings were edited; waivers the renderer would reject |
| low | waivers about to expire; the audit is far behind; no baseline audit yet |

It is a tripwire, not a review. For a scheduled full audit, [`templates/weekly-audit.yml`](templates/weekly-audit.yml) runs the real consultant weekly. That one needs an API key and costs money, runs only on a schedule or by hand, and must never be triggered by pull requests.

## What it cannot do

Be clear-eyed about this:

- It reads code and config. It cannot see your cloud console, DNS, contracts, vendor agreements or who has the pager. Those become questions.
- Scanner and registry checks only cover what is installed and reachable. If a tool is missing the report says that area was not checked, rather than calling it clean.
- It is a language model reading files. It will miss things and occasionally be wrong. Treat a clean report as "no known gaps in what was checked", never as safety.
- It is not a penetration test, an audit, legal advice, or a tax opinion. SOC 2 needs an auditor. HIPAA needs a person accountable for it. GDPR needs a lawyer.
- It does not replace the people in the second half of the original list: a senior engineer to read what the AI wrote, someone to run live-database migrations, an on-call human, someone who remembers why it is built this way. It tells you which of those you need, and how urgently.

## Use it with other agents

The skills are plain Markdown prompts and the checklist is plain YAML/JSON. Only the Claude Code plugin packaging is tested. For other tools, point the agent at `skills/consult/SKILL.md` and `agents/domain-auditor.md`, and run `python3 scripts/render_report.py --dir .consultant` yourself. Ports are welcome.

## Contributing

The best contributions are battle scars: the failure that cost you a weekend, written as a checklist item. See [CONTRIBUTING.md](CONTRIBUTING.md). To check the repo itself:

```
pip install pyyaml
python3 scripts/checklist.py validate && python3 scripts/checklist.py build --check
python3 -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).
