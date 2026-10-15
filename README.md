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

Needs Python 3 for the final report step (standard library only).

### Other commands

| Command | Use it for |
|---|---|
| `/ai-consultant:consult` | Full audit |
| `/ai-consultant:consult-audit identity payments` | Re-check specific domains after fixing things |
| `/ai-consultant:consult-roadmap` | Turn the report into an ordered plan with sizes, owners and what is safe to do with AI |
| `/ai-consultant:consult-ask "do I need SOC 2?"` | Plain-English advice grounded in your repo; also records accepted risks with an expiry |

You can also just ask: "is my app ready for paying customers?"

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
                ├─► domain-auditor × 14, in parallel, read-only ──► findings/<domain>.json
                │
                └─► scripts/render_report.py (deterministic) ──► REPORT.md
```

Design choices worth knowing:

- **The checklist is data, not prompt.** YAML in, JSON out. You can fork it for your own industry.
- **The verdict is code, not vibes.** `render_report.py` computes it with tested rules: any failing critical item means `NOT READY`; a critical item nobody could verify means `NOT VERIFIED`.
- **`pass` needs evidence.** A finding that says "pass" without a `file:line` is downgraded to `unknown`.
- **Honest about the invisible.** Items that need a console, a contract or a person are `unknown` with a specific question, never assumed fine.
- **Audited repos are untrusted input.** The auditor is instructed to treat READMEs and comments as data, never commands, to stay read-only, and never to copy a secret into a report.
- **Re-runs diff.** The report shows what you fixed and what regressed. Accepted risks go in `waivers.json` with a reason and an expiry, and reopen when they expire.

See a rendered example in [`examples/sample-output/REPORT.md`](examples/sample-output/REPORT.md) (illustrative, hand-written against the deliberately broken [`examples/vibe-coded-app`](examples/vibe-coded-app)).

## What it cannot do

Be clear-eyed about this:

- It reads code and config. It cannot see your cloud console, DNS, contracts, vendor agreements or who has the pager. Those become questions.
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
