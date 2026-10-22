# What it checks

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

Browse the source of truth in [`checklist/`](../checklist/). Items are scoped by **stage** (`launch`, `growth`, `enterprise`) and **tags** (`payments`, `phi`, `eu`, `ai`, ...) so a day-one founder is not told to buy SOC 2, and a clinic is not told it can skip HIPAA.

## Each item carries

| Field | Meaning |
|---|---|
| `severity` | `critical` (customers or money exposed now), `high`, `medium`, `low` |
| `tier` | `1` before the first paying customer, `2` before scaling, `3` enterprise or regulated |
| `when` | the product traits (tags) that make it apply |
| `evidence` | `code` (visible in source), `config` (visible in infrastructure or CI config), `process` (needs a person) |
| `role` | who normally owns it: security engineer, DevOps, lawyer, and so on |

To propose a new item, see [CONTRIBUTING.md](../CONTRIBUTING.md).
