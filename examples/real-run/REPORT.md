# Production readiness report: vibe-coded-fixture

Generated 2026-10-15 · stage: **launch** · tags: b2b, payments

## Verdict: NOT READY

At least one critical gap is confirmed. Do not put paying customers on this until the blockers below are fixed.

| Pass | Fail | Partial | Unknown | Attested | Waived | Not audited |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 25 | 3 | 8 | 0 | 0 | 28 |

Coverage: 38 of 66 in-scope items audited. 54 items are deferred to later stages and 47 do not apply to this product.

> This report comes from reading the repository and answers the founder gave. It cannot see your cloud console, DNS, contracts or processes, so those items show as UNKNOWN until someone confirms them. It does not replace a penetration test, an auditor, or an engineer who understands your system.

## Blockers (critical)

#### AUT-01 · Every route, API handler, server action and job enforces authorization on the server

`FAIL` · critical · owner: Security engineer · tier 1

No route enforces authorization. /login returns the raw user id as the 'token' and no middleware verifies any session or token, so GET /invoices/:id and POST /charge are open to anyone.

Evidence: `server.js:25`, `server.js:34-37`, `server.js:39-47`, `searched: auth|middleware|jwt|session|authorize|requireAuth in server.js`

**Fix:** Issue real signed session or JWT tokens at login and add an auth middleware to every non-public route (all but /signup, /login, /forgot). A human engineer should review the auth change.

#### AUT-02 · Object-level checks stop user A reading or editing user B's records by changing an ID

`FAIL` · critical · owner: Security engineer · tier 1

GET /invoices/:id selects by id only, with no owner or tenant scoping, so any caller can read any invoice by changing the id (likely sequential). The id is also interpolated into the SQL string.

Evidence: `server.js:34-37`

**Fix:** Require authentication, then query with a parameterised statement scoped to the owner, e.g. WHERE id = $1 AND user_id = $2, and return 404 when no row matches.

#### DAT-11 · All input is validated on the server with a schema, not only in the form

`FAIL` · critical · owner: Backend engineer · tier 1

No server-side validation on any write path: /signup, /login, /forgot and /charge use req.body fields directly with no schema, type, length or range limits. /charge takes price and qty from the client and an undefined password would throw in createHash.

Evidence: `server.js:14`, `server.js:21`, `server.js:30`, `server.js:40`, `searched: zod|joi|yup|ajv|express-validator across repo`

**Fix:** Add zod (or Joi) validation at every handler: email format and length, password length, qty as a bounded positive integer; have the server look up the price by product id (stripe playbook ST-2).

#### DAT-14 · Money is stored as integer minor units or fixed-point decimals with an explicit currency, never floats

`FAIL` · critical · owner: Backend engineer · tier 1

Money is computed with floats: price * qty * 1.0825 then Math.round(total * 100), with price and qty taken from the request body and currency hardcoded to usd with no currency column. Stripe playbook ST-2 and ST-9 apply.

Evidence: `server.js:40`, `server.js:44`

**Fix:** Store and compute prices as integer minor units with an explicit currency; look up the price server-side by product or Stripe Price id, and round tax in one documented step (or use Stripe Tax).

#### IDN-02 · Password reset and magic links expire, work once, and are stored hashed

`FAIL` · critical · owner: Security engineer · tier 1

/forgot generates the reset token with Math.random (predictable), stores it in plaintext, sets no expiry, and never emails it. No reset-confirm route exists, so single-use and invalidation are not implemented. Email is also interpolated into SQL (injection).

Evidence: `server.js:28-32`, `searched: reset confirm route, expiry, token hashing in server.js`

**Fix:** Use crypto.randomBytes(32), store only a SHA-256 hash with a short expiry, make it single-use, and invalidate on use and password change. Parameterise the query. Prefer a hosted auth provider; a human engineer should review the flow.

#### IDN-03 · Passwords hashed with a modern slow algorithm (argon2id, scrypt, bcrypt)

`FAIL` · critical · owner: Security engineer · tier 1

Passwords are hashed with unsalted MD5 at signup and login, which is trivially crackable.

Evidence: `server.js:15`, `server.js:22`

**Fix:** Switch to argon2id or bcrypt (argon2 / bcrypt package) with per-password salts; existing hashes need a rehash-on-login migration, so have an engineer handle it.

#### IDN-06 · Login, signup, reset and MFA endpoints are rate limited per account and per IP

`FAIL` · critical · owner: Security engineer · tier 1

No rate limiting on /signup, /login or /forgot, so credential stuffing and brute force against MD5 hashes are unrestricted.

Evidence: `server.js:13-32`, `searched: rate-limit|throttle|limiter|helmet across repo`

**Fix:** Add express-rate-limit with a shared store (e.g. Redis) per IP and per account on auth routes.

#### PAY-01 · Charge and order creation use idempotency keys so a retry never charges twice

`FAIL` · critical · owner: Backend engineer · tier 1

POST /charge calls Stripe /v1/charges with no Idempotency-Key header and records no order or payment attempt, so a retry or timeout can charge twice (playbook ST-5). The amount is also computed from client-supplied price and qty (ST-2), and it uses the legacy Charges API.

Evidence: `server.js:39-47`, `searched: idempotency|Idempotency-Key|idempotencyKey across server.js`

**Fix:** Create an order row server-side with a unique constraint, then pass its id as the Idempotency-Key header on the Stripe call. Move to PaymentIntents or Checkout with server-side price lookup.

#### PAY-04 · Provider webhooks verify signatures and are the source of truth for entitlement and payment state

`FAIL` · critical · owner: Backend engineer · tier 1

There is no Stripe webhook endpoint, so payment state is not driven by signed provider events (ST-1, ST-4). /charge just returns the Stripe response and nothing records payment state. The Stripe secret key is also hard-coded in source (a fake fixture value here; a real one would need rotating).

Evidence: `server.js:11`, `server.js:39-47`, `searched: webhook|constructEvent|whsec_|stripe-signature across server.js`

**Fix:** Add a POST /stripe/webhook route using express.raw and stripe.webhooks.constructEvent with the endpoint secret. Store processed event ids and grant entitlement only from checkout.session.completed or payment_intent.succeeded. Load keys from environment variables.

#### SEC-01 · No secrets in source code, git history, client bundles, or committed .env files

`FAIL` · critical · owner: Security engineer · tier 1

server.js hard-codes a Stripe secret-key-style string (STRIPE_KEY) in source and uses it in the /charge handler; the value looks like a fixture placeholder but the pattern is a committed secret. gitleaks did not run, so git history (single commit) was only checked by hand and no .env file is tracked. ST-3.

Evidence: `server.js:11`, `server.js:43`, `searched: .env files and key prefixes (sk_, AKIA, ghp_, xox, private key) in git ls-files; only server.js:11 matched`

**Fix:** Read the key from process.env (STRIPE_SECRET_KEY), keep it out of git, and rotate it if it was ever real. Run gitleaks over history.

#### SEC-06 · Database access is parameterised; no SQL, NoSQL or command injection paths

`FAIL` · critical · owner: Security engineer · tier 1

SQL is built by string interpolation of request input in signup, login, forgot and invoices, giving direct SQL injection (login bypass, data theft, account takeover via reset_token update).

Evidence: `server.js:16`, `server.js:23`, `server.js:30`, `server.js:35`

**Fix:** Use parameterised queries (db.query('... WHERE email = $1', [email])) in every handler and validate id as an integer.

## Important (high)

#### AUT-08 · Mass assignment is prevented; clients cannot set role, tenant, price or owner fields

`FAIL` · high · owner: Security engineer · tier 1

POST /charge takes price and qty from the request body and computes the charged amount from them (Stripe playbook ST-2), so a client can set any price. /signup inserts only email and hash, so there is no role or owner mass assignment there.

Evidence: `server.js:40`, `server.js:44`

**Fix:** Accept a product or plan id, look up the price server-side (Stripe Price ids), validate qty as a bounded integer, and never use client-supplied amounts.

#### DAT-01 · The schema was designed (keys, foreign keys, constraints, types), not improvised table by table

`FAIL` · high · owner: Backend engineer · tier 1

No schema, migrations or models exist in the repo; server.js:16 and :35 imply users and invoices tables, and :30 a reset_token column. Passwords are stored in the user-level 'password' column and invoices are fetched with no owner column visible.

Evidence: `server.js:16`, `server.js:35`, `searched: CREATE TABLE|schema|prisma|sequelize|knex across repo`

**Fix:** Define the schema in a migration tool with primary and foreign keys, NOT NULL, a unique index on normalised email, and an owner/tenant column on invoices.

#### DAT-02 · Migrations are versioned, run forward in CI and have a rollback path

`FAIL` · high · owner: Backend engineer · tier 1

No migration tool, migration files or CI exist. server.js requires ./db, which is not in the repo.

Evidence: `server.js:5`, `searched: migrations|knex|prisma|flyway|alembic and .github workflows across repo`

**Fix:** Adopt a migration tool (Knex, Prisma Migrate or node-pg-migrate), commit versioned migrations, and run them in the deploy pipeline.

#### DAT-05 · N+1 queries and unbounded result sets are controlled

`PARTIAL` · high · owner: Backend engineer · tier 1

No N+1 loops, but GET /invoices/:id returns a single row so unbounded sets are not present yet. There are no list endpoints at all, so this is mostly untested territory.

Evidence: `server.js:34-37`

**Fix:** When list endpoints are added, apply LIMIT and a max page size from the start.

#### DAT-06 · Connection pooling is configured so a traffic spike cannot exhaust the database

`FAIL` · high · owner: DevOps engineer · tier 1

Connection pooling and timeouts cannot be seen: ./db is missing from the repo and server.js sets no pool settings.

Evidence: `server.js:5`, `searched: pool|max connections|pgbouncer|statement_timeout across repo`

**Fix:** Configure a pool with explicit max size and timeouts in the db module, and use a provider pooler if deployed serverless or multi-instance.

#### IDN-01 · Login and signup handle plus-addressing, case, Unicode and whitespace in emails consistently

`FAIL` · high · owner: Backend engineer · tier 1

Emails are used raw in signup (line 16), login (23) and forgot (30): no trim, lowercasing or normalisation, and no unique index is visible (no schema in repo). Case variants create duplicate accounts or failed logins.

Evidence: `server.js:13-18`, `server.js:20-26`, `searched: toLowerCase|normalize|trim|unique across repo`

**Fix:** Normalise (trim, lowercase, Unicode NFKC) in one helper used by signup, login, forgot; add a unique index on the normalised email; use a validator such as zod.

#### IDN-05 · Sessions time out (idle and absolute) and all sessions for one user can be revoked

`FAIL` · high · owner: Backend engineer · tier 1

Login returns the raw user id as the 'token'. There is no session, expiry, signature or revocation, and the id is guessable and sequential. Nothing validates it on other routes.

Evidence: `server.js:25`, `searched: jwt|session|cookie|express-session across repo`

**Fix:** Issue server-side sessions or signed JWTs with idle and absolute expiry and a revocation mechanism (session table or token version), or adopt a hosted auth provider. Human engineer should do this.

#### IDN-07 · Lockout and throttling stop attackers without letting them lock out real users at will

`FAIL` · high · owner: Security engineer · tier 1

No throttling, progressive delay, captcha or lockout of any kind on /login.

Evidence: `server.js:20-26`, `searched: lockout|attempts|captcha|delay across repo`

**Fix:** Add per-account progressive delays or captcha after failures rather than hard lockout.

#### IDN-09 · Email is verified before it is trusted for access, invites or account linking

`FAIL` · high · owner: Security engineer · tier 1

There is no email verification step: signup inserts the account and it can log in immediately with any claimed address. No social login exists, but email is trusted for password reset and account identity unverified.

Evidence: `server.js:13-18`, `searched: verify|confirmation|verified across repo`

**Fix:** Add an email_verified flag and a hashed, expiring verification token; block login, invites and linking until verified.

#### PAY-02 · Double-submits (four clicks on "Pay") are deduplicated on the server and disabled in the UI

`FAIL` · high · owner: Backend engineer · tier 1

/charge has no server-side deduplication: no order or attempt table, no lock, no unique constraint. There is no front end in the repo, so no UI protection is visible either.

Evidence: `server.js:39-47`, `searched: dedupe|unique|lock|attempt across server.js`

**Fix:** Add a unique open payment attempt per order or cart in the database and reject or replay duplicates. Also disable the Pay button in the UI.

#### SEC-04 · Dependencies are scanned automatically and the lockfile is committed

`FAIL` · high · owner: DevOps engineer · tier 1

No manifest, lockfile, Dependabot/Renovate config or CI audit step exists in the repo.

Evidence: `searched: package-lock.json|yarn.lock|pnpm-lock.yaml|.github/|renovate.json|dependabot.yml; none tracked`

**Fix:** Commit package.json and a lockfile, install with npm ci, enable Dependabot and add npm audit to CI.

#### SEC-10 · CORS is restricted to known origins (not "*" with credentials or reflected origin)

`FAIL` · high · owner: Security engineer · tier 1

CORS is open to every origin on all routes, including the charge and invoice endpoints.

Evidence: `server.js:8`

**Fix:** Set cors({ origin: [your app origins] }) from config; avoid '*' once credentials or cookies are used.

#### SEC-14 · Logs record who did what and never record passwords, tokens, card numbers or other sensitive fields

`PARTIAL` · high · owner: Security engineer · tier 1

The code has no logging at all, so no sensitive data is logged, but it also records no audit of who did what. Passwords are also handled with an unsalted MD5 hash (see identity domain) and the full Stripe response, including charge details, is returned to the client.

Evidence: `server.js:46`, `searched: console.log|logger|morgan|pino|winston across server.js; none`

**Fix:** Add a structured logger with redaction of Authorization, password and card fields, and log authentication and charge events with actor and request ID. Return only the fields the client needs from /charge.

#### SEC-15 · Production errors do not leak stack traces, SQL, or internals; debug mode is off

`FAIL` · high · owner: Backend engineer · tier 1

No error handler exists and all handlers are async without try/catch, so a DB error (easily triggered by injection) leaves requests hanging or crashes the process on unhandled rejection in modern Node; the default Express handler prints stack traces unless NODE_ENV=production. The /charge handler also relays Stripe's raw error body to the client.

Evidence: `server.js:13-47`, `searched: app.use((err|NODE_ENV|errorHandler across server.js; none`

**Fix:** Add async error wrapping (or express-async-errors), a final error middleware returning a generic message, and set NODE_ENV=production.

## Worth fixing (medium and low)

#### DAT-13 · Text handling survives apostrophes, accents, emoji and right-to-left scripts in every field

`FAIL` · medium · owner: Backend engineer · tier 1

All SQL is built by string interpolation of user input (apostrophes in an email or id break or inject into the query), and charset of the database is unknown.

Evidence: `server.js:16`, `server.js:23`, `server.js:30`, `server.js:35`

**Fix:** Use parameterised queries ($1 placeholders) everywhere, and confirm the database encoding is UTF-8. Treat the injection itself as urgent; a human engineer should review all queries.

#### IDN-08 · Signup, login and reset responses do not reveal whether an account exists

`PARTIAL` · medium · owner: Security engineer · tier 1

Login returns a generic 'bad credentials' 401 for both unknown email and wrong password, and /forgot always returns ok. But /signup has no duplicate handling (would error or leak via a DB error), and the SQL injection in these routes undermines the guarantee. Timing is not equalised.

Evidence: `server.js:24`, `server.js:31`, `server.js:16`

**Fix:** Handle duplicate signup with a neutral response (and verification email), and fix the injection.

#### SEC-11 · Security headers are set on every response (CSP, HSTS, X-Content-Type-Options, frame protection, referrer policy)

`FAIL` · medium · owner: Security engineer · tier 1

No security headers are set: no helmet or manual HSTS, CSP, X-Content-Type-Options or frame protection, and Express sends X-Powered-By.

Evidence: `server.js:7-9`, `searched: helmet|Strict-Transport-Security|Content-Security-Policy|x-powered-by across server.js`

**Fix:** Add helmet() before routes and disable x-powered-by; confirm with curl -I on the live site.

## Needs a human to confirm

These could not be established from the repository. Answer each with evidence (a screenshot, a document, a console setting) and record it with `/ai-consultant:consult-evidence`.

#### DAT-07 · Automated backups run at least nightly

`UNKNOWN` · critical · owner: DevOps engineer · tier 1

No IaC or backup config in the repo; the database host is not identifiable.

Evidence: `searched: backup|snapshot|terraform|pg_dump|retention across repo`

**To confirm:** Show the managed database backup setting (console screenshot or IaC) with frequency and retention.

#### DAT-08 · A restore from backup has been performed and timed, and the steps are written down

`UNKNOWN` · critical · owner: DevOps engineer · tier 1

No restore runbook or drill record in the repo.

Evidence: `searched: restore|runbook|disaster|recovery in README.md and docs`

**To confirm:** Show a dated restore drill record with timing and written steps, or confirm none has been done.

#### OPS-04 · Every account, domain, repository, cloud project and vendor login belongs to the company, not to the person who built the prototype

`NOT AUDITED` · critical · owner: Tech lead · tier 1

**To confirm:** Show evidence for: Ask the founder to list registrar, DNS, cloud, git hosting, payment provider, app stores and email provider with the owning account for each. Personal emails as owner on any of them are a finding.

#### SEC-02 · Every key an AI assistant ever pasted into a config file, chat or prompt has been rotated

`UNKNOWN` · critical · owner: Security engineer · tier 1

Key rotation and whether any keys were shared with an AI tool cannot be seen from the repo.

Evidence: `searched: rotation notes or secrets docs in repo; none`

**To confirm:** When were the Stripe and database credentials last rotated, and were any pasted into an AI assistant, chat or screenshot?

#### CMP-09 · The terms of service and privacy policy match what the code actually collects, shares and retains

`NOT AUDITED` · high · owner: Lawyer · tier 1

**To confirm:** Show evidence for: Compare the policy text to analytics, trackers, third-party SDKs, stored fields, and retention behaviour. Flag mismatches for a lawyer.

#### DAT-04 · Indexes exist for real query paths (filters, joins, sorts, foreign keys)

`UNKNOWN` · high · owner: Backend engineer · tier 1

No schema is in the repo, so indexes cannot be matched to queries. Queries filter users by email (server.js:23, :30) and invoices by id (:35).

Evidence: `server.js:23`, `server.js:35`, `searched: CREATE INDEX|index across repo`

**To confirm:** Show the production schema (pg_dump --schema-only or equivalent) so indexes on users.email and invoices can be checked.

#### INF-03 · A deploy pipeline runs tests, linting and type checks before anything reaches customers

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: CI workflow files. Branch protection requiring green checks cannot be seen from the repo, so ask. Deploys from a laptop are a finding.

#### INF-09 · DNS, TLS certificates and domain registration auto-renew and expiries are monitored

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Managed certificates or ACME renewal with alerting, registrar auto-renew, registrar account owned by the company.

#### INF-10 · Slow work (email, reports, AI calls, imports) runs on a background queue, not in the request

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Long synchronous calls inside HTTP handlers, request timeouts shorter than the work, fire-and-forget promises that vanish on restart.

#### INF-11 · Outbound calls have timeouts and retries with exponential backoff and jitter

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: HTTP clients with no timeout, retry loops with no cap or delay, retries on non-idempotent calls.

#### INF-18 · Cost alerts and budgets exist, including per-service caps for pay-per-use APIs, so a runaway loop is caught the same day

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Cloud billing alarms, provider spend limits, and per-key caps on AI and email APIs.

#### API-09 · Every outbound third-party call has a timeout, a circuit breaker or fallback, and an owner for when the vendor is down

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: HTTP client defaults, failure handling in user-facing paths, graceful degradation of non-critical vendors (analytics, chat widgets).

#### MNT-02 · Every change gets a human code review before merge

`NOT AUDITED` · high · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Branch protection and PR history. Repos with direct pushes to main and AI-authored commits that nobody read are a finding.

#### OBS-01 · Logs are structured, correlated by request ID and searchable in one place

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: console.log soup vs a logger with levels and JSON output, request/trace IDs, and a log destination that retains history.

#### OBS-02 · Errors are captured and grouped by an error tracker, with release tagging

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Sentry-style SDK in both server and client, source maps uploaded, PII scrubbing, alert rules that avoid 4,000 identical emails.

#### OBS-03 · Uptime and key user journeys are checked from outside your own network

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: External probe on the login page and a core API route. Cannot be seen from the repo unless configured as code.

#### OPS-05 · At least two people can deploy, restore a backup and rotate every credential (bus factor above one)

`NOT AUDITED` · high · owner: Tech lead · tier 1

**To confirm:** Show evidence for: Who holds the root credentials and the 2FA devices? What happens if one person is unreachable for a week?

#### OPS-06 · Shared credentials live in a team password manager or secrets store, not in chat, docs or someone's head

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Look for credentials in README, wiki exports or setup scripts, and ask where the rest live.

#### SEC-03 · Every installed package exists, is the one intended, and is not a look-alike (hallucinated or typosquatted names)

`UNKNOWN` · high · owner: Security engineer · tier 1

No package.json or lockfile is committed, so the dependencies (express, cors, ./db) cannot be verified, and packages.json ran offline with zero packages. Also, ./db is required but not in the repo.

Evidence: `server.js:2-5`, `searched: package.json|requirements.txt|lockfiles in git ls-files`

**To confirm:** Show the real package.json and lockfile, and the ./db module, so dependency names can be verified against the registry.

#### SEC-12 · Data is encrypted in transit everywhere and at rest in databases, buckets and backups

`UNKNOWN` · high · owner: DevOps engineer · tier 1

Database and TLS configuration are not in the repo (./db is absent) and nothing in server.js redirects HTTP or terminates TLS. Stripe calls use https.

Evidence: `server.js:5`, `server.js:49`

**To confirm:** Show the DB connection settings (sslmode), the TLS terminator or host config, and the provider's at-rest encryption setting.

#### SEC-13 · Everyone and everything, including AI coding agents, holds least-privilege credentials, and none holds production write access by default

`UNKNOWN` · high · owner: Security engineer · tier 1

IAM, DB credential privileges and who holds production access cannot be seen from the repo. Note the Stripe key is a full secret key rather than a restricted key.

Evidence: `server.js:11`, `searched: IAM|role|grant config files; none`

**To confirm:** Which DB user does the app connect as (superuser?), and who and what (including AI agents) hold production credentials?

#### TST-01 · Business logic has unit tests that assert real expected behaviour, not just that the code runs

`NOT AUDITED` · high · owner: QA engineer · tier 1

**To confirm:** Show evidence for: Sample the tests. Tests with no assertions, assertions on mocks of the thing under test, snapshot tests of everything, or tests that were clearly generated from the implementation rather than the requirement.

#### TST-02 · Tests for the money and access paths exist end to end (signup, login, checkout, permission boundaries)

`NOT AUDITED` · high · owner: QA engineer · tier 1

**To confirm:** Show evidence for: Playwright/Cypress or equivalent covering the flows that make money and the flows that must refuse access.

#### TST-07 · Tests run in CI on every change and a failing test blocks merge

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: CI config runs the suite. Skipped tests (.skip, xfail, test.todo) counted and listed.

#### DAT-12 · Timestamps are stored in UTC with the user's zone kept separately, and scheduled work respects it

`UNKNOWN` · medium · owner: Backend engineer · tier 1

No schema or timestamp columns are visible, and no date handling or scheduled work exists in server.js.

Evidence: `searched: timestamp|timestamptz|Date|toISOString|cron across repo`

**To confirm:** Show the production schema to confirm timestamps use timestamptz (UTC).

#### INF-21 · Configuration is validated at boot and the app fails fast when a required setting is missing

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: A typed env schema. Silent fallbacks to test keys or localhost in production paths.

#### MNT-01 · The code is readable by a human who did not write it, with consistent structure and naming

`NOT AUDITED` · medium · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Sample several modules. Inconsistent patterns across files, god functions, magic numbers, comments that contradict code.

#### MNT-03 · A branching strategy lets two people work without overwriting each other

`NOT AUDITED` · medium · owner: Tech lead · tier 1

**To confirm:** Show evidence for: Branch naming, PR flow, release tagging, and a documented convention in CONTRIBUTING.

#### MNT-06 · Dead code, abandoned files and leftovers from the AI's earlier attempts have been deleted

`NOT AUDITED` · medium · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Unused exports, unreferenced files, commented-out blocks, v1/v2/old/backup filenames, duplicate implementations of the same helper.

#### MNT-07 · No single file has grown into an unreviewable monolith

`NOT AUDITED` · medium · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: List the largest files by line count and flag those above roughly 800 lines or with many unrelated responsibilities.

#### MNT-09 · A README gets a new engineer running locally in under an hour

`NOT AUDITED` · medium · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Follow the README literally. Prerequisites, env vars with an example file, seed data, how to run tests. Note every step that fails or is missing.

#### MNT-11 · Linting, formatting and type checking are configured and enforced

`NOT AUDITED` · medium · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: ESLint/ruff/mypy/tsc strictness, pre-commit hooks or CI enforcement, count of suppressions (any, ts-ignore, noqa).

#### TST-04 · Every fixed bug gets a regression test

`NOT AUDITED` · medium · owner: QA engineer · tier 1

**To confirm:** Show evidence for: Look at recent bug-fix commits for an accompanying test.

#### UXP-01 · Every screen has designed empty, loading and error states

`NOT AUDITED` · medium · owner: Frontend engineer · tier 1

**To confirm:** Show evidence for: Data-fetching components with no loading or error branch, blank screens on empty lists, infinite spinners.

#### UXP-02 · Error messages tell the customer what happened and what to do next, instead of "something went wrong"

`NOT AUDITED` · medium · owner: Frontend engineer · tier 1

**To confirm:** Show evidence for: Generic catch-all messages, raw exception text in the UI, errors with no recovery action or support reference ID.

#### UXP-03 · Forms keep what people typed when one field fails validation, and show errors next to the field

`NOT AUDITED` · low · owner: Frontend engineer · tier 1

**To confirm:** Show evidence for: Controlled state vs full page reload, server errors mapped to fields.

## People this product still needs

Open items grouped by the kind of person who normally owns them.

| Role | Open items | Critical | Most urgent |
|---|---:|---:|---|
| Security engineer | 18 | 8 | AUT-01 Every route, API handler, server action and job enforces authorization |
| Backend engineer | 19 | 4 | DAT-11 All input is validated on the server with a schema, not only in the fo |
| DevOps engineer | 11 | 2 | DAT-07 Automated backups run at least nightly |
| Tech lead | 3 | 1 | OPS-04 Every account, domain, repository, cloud project and vendor login belo |
| Senior engineer | 6 | 0 | MNT-02 Every change gets a human code review before merge |
| QA engineer | 3 | 0 | TST-01 Business logic has unit tests that assert real expected behaviour, not |
| Frontend engineer | 3 | 0 | UXP-01 Every screen has designed empty, loading and error states |
| Lawyer | 1 | 0 | CMP-09 The terms of service and privacy policy match what the code actually c |

## Coming up at later stages

Not counted against the verdict yet. Plan for these before you move up a stage.

- tier 2 · AUT-05 · Roles and permissions go deeper than "admin" and "everyone else"
- tier 2 · AUT-07 · Support "log in as this user" exists, is restricted, time-boxed and audit-logged on every use
- tier 2 · CMP-04 · A general audit log records security-relevant actions (login, permission change, export, delete, admin action) immutably
- tier 2 · DAT-03 · Migrations avoid long table locks on large tables (concurrent index builds, batched backfills, expand then contract)
- tier 2 · DAT-09 · Point-in-time recovery is enabled for the database
- tier 2 · IDN-04 · MFA is available, and there is a recovery path for users who lose their device
- tier 2 · INF-01 · Dev, staging and production are separate and configured alike
- tier 2 · INF-02 · Infrastructure is defined as code, so the setup does not live in one person's memory
- tier 2 · INF-04 · Rollback is one click or one command and has been rehearsed
- tier 2 · INF-13 · Scheduled jobs run exactly once even with multiple servers (leader election, locks or a managed scheduler)
- tier 2 · MNT-05 · The framework and runtime versions still receive security patches
- tier 2 · OBS-04 · Alerts page a human, on symptoms that matter, and are tuned until they stop paging for nothing
- tier 2 · OBS-07 · There is an on-call rotation, and a named person who picks up
- tier 2 · PAY-05 · Currency, rounding and tax rules are defined for every country sold into
- tier 2 · PAY-06 · Sales tax and VAT are calculated, collected and reported correctly where required
- tier 2 · PAY-09 · Refunds, credits and partial refunds work and keep revenue records consistent
- tier 2 · TST-05 · Load testing has been done at realistic data volume before launch campaigns
- tier 2 · CMP-11 · A DPA template and sub-processor list are available for business customers
- tier 2 · DAT-10 · Deletes of user-visible records are soft (recoverable) or otherwise reversible
- tier 2 · DAT-17 · Customers can export their data in a usable format without engineering help
- tier 2 · DAT-18 · Imports validate, report row-level errors and survive odd encodings, delimiters and huge files
- tier 2 · INF-05 · Deploys are zero-downtime (health checks, rolling or blue/green, graceful shutdown, backwards-compatible schema changes)
- tier 2 · INF-06 · Feature flags let you ship code without shipping the feature
- tier 2 · INF-07 · Autoscaling or enough headroom exists for the predictable spike
- tier 2 · INF-12 · Jobs that exhaust their retries land in a dead-letter queue that someone is alerted about
- tier 2 · INF-14 · Caching has a stated invalidation strategy and cannot serve one user's data to another
- tier 2 · API-06 · Parsing third-party responses tolerates unexpected shape changes and fails loudly, not silently
- tier 2 · MNT-04 · Dependencies are upgraded on a regular cadence, and nothing is two major versions behind
- tier 2 · MNT-10 · Documentation exists for whoever inherits the system (components, data flow, third parties, how to deploy)
- tier 2 · MNT-12 · Business rules live in one place each, not duplicated across the frontend, backend and database
- tier 2 · OBS-05 · Dashboards show latency, error rate and throughput for the core flows
- tier 2 · OBS-08 · Runbooks explain what each alert means and what to do first
- tier 2 · OBS-09 · Incidents get blameless postmortems, and the action items are tracked to done
- tier 2 · OBS-10 · A status page exists so customers check it before they email you
- tier 2 · OPS-01 · An admin panel lets your ops team do routine work without database access
- tier 2 · OPS-02 · Support tooling lets customer success answer questions without pinging engineering
- tier 2 · PAY-13 · Finance can reconcile revenue reports against the payment provider and the bank
- tier 2 · SEC-18 · A vulnerability disclosure process exists (security.txt, a monitored security@ inbox, a response SLA)
- tier 2 · SEC-19 · There is a documented plan for a stolen laptop or leaked credential (disk encryption, remote wipe, revocation steps)
- tier 2 · SEC-20 · Webhook endpoints, public APIs and forms are protected against automated abuse (bot protection, quotas)
- tier 2 · TST-03 · Integration tests cover every third-party API the product depends on, against sandboxes or recorded contracts
- tier 2 · UXP-04 · Pages and bundles are light enough for hotel wifi and mid-range phones
- tier 2 · UXP-08 · The app is usable by keyboard and screen reader (semantic HTML, labels, focus management, contrast)
- tier 2 · INF-08 · Static assets are served through a CDN and cached with sensible headers
- tier 2 · MNT-08 · Architecture decisions are written down with their reasons
- tier 2 · OPS-03 · Customers can read a changelog of what changed and when
- tier 2 · UXP-10 · The back button, deep links, refresh and multiple tabs behave as people expect
- tier 3 · INF-19 · A disaster recovery plan is written down and has been exercised at least once
- tier 3 · DAT-15 · The data model can absorb a customer's "one small change" (per-tenant settings, custom fields, plan variants) without a rewrite
- tier 3 · PAY-11 · Invoices carry required fields (legal entity, tax ID, customer PO number) and can be re-issued
- tier 3 · PAY-12 · Annual and custom-term contracts can be represented without code changes
- tier 3 · OBS-06 · A single slow request can be traced across every service it touches
- tier 3 · TST-08 · The app has been tested on old devices, slow networks and the browsers your customers actually use
- tier 3 · UXP-07 · Destructive actions have confirmation or undo

<details><summary>Passed (2)</summary>

- AUT-06 · Admin and internal endpoints are separated from the public surface and protected independently (`server.js:13-47`, `searched: admin|debug|seed|impersonat|role across server.js`)
- SEC-08 · SSRF, open redirects and path traversal are blocked (`server.js:41`, `searched: res.redirect|fs.|path.join|sendFile across server.js; none`)

</details>
