# Production readiness report: vibe-coded-fixture

Generated 2026-10-15 · stage: **launch** · tags: b2b, payments

## Verdict: NOT READY

At least one critical gap is confirmed. Do not put paying customers on this until the blockers below are fixed.

| Pass | Fail | Partial | Unknown | Attested | Waived | Not audited |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 13 | 0 | 2 | 0 | 0 | 66 |

Coverage: 15 of 81 in-scope items audited. 63 items are deferred to later stages and 49 do not apply to this product.

> This report comes from reading the repository and answers the founder gave. It cannot see your cloud console, DNS, contracts or processes, so those items show as UNKNOWN until someone confirms them. It does not replace a penetration test, an auditor, or an engineer who understands your system.

## Blockers (critical)

#### AUT-01 · Every route, API handler, server action and job enforces authorization on the server

`FAIL` · critical · owner: Security engineer · tier 1

No route checks who is calling. There is no authentication middleware at all.

Evidence: `examples/vibe-coded-app/server.js:34`

**Fix:** Add authentication middleware and apply it to every non-public route.

#### AUT-02 · Object-level checks stop user A reading or editing user B's records by changing an ID

`FAIL` · critical · owner: Security engineer · tier 1

GET /invoices/:id returns any invoice to anyone who changes the number in the URL.

Evidence: `examples/vibe-coded-app/server.js:35`

**Fix:** Require auth, then scope the query: WHERE id = $1 AND account_id = $2.

#### DAT-11 · All input is validated on the server with a schema, not only in the form

`FAIL` · critical · owner: Backend engineer · tier 1

Request bodies are used with no validation of type, length or format.

Evidence: `examples/vibe-coded-app/server.js:13`, `examples/vibe-coded-app/server.js:20`

**Fix:** Add schema validation (zod or similar) at every write route.

#### DAT-14 · Money is stored as integer minor units or fixed-point decimals with an explicit currency, never floats

`FAIL` · critical · owner: Backend engineer · tier 1

The charge total is computed with floating point and a tax multiplier inline.

Evidence: `examples/vibe-coded-app/server.js:40`

**Fix:** Keep prices as integer cents and apply tax and rounding in one tested function.

#### IDN-02 · Password reset and magic links expire, work once, and are stored hashed

`FAIL` · critical · owner: Security engineer · tier 1

Reset token comes from Math.random(), is stored in plain text, has no expiry and nothing invalidates it after use. It is also never emailed, so the flow is incomplete.

Evidence: `examples/vibe-coded-app/server.js:29`, `examples/vibe-coded-app/server.js:30`

**Fix:** Generate 32 bytes with crypto.randomBytes, store only a SHA-256 hash with an expiry of 30-60 minutes, delete it on use and on password change.

#### IDN-03 · Passwords hashed with a modern slow algorithm (argon2id, scrypt, bcrypt)

`FAIL` · critical · owner: Security engineer · tier 1

Passwords are hashed with unsalted MD5, which is cracked at billions of guesses per second.

Evidence: `examples/vibe-coded-app/server.js:15`, `examples/vibe-coded-app/server.js:22`

**Fix:** Use argon2id or bcrypt via a maintained library, and rehash existing users on their next login.

#### IDN-06 · Login, signup, reset and MFA endpoints are rate limited per account and per IP

`FAIL` · critical · owner: Security engineer · tier 1

/login, /signup and /forgot have no rate limiting. Searched: rate-limit|limiter|throttle across the repo, no hits.

Evidence: `examples/vibe-coded-app/server.js:19`, `searched: rate-limit|limiter|throttle`

**Fix:** Add express-rate-limit backed by Redis (per IP and per email) on all auth routes.

#### PAY-01 · Charge and order creation use idempotency keys so a retry never charges twice

`FAIL` · critical · owner: Backend engineer · tier 1

The charge call has no idempotency key, so a retry or double click charges the card twice.

Evidence: `examples/vibe-coded-app/server.js:41`

**Fix:** Send an Idempotency-Key derived from the order, and record attempts in a table with a unique constraint.

#### PAY-04 · Provider webhooks verify signatures and are the source of truth for entitlement and payment state

`FAIL` · critical · owner: Backend engineer · tier 1

Charge state is whatever the synchronous call returned. No webhook handler exists, so refunds, disputes and async failures are invisible.

Evidence: `searched: webhook|stripe-signature`

**Fix:** Add a signature-verified webhook endpoint and treat it as the source of truth.

#### SEC-01 · No secrets in source code, git history, client bundles, or committed .env files

`FAIL` · critical · owner: Security engineer · tier 1

A payment provider key is hard-coded in source. (In this fixture it is a fake string; a real one would need rotating immediately.)

Evidence: `examples/vibe-coded-app/server.js:11`

**Fix:** Move to an environment variable loaded at boot, add a secret scanner to CI, and rotate the key if it ever reached git history.

#### SEC-06 · Database access is parameterised; no SQL, NoSQL or command injection paths

`FAIL` · critical · owner: Security engineer · tier 1

Four queries are built by string interpolation of request data, so signup, login, forgot-password and invoice lookup are all injectable.

Evidence: `examples/vibe-coded-app/server.js:16`, `examples/vibe-coded-app/server.js:23`, `examples/vibe-coded-app/server.js:30`, `examples/vibe-coded-app/server.js:35`

**Fix:** Use parameterised queries ($1 placeholders) everywhere.

## Important (high)

#### IDN-05 · Sessions time out (idle and absolute) and all sessions for one user can be revoked

`FAIL` · high · owner: Backend engineer · tier 1

The 'token' returned by /login is the raw user id: it never expires and cannot be revoked, and it can be guessed.

Evidence: `examples/vibe-coded-app/server.js:25`

**Fix:** Issue signed, expiring session tokens or use a hosted auth provider. This is an auth rewrite, so ask an experienced engineer to review it.

#### SEC-10 · CORS is restricted to known origins (not "*" with credentials or reflected origin)

`FAIL` · high · owner: Security engineer · tier 1

CORS is configured to allow every origin.

Evidence: `examples/vibe-coded-app/server.js:8`

**Fix:** Allow only your own front-end origins.

## Needs a human to confirm

These could not be established from the repository. Answer each with evidence (a screenshot, a document, a console setting) and record it with `/ai-consultant:consult-evidence`.

#### AUT-06 · Admin and internal endpoints are separated from the public surface and protected independently

`NOT AUDITED` · critical · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Admin routes behind their own authentication, ideally network-restricted. Check for debug, seed, or "make me admin" endpoints left in.

#### DAT-07 · Automated backups run at least nightly

`UNKNOWN` · critical · owner: DevOps engineer · tier 1

No backup configuration is visible in the repository.

**To confirm:** Show the database provider's backup setting and the date of the latest backup.

#### DAT-08 · A restore from backup has been performed and timed, and the steps are written down

`NOT AUDITED` · critical · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Look for a restore runbook or drill record. Without one the status is unknown at best.

#### OPS-04 · Every account, domain, repository, cloud project and vendor login belongs to the company, not to the person who built the prototype

`NOT AUDITED` · critical · owner: Tech lead · tier 1

**To confirm:** Show evidence for: Ask the founder to list registrar, DNS, cloud, git hosting, payment provider, app stores and email provider with the owning account for each. Personal emails as owner on any of them are a finding.

#### SEC-02 · Every key an AI assistant ever pasted into a config file, chat or prompt has been rotated

`UNKNOWN` · critical · owner: Security engineer · tier 1

Whether any real key was ever pasted into an AI chat or committed cannot be seen from code.

**To confirm:** When were the Stripe, database and email keys last rotated, and were any pasted into an AI tool?

#### SEC-05 · User input is sanitised or encoded everywhere it is rendered, preventing XSS

`NOT AUDITED` · critical · owner: Security engineer · tier 1

**To confirm:** Show evidence for: dangerouslySetInnerHTML, v-html, innerHTML, |safe, unescaped template output, markdown rendering without a sanitiser, user-supplied URLs in href.

#### SEC-24 · Storage buckets are private by default and user files are served by short-lived signed URLs or an authorised endpoint

`NOT AUDITED` · critical · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Look at bucket policies and ACLs in IaC, SDK calls that set public-read, and code that builds permanent public URLs for private user documents. Fail on public buckets that hold customer files, signed URLs that live for days or are returned to anyone without an ownership check, and guessable object keys with no authorisation in front. Public assets by design (marketing images) are fine if they live in a separate bucket. Say unknown when only the cloud console could settle it.

#### AUT-08 · Mass assignment is prevented; clients cannot set role, tenant, price or owner fields

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Handlers that spread request bodies straight into ORM create/update calls.

#### CMP-09 · The terms of service and privacy policy match what the code actually collects, shares and retains

`NOT AUDITED` · high · owner: Lawyer · tier 1

**To confirm:** Show evidence for: Compare the policy text to analytics, trackers, third-party SDKs, stored fields, and retention behaviour. Flag mismatches for a lawyer.

#### DAT-01 · The schema was designed (keys, foreign keys, constraints, types), not improvised table by table

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Review schema and migrations. Missing foreign keys, NOT NULL, unique constraints, JSON blobs holding relational data, duplicated columns across tables, stringly-typed enums.

#### DAT-02 · Migrations are versioned, run forward in CI and have a rollback path

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: A migration tool in use (not "sync schema on boot"), down migrations or a documented expand/contract approach, and migrations run in the deploy pipeline.

#### DAT-04 · Indexes exist for real query paths (filters, joins, sorts, foreign keys)

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Match WHERE/ORDER BY/JOIN columns in the code to indexes in the schema. Flag foreign keys without indexes and unbounded table scans.

#### DAT-05 · N+1 queries and unbounded result sets are controlled

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Loops that query per row, ORM lazy loading in list endpoints, endpoints that return every row.

#### DAT-06 · Connection pooling is configured so a traffic spike cannot exhaust the database

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Pool size settings, a pooler (PgBouncer, RDS Proxy, provider pooler) for serverless or multi-instance deployments, sensible timeouts.

#### DAT-20 · Writes that must succeed or fail together run inside a database transaction

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Find flows with more than one write (create order and decrement stock, move money, create user and workspace). Fail on separate awaited writes with no transaction, a transaction opened but the writes issued on a different connection, and external calls (email, payment, AI) made inside an open transaction. Look at what the customer would see if the second write failed.

#### DAT-21 · Two people or jobs updating the same record cannot silently overwrite or double-spend each other

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Look for read-modify-write sequences on balances, stock, counters, seats, coupons and status fields. Passes with atomic updates (UPDATE ... SET n = n - 1 WHERE n > 0), a version column with optimistic checks, row locks (SELECT FOR UPDATE) or a unique constraint. Fail on check-then-insert with no unique index, increments computed in application memory, and "if not used then mark used" without a lock.

#### IDN-01 · Login and signup handle plus-addressing, case, Unicode and whitespace in emails consistently

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Find where emails are normalised. Same normalisation on signup, login, reset and invite? Unique index on the normalised value? Does "a+b@x.com" survive validation and email delivery?

#### IDN-07 · Lockout and throttling stop attackers without letting them lock out real users at will

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Progressive delays or captcha beat hard lockout. If hard lockout exists, is there a self-service unlock, and can an attacker lock a known victim out indefinitely?

#### IDN-09 · Email is verified before it is trusted for access, invites or account linking

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Social login or SSO that links to an existing account by unverified email enables account takeover. Check the linking logic.

#### IDN-13 · Access tokens are signed, verified and short-lived, and refresh tokens rotate and can be revoked

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Find where JWTs or API tokens are issued and verified. Fail on verification skipped or decode-only calls, the "none" algorithm or an algorithm taken from the token header, a hard-coded or weak signing secret, access tokens that live for days, tokens kept in localStorage where XSS can read them, and refresh tokens that never rotate or cannot be revoked after logout or a password change. Provider-managed sessions (Auth0, Clerk, Supabase) are a pass if the app verifies their tokens with the provider's library and does not re-implement it.

#### IDN-14 · OAuth and social login uses a state parameter, PKCE and exact redirect URIs

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Look at the authorization-code flow the app implements or configures. Fail on a missing or unchecked state value (login CSRF), public clients without PKCE, wildcard or prefix-matched redirect URIs, tokens returned in URL fragments or query strings, and linking a social account to an existing account by email without a verified-email check. Not applicable if login is fully delegated and the app configures no redirect URIs of its own.

#### IDN-15 · Session cookies are HttpOnly, Secure and SameSite, and the session ID changes at login

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Find the cookie options for the session or auth cookie. Fail on a missing HttpOnly, Secure or SameSite flag, a session ID that stays the same across login or privilege change (session fixation), session IDs in URLs, and long-lived cookies with no server-side expiry. Framework defaults count if the config does not override them.

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

#### INF-22 · Databases and internal services are not reachable from the public internet

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Read security groups, firewall rules, compose files, Kubernetes services and managed-database settings. Fail on 0.0.0.0/0 open to database, cache or admin ports (5432, 3306, 6379, 27017, 9200, 22), databases with public endpoints and no allow-list, and containers publishing internal ports to the host. Private subnets with only the load balancer public is the pass. Say unknown when no infrastructure code exists.

#### INF-27 · Queue and job consumers are idempotent, because the same message will sometimes arrive twice

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Read the job and queue handlers. Passes with a unique key or processed-message table checked before the side effect, or operations that are naturally repeatable. Fail on handlers that send an email, charge, create a record or call a partner each time they run with no duplicate check, and on handlers that acknowledge before the work is done. "Exactly once" claims from the broker do not count as evidence.

#### API-09 · Every outbound third-party call has a timeout, a circuit breaker or fallback, and an owner for when the vendor is down

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: HTTP client defaults, failure handling in user-facing paths, graceful degradation of non-critical vendors (analytics, chat widgets).

#### API-10 · WebSocket and server-sent event connections are authenticated, authorised per message and origin-checked

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Find the socket or event-stream endpoints. Fail on connections accepted without authentication, channel or room subscriptions that trust a client-supplied ID without an ownership check, no Origin check (cross-site WebSocket hijacking), tokens in the URL that end up in logs, and no limits on connections, message size or message rate. Not applicable if the app has no real-time channels.

#### MNT-02 · Every change gets a human code review before merge

`NOT AUDITED` · high · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Branch protection and PR history. Repos with direct pushes to main and AI-authored commits that nobody read are a finding.

#### MNT-13 · Errors are handled deliberately, with no swallowed failures, unhandled rejections or half-finished operations

`NOT AUDITED` · high · owner: Senior engineer · tier 1

**To confirm:** Show evidence for: Grep for empty catch blocks, catch blocks that only log and continue, promises with no await or catch, missing global handlers for unhandledRejection or uncaughtException, and async handlers whose errors never reach the framework error handler. In the money and data paths, check that a failure partway through leaves the system in a consistent state and that the customer is told. Tolerate deliberate, commented ignores.

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

#### PAY-02 · Double-submits (four clicks on "Pay") are deduplicated on the server and disabled in the UI

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Server-side dedupe on the write path, not just a disabled button.

#### SEC-03 · Every installed package exists, is the one intended, and is not a look-alike (hallucinated or typosquatted names)

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Review manifests and lockfiles. For each unfamiliar dependency check name spelling, publisher, age, download count and repository link. Flag packages with a handful of downloads that do something trivial.

#### SEC-04 · Dependencies are scanned automatically and the lockfile is committed

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: Dependabot/Renovate, npm audit / pip-audit / OSV in CI, lockfile present, and install uses the lockfile (npm ci).

#### SEC-07 · State-changing requests are protected against CSRF

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: CSRF tokens or SameSite cookies plus origin checks, for cookie-authenticated apps. Bearer-token-only APIs are lower risk.

#### SEC-08 · SSRF, open redirects and path traversal are blocked

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Server-side fetch of user-supplied URLs (webhooks, image import, link preview) without an allowlist or private-range block. Redirect targets taken from query parameters. File paths built from input.

#### SEC-12 · Data is encrypted in transit everywhere and at rest in databases, buckets and backups

`NOT AUDITED` · high · owner: DevOps engineer · tier 1

**To confirm:** Show evidence for: TLS-only connections including database and internal services, HTTP redirected, storage encryption flags in IaC or provider settings, field-level encryption for the most sensitive columns.

#### SEC-13 · Everyone and everything, including AI coding agents, holds least-privilege credentials, and none holds production write access by default

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: IAM roles, shared root credentials, database superuser in the app connection string, production credentials in a developer's or agent's local environment. Separate read-only credentials for investigation.

#### SEC-14 · Logs record who did what and never record passwords, tokens, card numbers or other sensitive fields

`NOT AUDITED` · high · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Logging of full request bodies, headers (Authorization, Cookie), ORM query logging with bound parameters, error reporters capturing PII. Redaction in place.

#### SEC-15 · Production errors do not leak stack traces, SQL, or internals; debug mode is off

`NOT AUDITED` · high · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: DEBUG=true defaults, verbose error handlers, GraphQL introspection and Swagger exposed in production, default admin credentials.

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

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: timestamp without time zone, local-time Date parsing, reminders computed in server local time, DST handling.

#### DAT-13 · Text handling survives apostrophes, accents, emoji and right-to-left scripts in every field

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: UTF-8 (utf8mb4) end to end, no ASCII-only regex name validation, no length truncation by bytes, no naive SQL string building. Check PDFs and emails too.

#### DAT-16 · List endpoints use pagination that stays fast and correct deep into the result set

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: OFFSET pagination on large tables, no max page size, no stable sort key. Cursor/keyset pagination is the fix.

#### DAT-22 · Foreign-key delete behaviour is chosen deliberately, so one delete cannot wipe unrelated data

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Read the ON DELETE rules and ORM cascade settings. Fail on CASCADE from long-lived records (customers, workspaces, invoices) down to financial or audit records, ORM cascades that delete more than intended, and delete behaviour that was simply left at the default. Restrict or soft delete is the safer choice for anything the business must keep.

#### IDN-08 · Signup, login and reset responses do not reveal whether an account exists

`NOT AUDITED` · medium · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Compare responses and timing for known and unknown emails on reset and login.

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

#### SEC-11 · Security headers are set on every response (CSP, HSTS, X-Content-Type-Options, frame protection, referrer policy)

`NOT AUDITED` · medium · owner: Security engineer · tier 1

**To confirm:** Show evidence for: Middleware, framework config, or CDN/edge rules. Judge by what is configured, and suggest curl -I against the live site for confirmation.

#### SEC-22 · Request body size limits and request timeouts are set, so one oversized request cannot take the app down

`NOT AUDITED` · medium · owner: Backend engineer · tier 1

**To confirm:** Show evidence for: Look for body-parser or framework limits, reverse-proxy or platform limits, and server timeouts. Fail on unlimited JSON or text bodies, no cap on array or page-size parameters, regular expressions run on unbounded input, and handlers with no timeout at all. Upload size limits alone (SEC-09) do not count.

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
| Security engineer | 24 | 10 | AUT-01 Every route, API handler, server action and job enforces authorization |
| Backend engineer | 27 | 4 | DAT-11 All input is validated on the server with a schema, not only in the fo |
| DevOps engineer | 13 | 3 | DAT-07 Automated backups run at least nightly |
| Tech lead | 3 | 1 | OPS-04 Every account, domain, repository, cloud project and vendor login belo |
| Senior engineer | 7 | 0 | MNT-02 Every change gets a human code review before merge |
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
- tier 2 · INF-26 · Terraform and other infrastructure state is stored remotely, locked and encrypted, never committed
- tier 2 · MNT-05 · The framework and runtime versions still receive security patches
- tier 2 · OBS-04 · Alerts page a human, on symptoms that matter, and are tuned until they stop paging for nothing
- tier 2 · OBS-07 · There is an on-call rotation, and a named person who picks up
- tier 2 · OBS-11 · A written incident response plan says who leads, how customers are told and who handles a breach notification
- tier 2 · PAY-05 · Currency, rounding and tax rules are defined for every country sold into
- tier 2 · PAY-06 · Sales tax and VAT are calculated, collected and reported correctly where required
- tier 2 · PAY-09 · Refunds, credits and partial refunds work and keep revenue records consistent
- tier 2 · TST-05 · Load testing has been done at realistic data volume before launch campaigns
- tier 2 · CMP-11 · A DPA template and sub-processor list are available for business customers
- tier 2 · CMP-13 · Dependency and asset licences are known and compatible with how the product is distributed and sold
- tier 2 · DAT-10 · Deletes of user-visible records are soft (recoverable) or otherwise reversible
- tier 2 · DAT-17 · Customers can export their data in a usable format without engineering help
- tier 2 · DAT-18 · Imports validate, report row-level errors and survive odd encodings, delimiters and huge files
- tier 2 · INF-05 · Deploys are zero-downtime (health checks, rolling or blue/green, graceful shutdown, backwards-compatible schema changes)
- tier 2 · INF-06 · Feature flags let you ship code without shipping the feature
- tier 2 · INF-07 · Autoscaling or enough headroom exists for the predictable spike
- tier 2 · INF-12 · Jobs that exhaust their retries land in a dead-letter queue that someone is alerted about
- tier 2 · INF-14 · Caching has a stated invalidation strategy and cannot serve one user's data to another
- tier 2 · INF-23 · App servers keep no state locally, so any instance can be replaced or added at any time
- tier 2 · INF-24 · Container images are small, run as a non-root user and are scanned before release
- tier 2 · INF-25 · Memory and CPU are bounded and monitored, and nothing in the code grows without limit
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
- tier 2 · PAY-14 · Chargebacks and disputes are detected, answered with evidence and tracked against revenue
- tier 2 · SEC-18 · A vulnerability disclosure process exists (security.txt, a monitored security@ inbox, a response SLA)
- tier 2 · SEC-19 · There is a documented plan for a stolen laptop or leaked credential (disk encryption, remote wipe, revocation steps)
- tier 2 · SEC-20 · Webhook endpoints, public APIs and forms are protected against automated abuse (bot protection, quotas)
- tier 2 · SEC-21 · Secrets, tokens and signatures are compared in constant time
- tier 2 · SEC-23 · A threat model for the main flows exists and is revisited when features change
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
