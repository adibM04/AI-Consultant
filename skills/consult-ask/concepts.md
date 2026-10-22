# Concepts the consultant can explain

Reference for `consult-ask`. Three parts: where a concept is already checked, concepts that are **not needed yet** (with the trigger for when they are), and plain-language explanations of ideas founders get told about. Explain in founder language, say "when it actually matters", and never tell a founder a launch-stage gap exists because of a scale-only concept. If the founder's own repository shows the problem, answer from the code and cite `path:line`, not from this file.

## Where a concept is checked

Use the item's `check`, `tier` and `severity` to answer. Concept, then item id.

- **Web attacks:** SQL injection SEC-06, XSS SEC-05, CSRF SEC-07, CORS SEC-10, SSRF and path traversal SEC-08, clickjacking, CSP, HSTS and security headers SEC-11, request size limits SEC-22, timing attacks SEC-21, bot protection SEC-20, file upload validation SEC-09, supply chain and hallucinated packages SEC-03 and SEC-04, lockfiles SEC-04, threat modeling SEC-23.
- **Access:** IDOR AUT-02, mass assignment AUT-08, server-side authorisation AUT-01, row-level security AUT-03, RBAC AUT-05, least privilege SEC-13, public buckets and presigned URLs SEC-24.
- **Secrets:** secrets management, `.env` in `.gitignore` and secret scanning SEC-01, key rotation SEC-02, shared credentials OPS-06.
- **Login:** password hashing, salting, bcrypt and Argon2 IDN-03, JWT expiry and refresh tokens IDN-13, OAuth 2.0 IDN-14, OpenID Connect IDN-10, session fixation and cookie flags IDN-15, session timeout IDN-05, MFA IDN-04, brute force IDN-06 and IDN-07, account enumeration IDN-08.
- **Database:** indexes, full table scans DAT-04, N+1 queries and ORM lazy loading DAT-05, connection pooling DAT-06, migrations and down migrations DAT-02 and DAT-03, transactions DAT-20, race conditions and locking DAT-21, cascading deletes DAT-22, soft deletes DAT-10, normalisation, foreign keys and unique constraints DAT-01, cursor pagination DAT-16, backups DAT-07, testing restores DAT-08, point-in-time recovery DAT-09, money as floats DAT-14, time zones and daylight saving DAT-12, Unicode and encodings DAT-13, schema validation DAT-11.
- **Reliability:** retries, jitter and retry storms INF-11, cascading failures and graceful degradation API-09, queues and background jobs INF-10, dead letter queues and poison messages INF-12, idempotent consumers INF-27, caching and TTLs INF-14, CDN and cache headers INF-08, health checks, graceful shutdown and blue-green INF-05, stateless services INF-23, memory leaks and OOM kills INF-25, failover and multi-region INF-20, disaster recovery INF-19, autoscaling INF-07, load testing TST-05, leader election INF-13.
- **Network and delivery:** VPCs, subnets, firewalls and security groups INF-22, infrastructure as code INF-02, Terraform state INF-26, containers INF-24, environments INF-01, rollbacks INF-04, feature flags INF-06, DNS and TLS expiry INF-09, email authentication INF-15, bounces INF-16, cost alerts and egress fees INF-18.
- **APIs and real time:** webhooks API-01 and API-02, API versioning and backward compatibility API-03, status codes and HTTP methods API-11, WebSockets and server-sent events API-10.
- **Observability:** structured logs, log levels and correlation IDs OBS-01, error tracking OBS-02, uptime OBS-03, alert fatigue OBS-04, tracing and OpenTelemetry OBS-06, on-call OBS-07, runbooks OBS-08, postmortems OBS-09, incident response OBS-11.
- **Testing and code health:** unit, integration, end-to-end and contract tests TST-01 to TST-03, regression tests TST-04, review of large AI diffs MNT-02, dead code MNT-06, technical debt MNT-04 and MNT-08, error handling and unhandled rejections MNT-13.
- **Law and money:** GDPR CMP-05, PII CMP-09 and SEC-14, audit logs CMP-04, data residency CMP-06, SOC 2 CMP-07, PCI DSS PAY-03, cookie consent CMP-10, software licences CMP-13, chargebacks PAY-14.
- **AI features:** prompt injection AIF-01, evals AIF-04, model version pinning AIF-06, context windows AIF-11.

## Not needed yet

Say it plainly: "You do not need this yet, and building it early will slow you down." Then give the trigger. None of these may be reported as a gap at launch stage.

| Concept | What it is | Look at it when |
|---|---|---|
| Read replicas, replication lag | Extra copies of the database that serve reads | Reads, not writes, are what slows the primary, and queries and indexes are already tuned |
| Sharding, partitioning, hot partitions | Splitting one huge table or database across machines or pieces | A single table is hundreds of millions of rows or one database can no longer fit the load after tuning |
| Postgres VACUUM | Cleanup of dead rows | Tables bloat or autovacuum falls behind. Managed databases mostly handle it |
| Change data capture, outbox pattern | Streaming database changes to other systems reliably | Two systems must stay in step and "write then publish" has already lost an event |
| Raft, leader election, split brain, quorums, distributed locks | How many machines agree on who is in charge | You run your own replicated database or coordination service. Use a managed one instead |
| Consistent hashing, Bloom filters | Spreading keys over machines, cheap membership tests | A cache or storage tier is spread over many nodes |
| Two-phase commit, CQRS, event sourcing | Patterns for coordinating several data stores | A real business need for an audit-grade history or separate read and write models, not before |
| Backpressure, load shedding, bulkheads | Protecting a busy system by refusing or isolating work | Queues grow without bound under real traffic and timeouts alone no longer protect you |
| Cache warming | Filling caches before traffic arrives | Cold caches after a deploy cause a visible slowdown |
| Kafka consumer groups, partition keys | Scaling a message stream over many readers | You operate Kafka at volume. A simple queue is enough until then |
| Service mesh, ingress controllers | Traffic control between many services | Dozens of services on Kubernetes. A monolith or a handful of services does not need one |
| Availability zones | Separate data centres in one region | The contract promises uptime a single zone cannot give. Many managed services already do it |
| SLOs, error budgets | Reliability targets and how much failure is acceptable | You have customers who depend on uptime and enough traffic to measure it |
| Chaos engineering | Breaking things on purpose to learn | Basic monitoring, failover and restores are already boring |
| GitOps | The repository as the source of truth for deployments | Several environments and people changing infrastructure. Plain infrastructure as code first |
| Canary releases | Releasing to a small share of users first | Releases are frequent and a bad one is expensive. Feature flags cover most needs |
| Pod disruption budgets | Kubernetes rules about how many copies stay up | You already run Kubernetes in production |

## Explaining the ideas

Each is a sentence or two to adapt, with when it actually matters.

**Data and consistency**
- **ACID.** A set of promises that a group of database changes either all happen or none do, and that once confirmed they stay. Matters whenever two or more writes belong together (DAT-20).
- **Isolation levels and deadlocks.** How much two people working at once can see of each other's half-done changes. Two jobs waiting on each other forever is a deadlock. Matters when you see sporadic "lock timeout" errors or double-spends; the usual fix is shorter transactions and locking rows in the same order.
- **CAP, eventual and strong consistency.** When data lives on several machines, during a network failure you must choose between answering with possibly stale data or refusing. Matters only once you run a distributed database. A single managed Postgres sidesteps it. "Eventual" means other copies catch up soon, not instantly.
- **Normalisation and denormalisation.** Store each fact once, versus copy it for faster reads. Normalise first. Copy only after measuring a slow query.
- **UUIDs versus auto-increment.** Counting IDs are guessable, so authorisation must not rely on them (AUT-02). Random IDs hide the count but are not a security control.
- **Full-text search.** The database can search words well enough for most products. A separate search engine matters when relevance ranking and typo tolerance are a product feature.
- **Materialized views.** A saved, precomputed query result. Matters for slow dashboards that can tolerate slightly old numbers.
- **EXPLAIN ANALYZE.** Asks the database how it ran a query. First tool for any slow query, and what an engineer will ask for.
- **Clock skew.** Servers disagree about the time by milliseconds to seconds, so never order events or expire tokens on timestamps from different machines without slack.
- **Hashing versus encryption.** Hashing is one-way (passwords). Encryption can be reversed with a key (data you must read back). Never encrypt a password you only need to verify.
- **Integer overflow, off-by-one errors, thread safety.** Rare in typical web code; relevant for counters that can pass 2 billion, loops over boundaries, and shared mutable state. Tests on edge values catch most of them.
- **Garbage collection.** Languages free memory automatically; pauses and leaks show up as slow spells. Matters when memory graphs climb steadily (INF-25).

**Messaging and caching**
- **Message ordering, at-least-once, exactly-once.** Queues usually deliver a message at least once, sometimes twice, sometimes out of order. Design handlers so repeats are harmless (INF-27). "Exactly once" is mostly marketing.
- **Thundering herd.** A popular cache entry expires and a thousand requests hit the database at once. Matters for hot pages; fix with locking the refill or staggering expiry.
- **Cache hit ratio, write-through versus write-back.** Share of requests answered from cache. Write-through saves to the store and cache together (safe); write-back saves to cache first (fast, can lose data).
- **Redis eviction.** When Redis is full it deletes data. Fine for a cache, damaging for queues or sessions stored in the same Redis. Use separate instances or a no-eviction policy.
- **ETags.** A fingerprint that lets browsers skip downloading unchanged content.

**Networking**
- **DNS propagation.** Record changes take minutes to days to reach everyone; lower the TTL before a planned move.
- **Keep-alive, HTTP/2, compression.** Standard features your host or CDN normally turns on. Verify rather than build.
- **Long polling, gRPC, Protocol Buffers.** Alternatives to WebSockets and JSON. gRPC and protobuf help when many internal services talk to each other. Not needed for a typical web app. OpenAPI specs are worth having if other people integrate with your API.
- **Latency versus throughput.** How long one request takes versus how many per second. A system can be good at one and bad at the other.
- **NAT gateways, egress fees.** Private servers reaching the internet go through a NAT gateway, and data leaving the cloud costs money. Matters when the monthly bill has a line nobody can explain (INF-18).
- **Single points of failure, RTO and RPO, SLAs.** One thing whose failure takes everything down. RTO is how long you can be down, RPO how much data you can lose. An SLA is the uptime you promise a customer in a contract. Agree these numbers before signing (INF-19, INF-20).
- **Horizontal versus vertical scaling, cold starts, capacity planning.** More machines versus a bigger one. Serverless functions start slowly after idle. Capacity planning is estimating next quarter's load from real numbers.

**Observability and engineering**
- **p99 latency.** The time the slowest one percent of requests take. Averages hide the pain; watch p95 or p99 for the core flows.
- **Metrics cardinality.** Putting user IDs or URLs into metric labels explodes cost. Keep labels to a handful of values.
- **Log levels, profiling, flame graphs.** Use ERROR for what needs a human, INFO for the story. A profiler and a flame graph show where time goes; use them before guessing.
- **Semantic versioning, reproducible builds.** Version numbers that say whether an upgrade can break you. Reproducible builds give the same output from the same input, which the lockfile and a pinned base image mostly deliver.
- **Flaky tests, mocking, property-based testing, fuzzing.** A flaky test fails at random and teaches the team to ignore failures; fix or delete it. A test that only checks mocks proves nothing about real behaviour. Property-based tests and fuzzers generate odd inputs for parsers and money maths.
- **Debouncing.** Wait until the user stops typing before acting. Protects search boxes; double-submit on payment is a separate server-side issue (PAY-02).
- **Big O notation.** How work grows with data. It matters when a loop inside a loop runs over thousands of rows; spot it as a page that gets slower each month.
- **Real-time streaming of AI answers.** Show tokens as they arrive. Keep timeouts and cancellation, and do not hold database connections open while a model streams.
- **12-factor apps.** Configuration in the environment, state outside the app, logs to stdout. A good checklist for INF-21 and INF-23.
