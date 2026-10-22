# Supabase playbook

Supabase exposes your database over a REST API using a public "anon" key that ships to every browser. Row Level Security (RLS) is the only thing between that key and your data. Most Supabase incidents in vibe-coded apps are a missing or permissive policy.

Maps to: AUT-01, AUT-02, AUT-03, SEC-01, SEC-05, SEC-09, SEC-12, IDN-05, DAT-07, DAT-09, INF-01

## SB-1 RLS is enabled on every table in an exposed schema
Maps to: AUT-02, AUT-03
- Look for: in `supabase/migrations/*.sql`, every `create table` in `public` (or any exposed schema) needs a matching `alter table ... enable row level security`. List each table and whether it has it.
- Fail when: any table holding user or tenant data lacks RLS. That table is readable and writable by anyone holding the anon key from your own JavaScript bundle.
- Unknown when: tables were created in the dashboard and are not in migrations. Ask the founder to run the Supabase Security Advisor, or `select tablename, rowsecurity from pg_tables where schemaname = 'public';`, and show the result.
- Fix: enable RLS on every table, then add explicit policies. A table with RLS and no policies is deny-all, which is the safe default.

## SB-2 Policies actually restrict rows
Maps to: AUT-02, AUT-03, AUT-05
- Look for: `using (true)` or `with check (true)` on tables with non-public data; policies that only check `auth.role() = 'authenticated'` (any signed-in user sees everyone's rows); multi-tenant tables whose policies do not compare against the tenant or owner column; `for all` policies with no `with check`.
- Fail when: authorization depends on `auth.jwt() -> 'user_metadata'`. Users can edit their own `user_metadata`, so that is a privilege-escalation hole. Roles belong in `app_metadata` or a server-controlled table.
- Fix: scope by `auth.uid() = user_id`, or a membership lookup for tenants. Separate `select`, `insert`, `update` and `delete` policies.

## SB-3 The service_role key never reaches a browser
Maps to: SEC-01, AUT-01
- Look for: `service_role`, `SUPABASE_SERVICE_ROLE_KEY` in client code, in any variable prefixed `NEXT_PUBLIC_`, `VITE_` or `EXPO_PUBLIC_`, or in a committed `.env`.
- Fail when: found anywhere that ships to the client or to git. It bypasses all RLS. Tell the founder to rotate it (Project Settings, API) immediately.
- Note: the anon key and project URL are designed to be public. Do not flag those.

## SB-4 Views, functions and RPC do not bypass RLS
Maps to: AUT-02, AUT-03, SEC-06
- Look for: views in `public` without `security_invoker = true` (they run as their owner and skip RLS); `security definer` functions without `set search_path = ''`; functions callable via `rpc()` that take a user id as an argument instead of using `auth.uid()`; default `grant execute ... to anon`.
- Fail when: a definer function or view returns data across users or tenants to a caller that should not see it.

## SB-5 Storage buckets and policies
Maps to: SEC-09, SEC-24, AUT-02
- Look for: buckets created with `public = true` that hold private files (invoices, IDs, medical documents); missing policies on `storage.objects`; policies that do not scope the object path to the user or tenant; no file size or MIME limits on buckets.
- Fix: private buckets with signed URLs, policies keyed on `(storage.foldername(name))[1] = auth.uid()::text` or tenant id.

## SB-6 Auth configuration
Maps to: IDN-05, IDN-08, IDN-09, IDN-06
- Look for in `supabase/config.toml`: `enable_confirmations = false` for email (unverified emails can sign up and be trusted), `enable_signup = true` when the product is invite-only, very long `jwt_expiry`, MFA not enabled for staff. Hosted-project settings are not in the repo, so these may be `unknown`: ask for a screenshot of Authentication settings.
- Rate limits for auth endpoints exist on the platform but their values are configurable. Ask rather than assume.

## SB-7 Edge Functions authenticate their callers
Maps to: AUT-01, API-01
- Look for: `[functions.<name>] verify_jwt = false` in `config.toml`, and functions under `supabase/functions/` that never read the Authorization header. Webhook receivers legitimately disable JWT verification but must then verify a provider signature.

## SB-8 Backups and recovery depend on the plan
Maps to: DAT-07, DAT-08, DAT-09
- Backup and point-in-time-recovery availability depend on the Supabase plan and add-ons. Do not assume either way. Mark `unknown` and ask which plan the production project is on and what the Database, Backups page shows. A restore test is still required.

## SB-9 Prototype and production share a project
Maps to: INF-01, TST-06
- Look for: one set of keys used in local, preview and production, seed scripts pointing at the live project, no `supabase/migrations` history (schema edited by hand in the dashboard).
