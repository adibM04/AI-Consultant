# Next.js playbook

Next.js blurs server and client code. The usual failures are secrets or data crossing that boundary, and "protected" pages whose underlying actions and API routes are not.

Maps to: AUT-01, AUT-02, AUT-03, AUT-06, AUT-08, SEC-01, SEC-05, SEC-08, SEC-10, SEC-11, SEC-15, INF-01, INF-14, INF-21, MNT-05

## NX-1 Secrets are not exposed to the browser
Maps to: SEC-01
- Look for: any variable prefixed `NEXT_PUBLIC_` whose name or value suggests a secret (`SECRET`, `SERVICE_ROLE`, `PRIVATE`, `TOKEN`, `PASSWORD`, `DATABASE_URL`, `sk_`); `.env`, `.env.local`, `.env.production` committed to git (check `.gitignore` and `git ls-files`, and history); server secrets imported in files marked `"use client"`.
- Note: publishable/anon keys and public project IDs are meant to be public.
- Fix: rename and rotate. Add `import "server-only"` to modules that touch secrets.

## NX-2 Every Server Action authorises itself
Maps to: AUT-01, AUT-02
- Look for: functions in files with `"use server"` or inline `"use server"`. Each exported action is a public POST endpoint callable by anyone, regardless of which page renders the button. Check that each one verifies the session and, for anything taking an id, that the record belongs to the caller.
- Fail when: authorization exists only in the page, layout or middleware.

## NX-3 Route Handlers and API routes authorise themselves, and middleware is not the only gate
Maps to: AUT-01, AUT-02, AUT-06
- Look for: `app/**/route.ts`, `pages/api/**`: session check, ownership check, input validation. Any route returning data by id without scoping.
- Also check: the Next.js version. CVE-2025-29927 allowed bypassing middleware-based authorization via a crafted header in unpatched versions (fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3). Anything using middleware as the sole auth layer on an unpatched version is critical. Verify the installed version in the lockfile.
- Fix: authorise in the data-access layer next to the query, and use middleware only as a convenience redirect.

## NX-4 Data passed to client components is minimal
Maps to: AUT-02, SEC-14
- Look for: server components passing whole ORM rows (password hashes, internal flags, other tenants' fields, emails) as props to client components. Props are serialised into the page HTML and visible in "view source".
- Fix: map to explicit DTOs.

## NX-5 Caching cannot leak one user's data to another
Maps to: INF-14, AUT-03
- Look for: `fetch` with default caching or `revalidate` on authenticated data, `unstable_cache` or `cache()` keyed without user or tenant, `force-static` on pages that render personalised content, CDN caching of responses that set cookies. Behaviour differs across major versions, so check the version's defaults rather than assuming.

## NX-6 Rendering untrusted content
Maps to: SEC-05
- Look for: `dangerouslySetInnerHTML`, markdown renderers without a sanitiser, user-supplied URLs in `href` or `src` (`javascript:`), unvalidated redirect targets in `redirect()` or `NextResponse.redirect`.

## NX-7 next.config and headers
Maps to: SEC-08, SEC-10, SEC-11, SEC-15
- Look for: `images.remotePatterns` or `domains` with wildcards (the image optimizer will fetch any host), no `headers()` block for CSP, HSTS, `X-Content-Type-Options`, frame protection; `productionBrowserSourceMaps: true`; `typescript.ignoreBuildErrors` or `eslint.ignoreDuringBuilds` set to true (build errors are being hidden).

## NX-8 Environments and deploys
Maps to: INF-01, INF-21, TST-06
- Look for: preview deployments (Vercel or similar) configured with production environment variables or the production database, no runtime validation of `process.env` at boot, different behaviour hard-coded on `NODE_ENV`.

## NX-9 Framework currency
Maps to: MNT-05, SEC-04
- Compare the `next` and `react` versions to current supported releases. Old majors stop receiving security fixes.
