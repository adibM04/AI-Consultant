# Firebase playbook

Firebase apps talk to the database straight from the browser, so security rules are the entire authorization layer. There is no server in between to save you.

Maps to: AUT-01, AUT-02, AUT-03, AUT-08, SEC-01, SEC-09, SEC-20, INF-18, DAT-01, DAT-04, DAT-11

## FB-1 Rules are not open
Maps to: AUT-01, AUT-02
- Look for in `firestore.rules`, `storage.rules`, and Realtime Database `database.rules.json`: `allow read, write: if true;`, `".read": true`, or the "test mode" default `allow read, write: if request.time < timestamp.date(...)`, which silently becomes deny-all (breaking the app) or is extended by hand, usually to "never".
- Fail when: any rule gives unauthenticated users access to non-public data. Also fail when a catch-all `match /{document=**}` grants access.

## FB-2 Authenticated is not authorised
Maps to: AUT-02, AUT-03
- Look for: rules that only test `request.auth != null`. Any signed-up user can then read every other user's documents.
- Fix: compare ownership (`request.auth.uid == resource.data.ownerId`) or tenant membership on reads, and on writes (`request.resource.data.ownerId == request.auth.uid`) so ownership cannot be reassigned.

## FB-3 Rules validate what is written
Maps to: DAT-11, AUT-08, DAT-01
- Look for: no checks on `request.resource.data` field names, types or sizes. Clients can add `role: "admin"`, `isPaid: true`, or arbitrarily large documents. Firestore has no enforced schema, so rules and server code are the only schema. Also check that `update` rules restrict which fields can change.

## FB-4 Roles are not stored where users can edit them
Maps to: AUT-05, AUT-08
- Look for: a `role` or `isAdmin` field in a user document the user can write. Use custom claims set from trusted server code (Admin SDK) and read them from `request.auth.token`.

## FB-5 Admin credentials and server keys stay out of the repo
Maps to: SEC-01, SEC-02
- Look for: files with `"type": "service_account"`, `serviceAccountKey.json`, `GOOGLE_APPLICATION_CREDENTIALS` pointing at a committed path, Admin SDK initialised in client code.
- Note: the Firebase web config (`apiKey`, `authDomain`, `projectId`) is public by design. Do not flag it as a leaked secret. Rules and App Check are what protect the project.

## FB-6 Cloud Functions check the caller
Maps to: AUT-01, SEC-20
- Look for: `onCall` handlers that never check `request.auth` (v2) or `context.auth` (v1); `onRequest` HTTP functions that perform privileged work with no token verification (`verifyIdToken`) and no webhook signature check; `cors: true` with credentials.

## FB-7 Abuse and cost controls
Maps to: INF-18, SEC-20, AIF-03
- Look for: App Check not enabled for Firestore, Storage, Functions; no budget alerts on the Blaze plan (a client-side loop or scraper can run up the bill); expensive queries without limits; storage bucket allowing large uploads. Budget alerts live in the Google Cloud console, so mark `unknown` and ask for a screenshot.

## FB-8 Queries, indexes and shape
Maps to: DAT-04, DAT-16, DAT-05
- Look for: `getDocs(collection(...))` with no `limit()`, client-side filtering of whole collections, deeply nested subcollections where cross-user queries are needed later, `firestore.indexes.json` missing for composite queries. Unbounded reads are both a performance and a cost problem.

## FB-9 Backups
Maps to: DAT-07, DAT-08, DAT-09
- Firestore backups and point-in-time recovery are opt-in settings, not defaults. Nothing in the repo proves them. Mark `unknown` and ask for the scheduled-backup or PITR configuration.
