# Changelog

## 0.2.0 — 2026-11-17

Sessions
- Session rows are sealed with AES-256-GCM; row ids and user keys are HMACs, so
  the table holds no usable cookie value or token. New required option
  `sessionSecret`. Rows from 0.1.x are deleted on first read.
- Sessions are revalidated with a refresh-token grant after `revalidateAfterMs`
  (default 10 minutes); a refusal (revoked, suspended, deleted) drops the
  session, an unreachable Logto keeps it. Refreshes of one session are
  serialized in-process.
- Default scopes `email profile offline_access roles`; new `resources` option
  and `getAccessToken(request, resource?)`.
- `getSession(request)` returns `{ user, claims, sub }`; `revokeUser(sub)` drops
  every session of a user.
- Sign-out answers `POST` from the app's own origin only (405 / 403 otherwise)
  and redirects with 303.
- `__Host-` cookies are deleted with `Secure` (and the other original
  attributes); browsers ignored the old deletion.
- `requestTimeoutMs` (default 8 s) for every call to Logto.
- `getUser`/`getSession` accept Node-style headers as well as a fetch Request.

Stores
- `SessionStore` stores opaque sealed blobs and gains `dropUser(userKey)`.
- `sqliteSessionStore` adds a `user_key` column (created or migrated with
  `createTable: true`) and accepts `node:sqlite` as well as better-sqlite3.

New entry points
- `./webhook`: `createLogtoWebhookHandler`, `readLogtoWebhook`,
  `verifyLogtoSignature` (HMAC-SHA256 of the raw body, constant-time).
- `./bearer`: `createBearerVerifier` for access tokens of an API resource.
- `./handle`: the shared handle rule `^[a-z_][a-z0-9_]{2,19}$`, the reserved
  list, `handleFromClaims`, `displayHandle`, `fallbackHandle`, `suggestHandle`.
- `./testing`: `startFakeLogto`, a local stand-in for Logto.

Packaging
- Ships compiled JavaScript and declarations in `dist/`.
- `@logto/node` is an optional peer (`>=3.1.0`); only the root import needs it.

## 0.1.0

First extraction of the Traditional Web sign-in from mapswitch.
