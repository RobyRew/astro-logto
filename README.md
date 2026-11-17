# @robyrew/astro-logto

Logto for the RobyRew server apps, in one place: sign-in through the
self-hosted Logto IdP (`https://auth.robyrew.com`) as a *Traditional Web*
application, the shared `@handle` rule, a verified webhook receiver, and
bearer-token checks for an API resource.

| Import | What it is | Needs `@logto/node` |
|---|---|---|
| `@robyrew/astro-logto` | Server-side sessions: sign-in, callback, sign-out, `getUser` | yes |
| `@robyrew/astro-logto/sqlite` | `sqliteSessionStore` (better-sqlite3 or `node:sqlite`), `memorySessionStore` | no |
| `@robyrew/astro-logto/webhook` | HMAC-verified Logto webhooks | no |
| `@robyrew/astro-logto/bearer` | Access-token validation for an API resource (JWKS) | no |
| `@robyrew/astro-logto/handle` | The one handle rule and reserved-word list (also safe in browser code) | no |
| `@robyrew/astro-logto/testing` | A fake Logto on 127.0.0.1 for tests and local runs | no |

The package ships compiled JavaScript with type declarations: no `tsx`, no
Vite `ssr.noExternal`.

## Install

```
npm i github:RobyRew/astro-logto#v0.2.0 @logto/node
```

`@logto/node` is an optional peer: only the root import uses it.

## Sessions

```ts
// src/server/auth.ts
import { DatabaseSync } from 'node:sqlite'; // or better-sqlite3
import { createLogtoAuth } from '@robyrew/astro-logto';
import { sqliteSessionStore } from '@robyrew/astro-logto/sqlite';

export const auth = createLogtoAuth({
  endpoint: process.env.LOGTO_ENDPOINT!,          // https://auth.robyrew.com
  appId: process.env.LOGTO_APP_ID!,
  appSecret: process.env.LOGTO_APP_SECRET!,       // server env only
  sessionSecret: process.env.LOGTO_COOKIE_SECRET!, // openssl rand -base64 32
  publicOrigin: process.env.PUBLIC_SITE_URL!,     // https://calendar.robyrew.com
  cookieName: 'cg_sid',
  store: sqliteSessionStore(db, { createTable: true }),
  resolveUser: (claims) => upsertUserBySub(claims), // claims.username, picture, roles
});
```

```ts
export const GET: APIRoute = (ctx) => auth.signIn(ctx);   // /api/auth/sign-in?returnTo=/path
export const GET: APIRoute = (ctx) => auth.callback(ctx); // /api/auth/callback
export const ALL: APIRoute = (ctx) => auth.signOut(ctx);  // /api/auth/sign-out — POST only

const user = await auth.getUser(request);       // null when signed out; never throws
const session = await auth.getSession(request); // { user, claims, sub } | null
const token = await auth.getAccessToken(request, 'https://api.app.example'); // for an API resource
await auth.revokeUser(sub);                      // drop every session of one user
```

Sign out with a form, not a link:

```html
<form method="post" action="/api/auth/sign-out"><button>Sign out</button></form>
```

The response is a 303 to Logto's `end_session`, so a page CSP with
`form-action 'self'` must also list the Logto origin
(`form-action 'self' https://auth.robyrew.com`), or the browser blocks the
redirect.

Register in the Logto console (first-party Traditional Web app; a third-party
registration rejects the `profile`/`email` scopes and loops):

- Redirect URI: `${PUBLIC_SITE_URL}/api/auth/callback`
- Post sign-out redirect URI: `${PUBLIC_SITE_URL}/`

### Behaviour

| | |
|---|---|
| Scopes | `openid email profile offline_access roles` by default. `profile` carries `username`, `name`, `picture`; `roles` carries the global roles once the Console's ID-token toggle for roles is on. |
| Cookie | `__Host-<cookieName>` on https (Secure, Path=/, host-only); plain `<cookieName>` on http for local dev. `HttpOnly`, `SameSite=Lax`, 14 days. Deleted with the same attributes (a `__Host-` deletion without `Secure` is ignored by browsers). |
| At rest | Each row is sealed with AES-256-GCM (key from `sessionSecret`, row id as associated data). The row id is an HMAC of the cookie value and the user key an HMAC of the Logto `sub`, so the table and its backups hold no usable cookie or token. A row that does not open (0.1.x plaintext, another secret, tampering) is deleted. |
| Revalidation | After `revalidateAfterMs` (10 min), the next request runs a refresh-token grant. Logto refuses it once the user is suspended or deleted (it revokes their tokens), and the session is dropped. If Logto cannot be reached, the session is kept and retried a minute later. Refreshes of one session are serialized in-process (one process per store). |
| Session id | A new id on every sign-in, and another after the callback. An id planted before login never becomes an authenticated session. |
| Callback failure | Redirects to `/?auth_error=1` (configurable) and drops the session; it never restarts sign-in by itself. |
| `returnTo` | Local paths only (`/…`, not `//…` or absolute URLs). |
| Sign-out | `POST` only (405 otherwise), same-origin only (403 otherwise). Revokes the refresh token, drops the local session and ends the Logto SSO session. |
| Redirect URIs | Built from `publicOrigin`, because behind Traefik the request arrives as `http://…`. |

### Session stores

- `sqliteSessionStore(db, { table?, columns?, createTable? })` takes better-sqlite3
  or Node's `node:sqlite`. Columns: `id`, `data`, `created_at`, `expires_at`,
  `user_key`. `createTable: true` creates the table and adds `user_key` to a
  0.1.x table; without it, a table missing `user_key` is refused at startup.
- `memorySessionStore()` is for tests.
- Anything implementing `SessionStore` (`load`/`save`/`drop`/`dropUser`/`prune`)
  works, for example a Postgres table.

## Webhooks

One webhook per app in Logto (Console → Webhooks), pointing at the app's route,
with its own signing key in the app env (`LOGTO_WEBHOOK_SIGNING_KEY`).

```ts
// src/pages/api/hooks/logto.ts
import { createLogtoWebhookHandler } from '@robyrew/astro-logto/webhook';

const handler = createLogtoWebhookHandler({
  signingKey: process.env.LOGTO_WEBHOOK_SIGNING_KEY!,
  revokeUser: auth.revokeUser,                       // User.Deleted, suspension
  onUserDataUpdated: (user) => copyHandle(user.id, user.username),
});
export const POST: APIRoute = ({ request }) => handler(request);
```

The signature (`logto-signature-sha-256`, HMAC-SHA256 of the raw body, hex) is
checked in constant time; events older than 15 minutes are refused; a
`deliveryId` already handled is acknowledged without running callbacks again; a
callback that throws answers 500, which Logto retries.

## Bearer tokens for an API resource

```ts
import { createBearerVerifier, BearerError } from '@robyrew/astro-logto/bearer';

const api = createBearerVerifier({
  endpoint: process.env.LOGTO_ENDPOINT!,
  audience: process.env.LOGTO_API_RESOURCE!, // the resource indicator in Logto
  requiredScopes: ['read:things'],
});

try {
  const claims = await api.verifyRequest(request); // signature, iss, aud, exp
} catch (err) {
  if (err instanceof BearerError) return err.toResponse(); // 401 / 403 + WWW-Authenticate
  throw err;
}
```

## The handle rule

The Logto `username` is the one @handle across the apps. It is chosen and
changed only at `id.robyrew.com`; apps read it from the ID token.

```ts
import { handleFromClaims, displayHandle, checkHandle } from '@robyrew/astro-logto/handle';

handleFromClaims(claims);   // 'bob' | null — the username only when it passes the rule
displayHandle(claims);      // 'bob', or 'user-x2kq9m' (first six of sub) without one
checkHandle('@Bob');        // { ok: true, handle: 'bob' } | { ok: false, problem: 'reserved' | … }
```

- Rule: `^[a-z_][a-z0-9_]{2,19}$` (`HANDLE_PATTERN`).
- `RESERVED_HANDLES`: words no one can pick in self-service (every app's
  top-level routes, staff/system/brand words). `isHandle` accepts them, so a
  reserved handle an admin assigned is still displayed.
- A Logto username that breaks the rule (Logto's own sign-up form accepts
  `^[A-Z_a-z]\w*$`) is not lowercased into a handle: `handleFromClaims` returns
  null and the app shows the fallback.

## Testing against a fake Logto

```ts
import { startFakeLogto } from '@robyrew/astro-logto/testing';

const logto = await startFakeLogto(); // apps { 'app-id': 'app-secret' }, m2m { 'm2m-id': 'm2m-secret' }
logto.addUser({ id: 'u1', username: 'alice', roles: ['moderator'] });
// endpoint: logto.endpoint — OIDC (PKCE, refresh, client_credentials), JWKS,
// /api/users (Management API slice), signed webhooks via logto.addHook().
```

Never deploy it: it signs in anyone who asks.

## Upgrading from 0.1

- `sessionSecret` is required (at least 32 characters). Rows written by 0.1.x
  do not open and are deleted: everyone signs in again once (one redirect while
  their Logto session lasts).
- `sqliteSessionStore` needs a `user_key` column: `createTable: true` adds it.
- Sign-out answers `POST` only. Change sign-out links into forms.
- The package ships `dist/`: drop `vite.ssr.noExternal` and `tsx` workarounds.
- `getUser` also accepts a request with Node-style headers.

## Develop

```
npm install
npm test
npm run typecheck
npm run build        # dist/ is committed: rebuild before tagging
```
