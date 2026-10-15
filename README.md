# @robyrew/astro-logto

Sign-in through the self-hosted Logto IdP (`https://auth.robyrew.com`) for
RobyRew Astro **server** apps, as a Logto *Traditional Web* application:

- The redirect, PKCE and code exchange all run on the server.
- OIDC tokens live in a server-side session store.
- The browser only holds an opaque, `httpOnly` session-id cookie.

mapswitch and chatforge each carried their own copy of this. This package is
that code, kept in one place.

## Install

```
npm i github:RobyRew/astro-logto#v0.1.0 @logto/node
```

The package ships TypeScript source, like `@robyrew/web-config`, so let Vite
bundle it into the server build:

```js
// astro.config.mjs
export default defineConfig({
  vite: { ssr: { noExternal: ['@robyrew/astro-logto'] } },
});
```

## Use

```ts
// src/server/auth.ts
import Database from 'better-sqlite3';
import { createLogtoAuth } from '@robyrew/astro-logto';
import { sqliteSessionStore } from '@robyrew/astro-logto/sqlite';

export const auth = createLogtoAuth({
  endpoint: process.env.LOGTO_ENDPOINT!,       // https://auth.robyrew.com
  appId: process.env.LOGTO_APP_ID!,
  appSecret: process.env.LOGTO_APP_SECRET!,    // server env only
  publicOrigin: process.env.PUBLIC_SITE_URL!,  // https://calendar.robyrew.com
  cookieName: 'cg_sid',
  store: sqliteSessionStore(sqlite),           // table logto_sessions(id, data, created_at, expires_at)
  resolveUser: (claims) => upsertUserBySub(claims), // your users row, keyed by claims.sub
});
```

```ts
// three routes, one line each
export const GET: APIRoute = (ctx) => auth.signIn(ctx);    // /api/auth/sign-in?returnTo=/path
export const GET: APIRoute = (ctx) => auth.callback(ctx);  // /api/auth/callback
export const GET: APIRoute = (ctx) => auth.signOut(ctx);   // /api/auth/sign-out (also POST)

// anywhere on the server
const user = await auth.getUser(request); // null when signed out; never throws
```

Register in the Logto console:

- Redirect URI: `${PUBLIC_SITE_URL}/api/auth/callback`
- Post sign-out redirect URI: `${PUBLIC_SITE_URL}/`

Register the application as **first-party** (Traditional Web). A third-party
registration rejects the `profile`/`email` scopes and loops.

## Behaviour

| | |
|---|---|
| Cookie | `__Host-<cookieName>` on https (Secure, Path=/, host-only, so no sibling subdomain can plant one); plain `<cookieName>` on http for local dev. `HttpOnly`, `SameSite=Lax`, 14 days by default. |
| Session id | A new id on every sign-in, and another after the callback succeeds. An id planted before login never becomes an authenticated session. |
| Callback failure | Redirects to `/?auth_error=1` (configurable) and drops the session. It does not restart sign-in, which is how a misconfigured app turns into an endless redirect loop. |
| `returnTo` | Local paths only (`/…`, not `//…` or absolute URLs). |
| Sign-out | Ends the Logto SSO session (`end_session`), not just the local one. |
| Redirect URIs | Built from `publicOrigin`, because behind Traefik the request arrives as `http://…`. |

## Session stores

- `sqliteSessionStore(db, { table?, columns?, createTable? })` works with any
  better-sqlite3-like handle. `columns` maps legacy camelCase schemas such as
  mapswitch's `createdAt`/`expiresAt`.
- `memorySessionStore()` is for tests.
- Anything implementing `SessionStore` (`load`/`save`/`drop`/`prune`) works,
  for example a Postgres table for chatforge.

## Develop

```
npm install
npm test
npm run typecheck
```
