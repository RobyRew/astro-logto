import { randomBytes } from 'node:crypto'
import LogtoClient, { type IdTokenClaims, type LogtoConfig } from '@logto/node'
import { deriveSessionKeys } from './seal.js'
import type { SessionStore } from './store.js'

// Logto "Traditional Web" sign-in for a server app: the redirect, PKCE and token
// exchange happen server-side, tokens live in a server-side session store (sealed
// with AES-256-GCM, keyed by an HMAC of the cookie value), and the browser only
// ever holds an opaque, httpOnly session-id cookie.
//
// Sessions are revalidated against Logto: once `revalidateAfterMs` has passed, the
// next request runs a refresh-token grant (scope offline_access). Logto refuses it
// for a suspended or deleted user (it revokes their tokens), and the session is
// dropped. The webhook helper (./webhook) drops them at once via revokeUser().

export type { SessionStore } from './store.js'
export { memorySessionStore } from './store.js'

export type LogtoClaims = IdTokenClaims

/** Requested by default; `openid` is always added by the SDK. */
export const DEFAULT_SCOPES: readonly string[] = ['email', 'profile', 'offline_access', 'roles']

export interface CookieOptions {
  httpOnly: boolean
  secure: boolean
  sameSite: 'lax' | 'strict'
  path: string
  maxAge: number
}

/** The subset of Astro's APIContext the handlers use (keeps the package independent of Astro's version). */
export interface RouteContext {
  url: URL
  request: Request
  cookies: {
    get(name: string): { value: string } | undefined
    set(name: string, value: string, options: CookieOptions): void
  }
  redirect(path: string, status?: 301 | 302 | 303 | 307 | 308): Response
}

/** A fetch Request, or anything with Node-style headers (IncomingMessage). */
export type RequestLike = Request | { headers: Headers | Record<string, string | string[] | undefined> }

type ClientAdapter = ConstructorParameters<typeof LogtoClient>[1]

export interface LogtoAuthOptions<User> {
  /** Logto endpoint, e.g. https://auth.robyrew.com (the SDK derives /oidc from discovery). */
  endpoint: string
  appId: string
  /** Traditional Web app secret: server env only, never in the client bundle. */
  appSecret: string
  /**
   * The app's public origin (https://calendar.robyrew.com). Behind Traefik the
   * request arrives as http://…, so redirect URIs are built from this instead.
   * An https origin also switches the cookies to Secure + the `__Host-` prefix.
   */
  publicOrigin: string
  /** Base name of the session cookie, e.g. 'cg_sid'. */
  cookieName: string
  store: SessionStore
  /**
   * At least 32 characters of secret material (`openssl rand -base64 32`, env
   * LOGTO_COOKIE_SECRET). Seals session rows and keys their ids. Changing it signs
   * everyone out: rows sealed under the old secret no longer open and are dropped.
   */
  sessionSecret: string
  /** Map verified ID-token claims to the app's local user (upsert by `sub`). Called on every authenticated request. */
  resolveUser(claims: LogtoClaims): User | Promise<User>
  /** Scopes; `openid` is always added by the SDK. Default: email, profile, offline_access, roles. */
  scopes?: string[]
  /** API resource indicators the app asks access tokens for (getAccessToken). */
  resources?: string[]
  /** Session lifetime, extended on each write. Default 14 days. */
  sessionTtlMs?: number
  /** How long a session is trusted before Logto is asked again (refresh grant). Default 10 minutes. */
  revalidateAfterMs?: number
  /** Timeout for each call to Logto. Default 8 seconds. */
  requestTimeoutMs?: number
  paths?: {
    /** Registered redirect URI path. Default /api/auth/callback. */
    callback?: string
    /** Where a failed callback lands (with ?auth_error=1). Default /. */
    afterError?: string
    /** Registered post-sign-out redirect path. Default /. */
    afterSignOut?: string
  }
  logger?: Pick<Console, 'error' | 'warn'>
  /** Test seam: override parts of the SDK adapter (e.g. `requester`). */
  adapter?: Partial<ClientAdapter>
}

export interface LogtoSession<User> {
  user: User
  claims: LogtoClaims
  sub: string
}

/** What is sealed into one session row. `logto` is the SDK's own storage (tokens, PKCE state). */
interface SessionRecord {
  v: 1
  /** Null while sign-in is in progress. */
  sub: string | null
  createdAt: number
  /** Last time Logto vouched for the session: the code exchange or a refresh grant. */
  validatedAt: number
  /** After Logto could not be reached, no new attempt before this time. */
  retryAt?: number
  logto: Record<string, string>
}

const MINUTE = 60_000
const DAY = 86_400_000
const PENDING_TTL_MS = 10 * MINUTE
const RETRY_AFTER_MS = MINUTE

/** Only same-site paths; blocks open redirects through ?returnTo=//evil.example. */
export function sanitizeReturnTo(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/'
  return raw
}

export function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1).trim())
      } catch {
        return null
      }
    }
  }
  return null
}

function cookieHeaderOf(request: RequestLike): string | null {
  const headers = request.headers as Headers | Record<string, string | string[] | undefined>
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get('cookie')
  const raw = (headers as Record<string, string | string[] | undefined>)['cookie']
  return Array.isArray(raw) ? raw.join('; ') : (raw ?? null)
}

const newSessionId = () => randomBytes(24).toString('base64url')
const message = (err: unknown) => (err instanceof Error ? err.message : String(err))

function parseRecord(value: unknown): SessionRecord | null {
  const r = value as Partial<SessionRecord> | null
  if (!r || r.v !== 1 || typeof r.createdAt !== 'number' || typeof r.validatedAt !== 'number') return null
  if (r.sub !== null && typeof r.sub !== 'string') return null
  if (!r.logto || typeof r.logto !== 'object') return null
  for (const v of Object.values(r.logto)) if (typeof v !== 'string') return null
  return r as SessionRecord
}

/**
 * True when Logto answered and refused the grant (revoked or expired refresh
 * token, suspended or deleted user, invalid client). Network errors, timeouts,
 * 5xx and 429 are not refusals.
 */
export function isLogtoRefusal(err: unknown): boolean {
  const e = err as { name?: unknown; code?: unknown; cause?: unknown; data?: unknown } | null
  if (!e || typeof e !== 'object') return false
  if (e.name === 'LogtoRequestError') {
    const status = (e.cause as { status?: unknown } | undefined)?.status
    if (typeof status === 'number') return status >= 400 && status < 500 && status !== 408 && status !== 429
    return typeof e.code === 'string' && /invalid_grant|invalid_client|unauthorized_client/.test(e.code)
  }
  if (e.name === 'LogtoError' && e.code === 'unexpected_response_error') {
    const error = (e.data as { error?: unknown } | undefined)?.error
    return error === 'invalid_grant' || error === 'invalid_client'
  }
  return e.name === 'LogtoClientError' && e.code === 'not_authenticated'
}

export function createLogtoAuth<User>(opts: LogtoAuthOptions<User>) {
  const origin = opts.publicOrigin.replace(/\/+$/, '')
  const secure = origin.startsWith('https:')
  // __Host- cookies must be Secure, Path=/ and host-only, so no sibling
  // subdomain can plant a session id for this app (session fixation).
  const cookieName = secure ? `__Host-${opts.cookieName}` : opts.cookieName
  const returnCookie = `${cookieName}_rt`
  const ttl = opts.sessionTtlMs ?? 14 * DAY
  const revalidateAfter = opts.revalidateAfterMs ?? 10 * MINUTE
  const callbackPath = opts.paths?.callback ?? '/api/auth/callback'
  const afterError = opts.paths?.afterError ?? '/'
  const afterSignOut = opts.paths?.afterSignOut ?? '/'
  const log = opts.logger ?? console
  const keys = deriveSessionKeys(opts.sessionSecret)
  const config: LogtoConfig = {
    endpoint: opts.endpoint,
    appId: opts.appId,
    appSecret: opts.appSecret,
    scopes: [...(opts.scopes ?? DEFAULT_SCOPES)],
    ...(opts.resources?.length ? { resources: [...opts.resources] } : {}),
    requestTimeoutMs: opts.requestTimeoutMs ?? 8_000,
  }
  const cookie = (maxAgeMs: number): CookieOptions => ({
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: Math.floor(maxAgeMs / 1000),
  })
  // Deleting is setting an expired cookie with the same attributes: a browser
  // ignores a __Host- Set-Cookie that lacks Secure, deletion included.
  const clearCookie = (ctx: RouteContext, name: string) => ctx.cookies.set(name, '', cookie(0))

  // One lock per session row, in this process. A refresh grant may rotate the
  // refresh token, and Logto revokes the whole grant when a rotated token is
  // presented again, so two requests of one session must not refresh at once.
  // One process per store is assumed.
  const locks = new Map<string, Promise<void>>()
  async function withLock<T>(id: string, fn: () => Promise<T>): Promise<T> {
    const previous = locks.get(id) ?? Promise.resolve()
    let release!: () => void
    const current = new Promise<void>((resolve) => {
      release = resolve
    })
    const tail = previous.then(() => current)
    locks.set(id, tail)
    await previous
    try {
      return await fn()
    } finally {
      release()
      if (locks.get(id) === tail) locks.delete(id)
    }
  }

  async function readRecord(id: string): Promise<SessionRecord | null> {
    const blob = await opts.store.load(id)
    if (!blob) return null
    const json = keys.open(blob, id)
    let record: SessionRecord | null = null
    if (json) {
      try {
        record = parseRecord(JSON.parse(json))
      } catch {
        record = null
      }
    }
    if (!record) {
      // A 0.1.x plaintext row, a row sealed under another secret, or a tampered one.
      await opts.store.drop(id)
      return null
    }
    return record
  }

  async function writeRecord(id: string, record: SessionRecord): Promise<void> {
    const lifetime = record.sub ? ttl : PENDING_TTL_MS
    await opts.store.save(id, keys.seal(JSON.stringify(record), id), Date.now() + lifetime, record.sub ? keys.userKey(record.sub) : null)
  }

  /** An SDK client whose storage is the record's `logto` map; callers write the record back. */
  function clientFor(record: SessionRecord, navigate: (url: string) => void = () => {}) {
    const storage = {
      async getItem(key: string) {
        return record.logto[key] ?? null
      },
      async setItem(key: string, value: string) {
        record.logto[key] = value
      },
      async removeItem(key: string) {
        delete record.logto[key]
      },
    }
    return new LogtoClient(config, { ...opts.adapter, navigate, storage })
  }

  async function refresh(client: LogtoClient): Promise<'ok' | 'refused' | 'unreachable' | 'no_refresh_token'> {
    if (!(await client.getRefreshToken())) return 'no_refresh_token'
    try {
      // Dropping the cached access token makes the next call run the refresh grant.
      await client.clearAccessToken()
      await client.getAccessToken()
      return 'ok'
    } catch (err) {
      if (isLogtoRefusal(err)) {
        log.warn('[auth] Logto refused the session refresh; the session is dropped:', message(err))
        return 'refused'
      }
      log.warn('[auth] session refresh could not reach Logto; the session is kept:', message(err))
      return 'unreachable'
    }
  }

  /** False when the session is over (it has been dropped). */
  async function revalidateIfDue(id: string, record: SessionRecord, client: LogtoClient): Promise<boolean> {
    const now = Date.now()
    if (now - record.validatedAt < revalidateAfter || (record.retryAt ?? 0) > now) return true
    const outcome = await refresh(client)
    if (outcome === 'refused') {
      await opts.store.drop(id)
      return false
    }
    if (outcome === 'no_refresh_token') {
      // Without a refresh token nothing can be renewed: the session ends with its ID token.
      const { exp } = await client.getIdTokenClaims()
      if (exp * 1000 <= now) {
        await opts.store.drop(id)
        return false
      }
      return true
    }
    if (outcome === 'ok') {
      record.validatedAt = now
      delete record.retryAt
    } else {
      record.retryAt = now + RETRY_AFTER_MS
    }
    await writeRecord(id, record)
    return true
  }

  /** Loads the session behind the request's cookie, revalidated when due, under the row's lock. */
  async function withSession<T>(request: RequestLike, fn: (id: string, record: SessionRecord, client: LogtoClient) => Promise<T | null>): Promise<T | null> {
    const sid = readCookie(cookieHeaderOf(request), cookieName)
    if (!sid) return null
    const id = keys.rowId(sid)
    return withLock(id, async () => {
      const record = await readRecord(id)
      if (!record?.sub) return null
      const client = clientFor(record)
      if (!(await client.isAuthenticated())) return null
      if (!(await revalidateIfDue(id, record, client))) return null
      return fn(id, record, client)
    })
  }

  /** The session (local user + verified claims) for a request, or null. Never throws. */
  async function getSession(request: RequestLike): Promise<LogtoSession<User> | null> {
    try {
      return await withSession(request, async (id, record, client) => {
        const claims = await client.getIdTokenClaims()
        if (claims.sub !== record.sub) {
          await opts.store.drop(id)
          return null
        }
        const user = await opts.resolveUser(claims)
        return { user, claims, sub: claims.sub }
      })
    } catch (err) {
      log.error('[auth] getSession failed:', message(err))
      return null
    }
  }

  /** The signed-in user for a request, or null. Never throws. */
  async function getUser(request: RequestLike): Promise<User | null> {
    return (await getSession(request))?.user ?? null
  }

  /**
   * An access token for one of `resources` (or Logto's userinfo when omitted),
   * refreshed when expired. Null when signed out or when Logto refuses. Never throws.
   */
  async function getAccessToken(request: RequestLike, resource?: string): Promise<string | null> {
    try {
      return await withSession(request, async (id, record, client) => {
        const before = JSON.stringify(record.logto)
        try {
          const token = await client.getAccessToken(resource)
          if (JSON.stringify(record.logto) !== before) await writeRecord(id, record)
          return token
        } catch (err) {
          if (isLogtoRefusal(err)) await opts.store.drop(id)
          else log.warn('[auth] access token unavailable:', message(err))
          return null
        }
      })
    } catch (err) {
      log.error('[auth] getAccessToken failed:', message(err))
      return null
    }
  }

  /** GET /api/auth/sign-in?returnTo=/path[&mode=signUp] */
  async function signIn(ctx: RouteContext): Promise<Response> {
    // A fresh pre-login session every time; the PKCE verifier and state live in it.
    const sid = newSessionId()
    const id = keys.rowId(sid)
    try {
      await opts.store.prune?.(Date.now())
    } catch (err) {
      log.warn('[auth] session prune failed:', message(err))
    }
    const now = Date.now()
    const record: SessionRecord = { v: 1, sub: null, createdAt: now, validatedAt: 0, logto: {} }
    let target = afterError
    const client = clientFor(record, (u) => {
      target = u
    })
    await client.signIn({
      redirectUri: `${origin}${callbackPath}`,
      ...(ctx.url.searchParams.get('mode') === 'signUp' ? { interactionMode: 'signUp' as const } : {}),
    })
    await writeRecord(id, record)
    ctx.cookies.set(cookieName, sid, cookie(ttl))
    ctx.cookies.set(returnCookie, sanitizeReturnTo(ctx.url.searchParams.get('returnTo')), cookie(PENDING_TTL_MS))
    return ctx.redirect(target, 302)
  }

  /** GET /api/auth/callback — exchanges the code, then rotates the session id. */
  async function callback(ctx: RouteContext): Promise<Response> {
    const sid = ctx.cookies.get(cookieName)?.value
    const failed = () => ctx.redirect(`${afterError}${afterError.includes('?') ? '&' : '?'}auth_error=1`, 302)
    if (!sid) return failed()
    const pendingId = keys.rowId(sid)
    const fresh = await withLock(pendingId, async () => {
      const record = await readRecord(pendingId)
      if (!record || record.sub) return null
      const client = clientFor(record)
      try {
        // Rebuild the callback URL from the public origin, keeping ?code&state.
        await client.handleSignInCallback(`${origin}${ctx.url.pathname}${ctx.url.search}`)
        const claims = await client.getIdTokenClaims()
        if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('ID token has no sub')
        await opts.resolveUser(claims)
        const now = Date.now()
        record.sub = claims.sub
        record.createdAt = now
        record.validatedAt = now
      } catch (err) {
        // Land on a page instead of restarting sign-in: an automatic retry is how a
        // misconfigured app turns into an endless redirect loop.
        log.error('[auth] sign-in callback failed:', message(err))
        await opts.store.drop(pendingId)
        return null
      }
      // New id for the authenticated session; the pre-login id stops working.
      const freshSid = newSessionId()
      await writeRecord(keys.rowId(freshSid), record)
      await opts.store.drop(pendingId)
      return freshSid
    })
    if (!fresh) {
      clearCookie(ctx, cookieName)
      clearCookie(ctx, returnCookie)
      return failed()
    }
    ctx.cookies.set(cookieName, fresh, cookie(ttl))
    const returnTo = sanitizeReturnTo(ctx.cookies.get(returnCookie)?.value)
    clearCookie(ctx, returnCookie)
    return ctx.redirect(returnTo, 302)
  }

  /** True when a browser sent this POST from the app's own origin (CSRF check). */
  function sameOrigin(request: Request): boolean {
    const originHeader = request.headers.get('origin')
    if (originHeader) return originHeader === origin
    const site = request.headers.get('sec-fetch-site')
    return !site || site === 'same-origin' || site === 'none'
  }

  /**
   * POST /api/auth/sign-out — revokes the refresh token, drops the local session and
   * ends the Logto SSO session (end_session), not just the local one. Any other
   * method gets 405, and a cross-origin POST 403, so a link or an image on another
   * site cannot sign anyone out.
   */
  async function signOut(ctx: RouteContext): Promise<Response> {
    if (ctx.request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: { allow: 'POST' } })
    }
    if (!sameOrigin(ctx.request)) return new Response('Forbidden', { status: 403 })
    const sid = ctx.cookies.get(cookieName)?.value
    let target = `${origin}${afterSignOut}`
    if (sid) {
      const id = keys.rowId(sid)
      await withLock(id, async () => {
        const record = await readRecord(id)
        if (record?.sub) {
          try {
            const client = clientFor(record, (u) => {
              target = u
            })
            await client.signOut(`${origin}${afterSignOut}`)
          } catch (err) {
            log.warn('[auth] Logto end-session failed (local session cleared anyway):', message(err))
          }
        }
        await opts.store.drop(id)
      })
      clearCookie(ctx, cookieName)
    }
    return ctx.redirect(target, 303)
  }

  /** Drops every local session of a Logto user (webhook: deletion, suspension). */
  async function revokeUser(sub: string): Promise<void> {
    await opts.store.dropUser(keys.userKey(sub))
  }

  return { getUser, getSession, getAccessToken, signIn, callback, signOut, revokeUser, cookieName }
}

export type LogtoAuth<User> = ReturnType<typeof createLogtoAuth<User>>
