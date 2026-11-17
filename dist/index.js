import { randomBytes } from 'node:crypto';
import LogtoClient, {} from '@logto/node';
import { deriveSessionKeys } from './seal.js';
export { memorySessionStore } from './store.js';
/** Requested by default; `openid` is always added by the SDK. */
export const DEFAULT_SCOPES = ['email', 'profile', 'offline_access', 'roles'];
const MINUTE = 60_000;
const DAY = 86_400_000;
const PENDING_TTL_MS = 10 * MINUTE;
const RETRY_AFTER_MS = MINUTE;
/** Only same-site paths; blocks open redirects through ?returnTo=//evil.example. */
export function sanitizeReturnTo(raw) {
    if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\'))
        return '/';
    return raw;
}
export function readCookie(header, name) {
    if (!header)
        return null;
    for (const part of header.split(';')) {
        const eq = part.indexOf('=');
        if (eq === -1)
            continue;
        if (part.slice(0, eq).trim() === name) {
            try {
                return decodeURIComponent(part.slice(eq + 1).trim());
            }
            catch {
                return null;
            }
        }
    }
    return null;
}
function cookieHeaderOf(request) {
    const headers = request.headers;
    if (typeof headers.get === 'function')
        return headers.get('cookie');
    const raw = headers['cookie'];
    return Array.isArray(raw) ? raw.join('; ') : (raw ?? null);
}
const newSessionId = () => randomBytes(24).toString('base64url');
const message = (err) => (err instanceof Error ? err.message : String(err));
function parseRecord(value) {
    const r = value;
    if (!r || r.v !== 1 || typeof r.createdAt !== 'number' || typeof r.validatedAt !== 'number')
        return null;
    if (r.sub !== null && typeof r.sub !== 'string')
        return null;
    if (!r.logto || typeof r.logto !== 'object')
        return null;
    for (const v of Object.values(r.logto))
        if (typeof v !== 'string')
            return null;
    return r;
}
/**
 * True when Logto answered and refused the grant (revoked or expired refresh
 * token, suspended or deleted user, invalid client). Network errors, timeouts,
 * 5xx and 429 are not refusals.
 */
export function isLogtoRefusal(err) {
    const e = err;
    if (!e || typeof e !== 'object')
        return false;
    if (e.name === 'LogtoRequestError') {
        const status = e.cause?.status;
        if (typeof status === 'number')
            return status >= 400 && status < 500 && status !== 408 && status !== 429;
        return typeof e.code === 'string' && /invalid_grant|invalid_client|unauthorized_client/.test(e.code);
    }
    if (e.name === 'LogtoError' && e.code === 'unexpected_response_error') {
        const error = e.data?.error;
        return error === 'invalid_grant' || error === 'invalid_client';
    }
    return e.name === 'LogtoClientError' && e.code === 'not_authenticated';
}
export function createLogtoAuth(opts) {
    const origin = opts.publicOrigin.replace(/\/+$/, '');
    const secure = origin.startsWith('https:');
    // __Host- cookies must be Secure, Path=/ and host-only, so no sibling
    // subdomain can plant a session id for this app (session fixation).
    const cookieName = secure ? `__Host-${opts.cookieName}` : opts.cookieName;
    const returnCookie = `${cookieName}_rt`;
    const ttl = opts.sessionTtlMs ?? 14 * DAY;
    const revalidateAfter = opts.revalidateAfterMs ?? 10 * MINUTE;
    const callbackPath = opts.paths?.callback ?? '/api/auth/callback';
    const afterError = opts.paths?.afterError ?? '/';
    const afterSignOut = opts.paths?.afterSignOut ?? '/';
    const log = opts.logger ?? console;
    const keys = deriveSessionKeys(opts.sessionSecret);
    const config = {
        endpoint: opts.endpoint,
        appId: opts.appId,
        appSecret: opts.appSecret,
        scopes: [...(opts.scopes ?? DEFAULT_SCOPES)],
        ...(opts.resources?.length ? { resources: [...opts.resources] } : {}),
        requestTimeoutMs: opts.requestTimeoutMs ?? 8_000,
    };
    const cookie = (maxAgeMs) => ({
        httpOnly: true,
        secure,
        sameSite: 'lax',
        path: '/',
        maxAge: Math.floor(maxAgeMs / 1000),
    });
    // Deleting is setting an expired cookie with the same attributes: a browser
    // ignores a __Host- Set-Cookie that lacks Secure, deletion included.
    const clearCookie = (ctx, name) => ctx.cookies.set(name, '', cookie(0));
    // One lock per session row, in this process. A refresh grant may rotate the
    // refresh token, and Logto revokes the whole grant when a rotated token is
    // presented again, so two requests of one session must not refresh at once.
    // One process per store is assumed.
    const locks = new Map();
    async function withLock(id, fn) {
        const previous = locks.get(id) ?? Promise.resolve();
        let release;
        const current = new Promise((resolve) => {
            release = resolve;
        });
        const tail = previous.then(() => current);
        locks.set(id, tail);
        await previous;
        try {
            return await fn();
        }
        finally {
            release();
            if (locks.get(id) === tail)
                locks.delete(id);
        }
    }
    async function readRecord(id) {
        const blob = await opts.store.load(id);
        if (!blob)
            return null;
        const json = keys.open(blob, id);
        let record = null;
        if (json) {
            try {
                record = parseRecord(JSON.parse(json));
            }
            catch {
                record = null;
            }
        }
        if (!record) {
            // A 0.1.x plaintext row, a row sealed under another secret, or a tampered one.
            await opts.store.drop(id);
            return null;
        }
        return record;
    }
    async function writeRecord(id, record) {
        const lifetime = record.sub ? ttl : PENDING_TTL_MS;
        await opts.store.save(id, keys.seal(JSON.stringify(record), id), Date.now() + lifetime, record.sub ? keys.userKey(record.sub) : null);
    }
    /** An SDK client whose storage is the record's `logto` map; callers write the record back. */
    function clientFor(record, navigate = () => { }) {
        const storage = {
            async getItem(key) {
                return record.logto[key] ?? null;
            },
            async setItem(key, value) {
                record.logto[key] = value;
            },
            async removeItem(key) {
                delete record.logto[key];
            },
        };
        return new LogtoClient(config, { ...opts.adapter, navigate, storage });
    }
    async function refresh(client) {
        if (!(await client.getRefreshToken()))
            return 'no_refresh_token';
        try {
            // Dropping the cached access token makes the next call run the refresh grant.
            await client.clearAccessToken();
            await client.getAccessToken();
            return 'ok';
        }
        catch (err) {
            if (isLogtoRefusal(err)) {
                log.warn('[auth] Logto refused the session refresh; the session is dropped:', message(err));
                return 'refused';
            }
            log.warn('[auth] session refresh could not reach Logto; the session is kept:', message(err));
            return 'unreachable';
        }
    }
    /** False when the session is over (it has been dropped). */
    async function revalidateIfDue(id, record, client) {
        const now = Date.now();
        if (now - record.validatedAt < revalidateAfter || (record.retryAt ?? 0) > now)
            return true;
        const outcome = await refresh(client);
        if (outcome === 'refused') {
            await opts.store.drop(id);
            return false;
        }
        if (outcome === 'no_refresh_token') {
            // Without a refresh token nothing can be renewed: the session ends with its ID token.
            const { exp } = await client.getIdTokenClaims();
            if (exp * 1000 <= now) {
                await opts.store.drop(id);
                return false;
            }
            return true;
        }
        if (outcome === 'ok') {
            record.validatedAt = now;
            delete record.retryAt;
        }
        else {
            record.retryAt = now + RETRY_AFTER_MS;
        }
        await writeRecord(id, record);
        return true;
    }
    /** Loads the session behind the request's cookie, revalidated when due, under the row's lock. */
    async function withSession(request, fn) {
        const sid = readCookie(cookieHeaderOf(request), cookieName);
        if (!sid)
            return null;
        const id = keys.rowId(sid);
        return withLock(id, async () => {
            const record = await readRecord(id);
            if (!record?.sub)
                return null;
            const client = clientFor(record);
            if (!(await client.isAuthenticated()))
                return null;
            if (!(await revalidateIfDue(id, record, client)))
                return null;
            return fn(id, record, client);
        });
    }
    /** The session (local user + verified claims) for a request, or null. Never throws. */
    async function getSession(request) {
        try {
            return await withSession(request, async (id, record, client) => {
                const claims = await client.getIdTokenClaims();
                if (claims.sub !== record.sub) {
                    await opts.store.drop(id);
                    return null;
                }
                const user = await opts.resolveUser(claims);
                return { user, claims, sub: claims.sub };
            });
        }
        catch (err) {
            log.error('[auth] getSession failed:', message(err));
            return null;
        }
    }
    /** The signed-in user for a request, or null. Never throws. */
    async function getUser(request) {
        return (await getSession(request))?.user ?? null;
    }
    /**
     * An access token for one of `resources` (or Logto's userinfo when omitted),
     * refreshed when expired. Null when signed out or when Logto refuses. Never throws.
     */
    async function getAccessToken(request, resource) {
        try {
            return await withSession(request, async (id, record, client) => {
                const before = JSON.stringify(record.logto);
                try {
                    const token = await client.getAccessToken(resource);
                    if (JSON.stringify(record.logto) !== before)
                        await writeRecord(id, record);
                    return token;
                }
                catch (err) {
                    if (isLogtoRefusal(err))
                        await opts.store.drop(id);
                    else
                        log.warn('[auth] access token unavailable:', message(err));
                    return null;
                }
            });
        }
        catch (err) {
            log.error('[auth] getAccessToken failed:', message(err));
            return null;
        }
    }
    /** GET /api/auth/sign-in?returnTo=/path[&mode=signUp] */
    async function signIn(ctx) {
        // A fresh pre-login session every time; the PKCE verifier and state live in it.
        const sid = newSessionId();
        const id = keys.rowId(sid);
        try {
            await opts.store.prune?.(Date.now());
        }
        catch (err) {
            log.warn('[auth] session prune failed:', message(err));
        }
        const now = Date.now();
        const record = { v: 1, sub: null, createdAt: now, validatedAt: 0, logto: {} };
        let target = afterError;
        const client = clientFor(record, (u) => {
            target = u;
        });
        await client.signIn({
            redirectUri: `${origin}${callbackPath}`,
            ...(ctx.url.searchParams.get('mode') === 'signUp' ? { interactionMode: 'signUp' } : {}),
        });
        await writeRecord(id, record);
        ctx.cookies.set(cookieName, sid, cookie(ttl));
        ctx.cookies.set(returnCookie, sanitizeReturnTo(ctx.url.searchParams.get('returnTo')), cookie(PENDING_TTL_MS));
        return ctx.redirect(target, 302);
    }
    /** GET /api/auth/callback — exchanges the code, then rotates the session id. */
    async function callback(ctx) {
        const sid = ctx.cookies.get(cookieName)?.value;
        const failed = () => ctx.redirect(`${afterError}${afterError.includes('?') ? '&' : '?'}auth_error=1`, 302);
        if (!sid)
            return failed();
        const pendingId = keys.rowId(sid);
        const fresh = await withLock(pendingId, async () => {
            const record = await readRecord(pendingId);
            if (!record || record.sub)
                return null;
            const client = clientFor(record);
            try {
                // Rebuild the callback URL from the public origin, keeping ?code&state.
                await client.handleSignInCallback(`${origin}${ctx.url.pathname}${ctx.url.search}`);
                const claims = await client.getIdTokenClaims();
                if (typeof claims.sub !== 'string' || !claims.sub)
                    throw new Error('ID token has no sub');
                await opts.resolveUser(claims);
                const now = Date.now();
                record.sub = claims.sub;
                record.createdAt = now;
                record.validatedAt = now;
            }
            catch (err) {
                // Land on a page instead of restarting sign-in: an automatic retry is how a
                // misconfigured app turns into an endless redirect loop.
                log.error('[auth] sign-in callback failed:', message(err));
                await opts.store.drop(pendingId);
                return null;
            }
            // New id for the authenticated session; the pre-login id stops working.
            const freshSid = newSessionId();
            await writeRecord(keys.rowId(freshSid), record);
            await opts.store.drop(pendingId);
            return freshSid;
        });
        if (!fresh) {
            clearCookie(ctx, cookieName);
            clearCookie(ctx, returnCookie);
            return failed();
        }
        ctx.cookies.set(cookieName, fresh, cookie(ttl));
        const returnTo = sanitizeReturnTo(ctx.cookies.get(returnCookie)?.value);
        clearCookie(ctx, returnCookie);
        return ctx.redirect(returnTo, 302);
    }
    /** True when a browser sent this POST from the app's own origin (CSRF check). */
    function sameOrigin(request) {
        const originHeader = request.headers.get('origin');
        if (originHeader)
            return originHeader === origin;
        const site = request.headers.get('sec-fetch-site');
        return !site || site === 'same-origin' || site === 'none';
    }
    /**
     * POST /api/auth/sign-out — revokes the refresh token, drops the local session and
     * ends the Logto SSO session (end_session), not just the local one. Any other
     * method gets 405, and a cross-origin POST 403, so a link or an image on another
     * site cannot sign anyone out.
     */
    async function signOut(ctx) {
        if (ctx.request.method !== 'POST') {
            return new Response('Method Not Allowed', { status: 405, headers: { allow: 'POST' } });
        }
        if (!sameOrigin(ctx.request))
            return new Response('Forbidden', { status: 403 });
        const sid = ctx.cookies.get(cookieName)?.value;
        let target = `${origin}${afterSignOut}`;
        if (sid) {
            const id = keys.rowId(sid);
            await withLock(id, async () => {
                const record = await readRecord(id);
                if (record?.sub) {
                    try {
                        const client = clientFor(record, (u) => {
                            target = u;
                        });
                        await client.signOut(`${origin}${afterSignOut}`);
                    }
                    catch (err) {
                        log.warn('[auth] Logto end-session failed (local session cleared anyway):', message(err));
                    }
                }
                await opts.store.drop(id);
            });
            clearCookie(ctx, cookieName);
        }
        return ctx.redirect(target, 303);
    }
    /** Drops every local session of a Logto user (webhook: deletion, suspension). */
    async function revokeUser(sub) {
        await opts.store.dropUser(keys.userKey(sub));
    }
    return { getUser, getSession, getAccessToken, signIn, callback, signOut, revokeUser, cookieName };
}
