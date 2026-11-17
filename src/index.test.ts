import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createLogtoAuth, readCookie, sanitizeReturnTo, type CookieOptions, type RouteContext } from './index.js'
import { memorySessionStore } from './store.js'
import { startFakeLogto, type FakeLogto } from './testing.js'

const ORIGIN = 'https://app.example.test'
const SECRET = 'test-session-secret-0123456789-abcdef'
const quiet = { error: () => {}, warn: () => {} }

type Jar = Record<string, { value: string; options?: CookieOptions }>

function context(url: string, jar: Jar = {}, init: { method?: string; headers?: Record<string, string> } = {}) {
  const ctx = {
    url: new URL(url),
    request: new Request(url, { method: init.method ?? 'GET', headers: init.headers }),
    jar,
    location: undefined as string | undefined,
    status: undefined as number | undefined,
    cookies: {
      get: (name: string) => (jar[name] && jar[name].options?.maxAge !== 0 ? { value: jar[name].value } : undefined),
      set: (name: string, value: string, options: CookieOptions) => void (jar[name] = { value, options }),
    },
    redirect(path: string, status = 302) {
      ctx.location = path
      ctx.status = status
      return new Response(null, { status, headers: { location: path } })
    },
  } satisfies RouteContext & Record<string, unknown>
  return ctx
}

/** The Cookie header a browser would send for this jar. */
const cookieHeader = (jar: Jar) =>
  Object.entries(jar)
    .filter(([, c]) => c.options?.maxAge !== 0)
    .map(([k, c]) => `${k}=${encodeURIComponent(c.value)}`)
    .join('; ')

let fake: FakeLogto

beforeEach(async () => {
  fake = await startFakeLogto()
  fake.addUser({ id: 'alice00000001', username: 'alice', name: 'Alice', avatar: 'https://id.example.test/avatars/a.webp', roles: ['moderator'] })
  fake.addUser({ id: 'bobby00000002', username: 'bob', name: 'Bob' })
})
afterEach(async () => {
  await fake.close()
})

function setup(overrides: Partial<Parameters<typeof createLogtoAuth>[0]> = {}) {
  const store = memorySessionStore()
  const auth = createLogtoAuth({
    endpoint: fake.endpoint,
    appId: 'app-id',
    appSecret: 'app-secret',
    publicOrigin: ORIGIN,
    cookieName: 'cg_sid',
    sessionSecret: SECRET,
    store,
    resolveUser: (claims) => ({ id: claims.sub, username: claims.username ?? null, roles: claims.roles ?? [] }),
    logger: quiet,
    ...overrides,
  })
  return { auth, store }
}

/** Sign-in → Logto approves `sub` → callback. Returns the browser's cookie jar. */
async function signInAs(auth: ReturnType<typeof setup>['auth'], sub: string, returnTo = '/') {
  const jar: Jar = {}
  const start = context(`http://internal:4321/api/auth/sign-in?returnTo=${encodeURIComponent(returnTo)}`, jar)
  await auth.signIn(start)
  const callbackUrl = fake.authorize(start.location!, sub)
  const cb = context(callbackUrl.replace(ORIGIN, 'http://internal:4321'), jar)
  await auth.callback(cb)
  return { jar, callback: cb }
}

const request = (jar: Jar, path = '/api/me') => new Request(`${ORIGIN}${path}`, { headers: { cookie: cookieHeader(jar) } })

describe('helpers', () => {
  it('sanitizeReturnTo keeps local paths only', () => {
    expect(sanitizeReturnTo('/s/abc?x=1')).toBe('/s/abc?x=1')
    expect(sanitizeReturnTo('//evil.test')).toBe('/')
    expect(sanitizeReturnTo('/\\evil.test')).toBe('/')
    expect(sanitizeReturnTo('https://evil.test')).toBe('/')
    expect(sanitizeReturnTo(null)).toBe('/')
  })

  it('readCookie finds a cookie among others', () => {
    expect(readCookie('a=1; __Host-cg_sid=xyz; b=2', '__Host-cg_sid')).toBe('xyz')
    expect(readCookie('a=1', 'cg_sid')).toBeNull()
    expect(readCookie(null, 'cg_sid')).toBeNull()
  })

  it('refuses a short session secret', () => {
    expect(() => setup({ sessionSecret: 'short' })).toThrow(/at least 32/)
  })
})

describe('sign-in', () => {
  it('redirects to Logto with PKCE, offline_access and roles, and stores a sealed pre-login row', async () => {
    const { auth, store } = setup()
    const jar: Jar = {}
    const ctx = context('http://internal:4321/api/auth/sign-in?returnTo=/s/tok', jar)
    await auth.signIn(ctx)
    expect(auth.cookieName).toBe('__Host-cg_sid')
    expect(jar['__Host-cg_sid']!.value).toMatch(/^[A-Za-z0-9_-]{32}$/)
    expect(jar['__Host-cg_sid']!.options).toMatchObject({ secure: true, httpOnly: true, sameSite: 'lax', path: '/' })
    expect(jar['__Host-cg_sid_rt']!.value).toBe('/s/tok')
    const target = new URL(ctx.location!)
    expect(target.origin + target.pathname).toBe(`${fake.endpoint}/oidc/auth`)
    expect(target.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/api/auth/callback`)
    expect(target.searchParams.get('code_challenge_method')).toBe('S256')
    expect(target.searchParams.get('scope')!.split(' ')).toEqual(expect.arrayContaining(['openid', 'offline_access', 'profile', 'email', 'roles']))
    const [rowId, row] = [...store.rows()][0]!
    expect(rowId).not.toBe(jar['__Host-cg_sid']!.value)
    expect(row!.blob).toMatch(/^v1\./)
    expect(row!.blob).not.toContain('codeVerifier')
    expect(row!.userKey).toBeNull()
  })

  it('uses a plain cookie name on http (local dev)', async () => {
    const { auth } = setup({ publicOrigin: 'http://localhost:5173' })
    const jar: Jar = {}
    await auth.signIn(context('http://localhost:5173/api/auth/sign-in', jar))
    expect(jar['cg_sid']).toBeDefined()
    expect(jar['cg_sid']!.options!.secure).toBe(false)
  })
})

describe('callback and sessions', () => {
  it('signs in, rotates the session id, honours returnTo and exposes username, picture and roles', async () => {
    const { auth, store } = setup()
    const jar: Jar = {}
    const start = context('http://internal:4321/api/auth/sign-in?returnTo=/settings', jar)
    await auth.signIn(start)
    const preLogin = jar['__Host-cg_sid']!.value
    const cb = context(fake.authorize(start.location!, 'alice00000001').replace(ORIGIN, 'http://internal:4321'), jar)
    await auth.callback(cb)
    expect(cb.location).toBe('/settings')
    expect(jar['__Host-cg_sid']!.value).not.toBe(preLogin)
    expect(jar['__Host-cg_sid_rt']!.options).toMatchObject({ maxAge: 0, secure: true })
    const session = await auth.getSession(request(jar))
    expect(session?.user).toEqual({ id: 'alice00000001', username: 'alice', roles: ['moderator'] })
    expect(session?.claims.picture).toBe('https://id.example.test/avatars/a.webp')
    // One authenticated row, sealed: no token or claim in clear.
    expect(store.size()).toBe(1)
    const [, row] = [...store.rows()][0]!
    expect(row!.blob).not.toMatch(/alice|idToken|refreshToken/)
    expect(row!.userKey).toMatch(/^[\w-]{43}$/)
    // The pre-login id no longer opens anything.
    expect(await auth.getUser(new Request(ORIGIN, { headers: { cookie: `__Host-cg_sid=${preLogin}` } }))).toBeNull()
  })

  it('lands on the error page (not back in sign-in) when the exchange fails', async () => {
    const { auth, store } = setup()
    const jar: Jar = {}
    await auth.signIn(context('http://internal:4321/api/auth/sign-in', jar))
    const ctx = context(`${ORIGIN}/api/auth/callback?code=bad&state=wrong`, jar)
    await auth.callback(ctx)
    expect(ctx.location).toBe('/?auth_error=1')
    expect(jar['__Host-cg_sid']!.options).toMatchObject({ maxAge: 0, secure: true })
    expect(store.size()).toBe(0)
  })

  it('redirects to the error page without a session cookie', async () => {
    const { auth } = setup()
    const ctx = context(`${ORIGIN}/api/auth/callback?code=x&state=y`)
    await auth.callback(ctx)
    expect(ctx.location).toBe('/?auth_error=1')
  })

  it('returns null without a session and for an unknown id', async () => {
    const { auth } = setup()
    expect(await auth.getUser(new Request(`${ORIGIN}/api/me`))).toBeNull()
    expect(await auth.getUser(new Request(`${ORIGIN}/api/me`, { headers: { cookie: '__Host-cg_sid=unknown' } }))).toBeNull()
  })

  it('drops a 0.1.x plaintext row instead of trusting it', async () => {
    const { auth, store } = setup()
    const { jar } = await signInAs(auth, 'alice00000001')
    const [rowId] = [...store.rows()][0]!
    store.save(rowId!, JSON.stringify({ idToken: 'forged' }), Date.now() + 60_000, null)
    expect(await auth.getUser(request(jar))).toBeNull()
    expect(store.size()).toBe(0)
  })
})

describe('revalidation', () => {
  it('picks up a renamed handle from the refreshed ID token', async () => {
    const { auth } = setup({ revalidateAfterMs: 0 })
    const { jar } = await signInAs(auth, 'alice00000001')
    fake.updateUser('alice00000001', { username: 'alice_2' })
    expect((await auth.getSession(request(jar)))?.claims.username).toBe('alice_2')
  })

  it('does not ask Logto again before revalidateAfterMs', async () => {
    const { auth } = setup({ revalidateAfterMs: 60_000 })
    const { jar } = await signInAs(auth, 'alice00000001')
    const before = fake.requests.filter((r) => r.path === '/oidc/token').length
    fake.updateUser('alice00000001', { username: 'alice_2' })
    expect((await auth.getSession(request(jar)))?.claims.username).toBe('alice')
    expect(fake.requests.filter((r) => r.path === '/oidc/token').length).toBe(before)
  })

  it('drops the session when Logto refuses the refresh (suspended user)', async () => {
    const { auth, store } = setup({ revalidateAfterMs: 0 })
    const { jar } = await signInAs(auth, 'alice00000001')
    fake.suspend('alice00000001')
    expect(await auth.getUser(request(jar))).toBeNull()
    expect(store.size()).toBe(0)
  })

  it('keeps the session while Logto is unreachable, and waits before asking again', async () => {
    const { auth } = setup({ revalidateAfterMs: 0 })
    const { jar } = await signInAs(auth, 'alice00000001')
    fake.failTokenEndpoint(503)
    expect((await auth.getUser(request(jar)) as { id: string } | null)?.id).toBe('alice00000001')
    const attempts = fake.requests.filter((r) => r.path === '/oidc/token').length
    expect((await auth.getUser(request(jar)) as { id: string } | null)?.id).toBe('alice00000001')
    expect(fake.requests.filter((r) => r.path === '/oidc/token').length).toBe(attempts)
  })

  it('serializes refreshes of one session (a reused refresh token would be refused)', async () => {
    const { auth } = setup({ revalidateAfterMs: 0 })
    const { jar } = await signInAs(auth, 'alice00000001')
    const results = await Promise.all([1, 2, 3].map(() => auth.getUser(request(jar))))
    expect(results.every((u) => (u as { id: string } | null)?.id === 'alice00000001')).toBe(true)
  })

  it('revokeUser drops every session of that user only', async () => {
    const { auth, store } = setup()
    const one = await signInAs(auth, 'alice00000001')
    const two = await signInAs(auth, 'alice00000001')
    const other = await signInAs(auth, 'bobby00000002')
    expect(store.size()).toBe(3)
    await auth.revokeUser('alice00000001')
    expect(await auth.getUser(request(one.jar))).toBeNull()
    expect(await auth.getUser(request(two.jar))).toBeNull()
    expect(await auth.getUser(request(other.jar))).not.toBeNull()
  })

  it('getAccessToken returns a token for a signed-in request', async () => {
    const { auth } = setup()
    const { jar } = await signInAs(auth, 'bobby00000002')
    expect(await auth.getAccessToken(request(jar))).toEqual(expect.any(String))
    expect(await auth.getAccessToken(new Request(ORIGIN))).toBeNull()
  })
})

describe('sign-out', () => {
  it('only answers a same-origin POST', async () => {
    const { auth } = setup()
    const { jar } = await signInAs(auth, 'alice00000001')
    expect((await auth.signOut(context(`${ORIGIN}/api/auth/sign-out`, jar))).status).toBe(405)
    const cross = context(`${ORIGIN}/api/auth/sign-out`, jar, { method: 'POST', headers: { origin: 'https://evil.example.test' } })
    expect((await auth.signOut(cross)).status).toBe(403)
    expect(await auth.getUser(request(jar))).not.toBeNull()
  })

  it('revokes, drops the local session, clears the cookie with Secure and ends the Logto session', async () => {
    const { auth, store } = setup()
    const { jar } = await signInAs(auth, 'alice00000001')
    const ctx = context(`${ORIGIN}/api/auth/sign-out`, jar, { method: 'POST', headers: { origin: ORIGIN } })
    const res = await auth.signOut(ctx)
    expect(res.status).toBe(303)
    expect(ctx.location).toContain(`${fake.endpoint}/oidc/session/end`)
    expect(new URL(ctx.location!).searchParams.get('post_logout_redirect_uri')).toBe(`${ORIGIN}/`)
    expect(jar['__Host-cg_sid']!.options).toMatchObject({ maxAge: 0, secure: true, path: '/' })
    expect(store.size()).toBe(0)
    expect(fake.requests.some((r) => r.path === '/oidc/token/revocation')).toBe(true)
  })
})
