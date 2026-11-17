import { describe, expect, it } from 'vitest'
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose'
import { BearerError, bearerToken, createBearerVerifier } from './bearer.js'

const ENDPOINT = 'https://auth.example.test'
const AUDIENCE = 'https://api.app.example.test'

async function keys() {
  const { publicKey, privateKey } = await generateKeyPair('ES384')
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES384' }
  return { privateKey: privateKey as CryptoKey, jwks: createLocalJWKSet({ keys: [jwk] }) }
}

async function token(privateKey: CryptoKey, claims: Record<string, unknown> = {}, opts: { aud?: string; iss?: string; exp?: number } = {}) {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ scope: 'read:things write:things', ...claims })
    .setProtectedHeader({ alg: 'ES384', kid: 'k1' })
    .setIssuer(opts.iss ?? `${ENDPOINT}/oidc`)
    .setAudience(opts.aud ?? AUDIENCE)
    .setSubject('user-1')
    .setIssuedAt(now)
    .setExpirationTime(opts.exp ?? now + 600)
    .sign(privateKey)
}

describe('bearerToken', () => {
  it('reads Authorization: Bearer only', () => {
    expect(bearerToken('Bearer abc.def-ghi')).toBe('abc.def-ghi')
    expect(bearerToken('bearer abc')).toBe('abc')
    expect(bearerToken('Basic abc')).toBeNull()
    expect(bearerToken(null)).toBeNull()
  })
})

describe('createBearerVerifier', () => {
  it('accepts a token for this audience and returns its claims', async () => {
    const { privateKey, jwks } = await keys()
    const verifier = createBearerVerifier({ endpoint: ENDPOINT, audience: AUDIENCE, jwks, requiredScopes: ['read:things'] })
    const req = new Request('https://api.example.test/x', { headers: { authorization: `Bearer ${await token(privateKey)}` } })
    await expect(verifier.verifyRequest(req)).resolves.toMatchObject({ sub: 'user-1' })
    // Node-style headers work too.
    await expect(verifier.verifyRequest({ headers: { authorization: `Bearer ${await token(privateKey)}` } })).resolves.toMatchObject({ sub: 'user-1' })
  })

  it('refuses another audience, issuer, an expired token and a foreign key', async () => {
    const { privateKey, jwks } = await keys()
    const other = await keys()
    const verifier = createBearerVerifier({ endpoint: ENDPOINT, audience: AUDIENCE, jwks })
    const now = Math.floor(Date.now() / 1000)
    for (const bad of [
      await token(privateKey, {}, { aud: 'https://other.example.test' }),
      await token(privateKey, {}, { iss: 'https://evil.example.test/oidc' }),
      await token(privateKey, {}, { exp: now - 60 }),
      await token(other.privateKey),
    ]) {
      await expect(verifier.verify(bad)).rejects.toMatchObject({ status: 401, code: 'invalid_token' })
    }
  })

  it('answers 401 without a token and 403 for a missing scope', async () => {
    const { privateKey, jwks } = await keys()
    const verifier = createBearerVerifier({ endpoint: ENDPOINT, audience: AUDIENCE, jwks, requiredScopes: ['admin:things'] })
    const missing = await verifier.verifyRequest(new Request('https://x.test')).catch((e: unknown) => e)
    expect(missing).toBeInstanceOf(BearerError)
    expect((missing as BearerError).toResponse().headers.get('www-authenticate')).toBe('Bearer realm="api"')
    const scoped = await verifier.verify(await token(privateKey)).catch((e: unknown) => e)
    expect(scoped).toMatchObject({ status: 403, code: 'insufficient_scope' })
    expect((scoped as BearerError).challenge()).toContain('error="insufficient_scope"')
  })
})
