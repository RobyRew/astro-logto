import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose'

// Access tokens for an API resource registered in Logto: a JWT whose `aud` is the
// resource indicator. The signature is checked against Logto's JWKS (fetched once,
// cached, re-fetched when an unknown key id shows up), then iss, aud, exp and nbf.
// Does not import @logto/node.

export interface AccessTokenClaims extends JWTPayload {
  sub: string
  /** Space-separated scopes granted for this resource. */
  scope?: string
  client_id?: string
}

export type BearerErrorCode = 'missing_token' | 'invalid_token' | 'insufficient_scope'

export class BearerError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly code: BearerErrorCode,
    readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code)
    this.name = 'BearerError'
  }

  /** Value for a WWW-Authenticate response header (RFC 6750). */
  challenge(realm = 'api'): string {
    return this.code === 'missing_token' ? `Bearer realm="${realm}"` : `Bearer realm="${realm}", error="${this.code}"`
  }

  toResponse(realm?: string): Response {
    return new Response(JSON.stringify({ error: this.code }), {
      status: this.status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'www-authenticate': this.challenge(realm) },
    })
  }
}

export interface BearerVerifierOptions {
  /** Logto endpoint, e.g. https://auth.robyrew.com (issuer = `${endpoint}/oidc`). */
  endpoint: string
  /** The API resource indicator registered in Logto; tokens for any other audience are refused. */
  audience: string
  /** Every one of these must be in the token's `scope`. */
  requiredScopes?: string[]
  /** Seconds of clock skew allowed on exp/nbf. Default 5. */
  clockToleranceSec?: number
  /** Test seam: a key resolver instead of the remote JWKS. */
  jwks?: JWTVerifyGetKey
}

type HeaderSource = Request | { headers: Headers | Record<string, string | string[] | undefined> }

function authorizationHeader(source: HeaderSource): string | null {
  const headers = source.headers as Headers | Record<string, string | string[] | undefined>
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get('authorization')
  const raw = (headers as Record<string, string | string[] | undefined>)['authorization']
  return Array.isArray(raw) ? (raw[0] ?? null) : (raw ?? null)
}

/** The token of an `Authorization: Bearer …` header, or null. */
export function bearerToken(header: string | null | undefined): string | null {
  const match = /^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)\s*$/i.exec(header ?? '')
  return match ? match[1]! : null
}

// Asymmetric algorithms only: Logto signs with its private keys (ES384 by default).
const ALGORITHMS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA']

export function createBearerVerifier(options: BearerVerifierOptions) {
  const endpoint = options.endpoint.replace(/\/+$/, '')
  const issuer = `${endpoint}/oidc`
  if (!options.audience) throw new Error('createBearerVerifier: audience is required')
  const jwks = options.jwks ?? createRemoteJWKSet(new URL(`${issuer}/jwks`), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 })
  const required = options.requiredScopes ?? []

  /** Verified claims of an access token. Throws BearerError. */
  async function verify(token: string): Promise<AccessTokenClaims> {
    let payload: JWTPayload
    try {
      ;({ payload } = await jwtVerify(token, jwks, {
        issuer,
        audience: options.audience,
        algorithms: ALGORITHMS,
        clockTolerance: options.clockToleranceSec ?? 5,
        requiredClaims: ['sub', 'exp'],
      }))
    } catch (err) {
      throw new BearerError(401, 'invalid_token', err instanceof Error ? err.message : String(err))
    }
    const granted = new Set(typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [])
    const missing = required.filter((scope) => !granted.has(scope))
    if (missing.length) throw new BearerError(403, 'insufficient_scope', missing.join(' '))
    return payload as AccessTokenClaims
  }

  /** Verified claims from a request's Authorization header. Throws BearerError. */
  async function verifyRequest(source: HeaderSource): Promise<AccessTokenClaims> {
    const token = bearerToken(authorizationHeader(source))
    if (!token) throw new BearerError(401, 'missing_token')
    return verify(token)
  }

  return { issuer, audience: options.audience, verify, verifyRequest }
}

export type BearerVerifier = ReturnType<typeof createBearerVerifier>
