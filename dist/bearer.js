import { createRemoteJWKSet, jwtVerify } from 'jose';
export class BearerError extends Error {
    status;
    code;
    detail;
    constructor(status, code, detail) {
        super(detail ? `${code}: ${detail}` : code);
        this.status = status;
        this.code = code;
        this.detail = detail;
        this.name = 'BearerError';
    }
    /** Value for a WWW-Authenticate response header (RFC 6750). */
    challenge(realm = 'api') {
        return this.code === 'missing_token' ? `Bearer realm="${realm}"` : `Bearer realm="${realm}", error="${this.code}"`;
    }
    toResponse(realm) {
        return new Response(JSON.stringify({ error: this.code }), {
            status: this.status,
            headers: { 'content-type': 'application/json; charset=utf-8', 'www-authenticate': this.challenge(realm) },
        });
    }
}
function authorizationHeader(source) {
    const headers = source.headers;
    if (typeof headers.get === 'function')
        return headers.get('authorization');
    const raw = headers['authorization'];
    return Array.isArray(raw) ? (raw[0] ?? null) : (raw ?? null);
}
/** The token of an `Authorization: Bearer …` header, or null. */
export function bearerToken(header) {
    const match = /^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)\s*$/i.exec(header ?? '');
    return match ? match[1] : null;
}
// Asymmetric algorithms only: Logto signs with its private keys (ES384 by default).
const ALGORITHMS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];
export function createBearerVerifier(options) {
    const endpoint = options.endpoint.replace(/\/+$/, '');
    const issuer = `${endpoint}/oidc`;
    if (!options.audience)
        throw new Error('createBearerVerifier: audience is required');
    const jwks = options.jwks ?? createRemoteJWKSet(new URL(`${issuer}/jwks`), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
    const required = options.requiredScopes ?? [];
    /** Verified claims of an access token. Throws BearerError. */
    async function verify(token) {
        let payload;
        try {
            ;
            ({ payload } = await jwtVerify(token, jwks, {
                issuer,
                audience: options.audience,
                algorithms: ALGORITHMS,
                clockTolerance: options.clockToleranceSec ?? 5,
                requiredClaims: ['sub', 'exp'],
            }));
        }
        catch (err) {
            throw new BearerError(401, 'invalid_token', err instanceof Error ? err.message : String(err));
        }
        const granted = new Set(typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : []);
        const missing = required.filter((scope) => !granted.has(scope));
        if (missing.length)
            throw new BearerError(403, 'insufficient_scope', missing.join(' '));
        return payload;
    }
    /** Verified claims from a request's Authorization header. Throws BearerError. */
    async function verifyRequest(source) {
        const token = bearerToken(authorizationHeader(source));
        if (!token)
            throw new BearerError(401, 'missing_token');
        return verify(token);
    }
    return { issuer, audience: options.audience, verify, verifyRequest };
}
