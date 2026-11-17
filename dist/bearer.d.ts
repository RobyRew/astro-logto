import { type JWTPayload, type JWTVerifyGetKey } from 'jose';
export interface AccessTokenClaims extends JWTPayload {
    sub: string;
    /** Space-separated scopes granted for this resource. */
    scope?: string;
    client_id?: string;
}
export type BearerErrorCode = 'missing_token' | 'invalid_token' | 'insufficient_scope';
export declare class BearerError extends Error {
    readonly status: 401 | 403;
    readonly code: BearerErrorCode;
    readonly detail?: string | undefined;
    constructor(status: 401 | 403, code: BearerErrorCode, detail?: string | undefined);
    /** Value for a WWW-Authenticate response header (RFC 6750). */
    challenge(realm?: string): string;
    toResponse(realm?: string): Response;
}
export interface BearerVerifierOptions {
    /** Logto endpoint, e.g. https://auth.robyrew.com (issuer = `${endpoint}/oidc`). */
    endpoint: string;
    /** The API resource indicator registered in Logto; tokens for any other audience are refused. */
    audience: string;
    /** Every one of these must be in the token's `scope`. */
    requiredScopes?: string[];
    /** Seconds of clock skew allowed on exp/nbf. Default 5. */
    clockToleranceSec?: number;
    /** Test seam: a key resolver instead of the remote JWKS. */
    jwks?: JWTVerifyGetKey;
}
type HeaderSource = Request | {
    headers: Headers | Record<string, string | string[] | undefined>;
};
/** The token of an `Authorization: Bearer …` header, or null. */
export declare function bearerToken(header: string | null | undefined): string | null;
export declare function createBearerVerifier(options: BearerVerifierOptions): {
    issuer: string;
    audience: string;
    verify: (token: string) => Promise<AccessTokenClaims>;
    verifyRequest: (source: HeaderSource) => Promise<AccessTokenClaims>;
};
export type BearerVerifier = ReturnType<typeof createBearerVerifier>;
export {};
