import LogtoClient, { type IdTokenClaims } from '@logto/node';
import type { SessionStore } from './store.js';
export type { SessionStore } from './store.js';
export { memorySessionStore } from './store.js';
export type LogtoClaims = IdTokenClaims;
/** Requested by default; `openid` is always added by the SDK. */
export declare const DEFAULT_SCOPES: readonly string[];
export interface CookieOptions {
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'lax' | 'strict';
    path: string;
    maxAge: number;
}
/** The subset of Astro's APIContext the handlers use (keeps the package independent of Astro's version). */
export interface RouteContext {
    url: URL;
    request: Request;
    cookies: {
        get(name: string): {
            value: string;
        } | undefined;
        set(name: string, value: string, options: CookieOptions): void;
    };
    redirect(path: string, status?: 301 | 302 | 303 | 307 | 308): Response;
}
/** A fetch Request, or anything with Node-style headers (IncomingMessage). */
export type RequestLike = Request | {
    headers: Headers | Record<string, string | string[] | undefined>;
};
type ClientAdapter = ConstructorParameters<typeof LogtoClient>[1];
export interface LogtoAuthOptions<User> {
    /** Logto endpoint, e.g. https://auth.robyrew.com (the SDK derives /oidc from discovery). */
    endpoint: string;
    appId: string;
    /** Traditional Web app secret: server env only, never in the client bundle. */
    appSecret: string;
    /**
     * The app's public origin (https://calendar.robyrew.com). Behind Traefik the
     * request arrives as http://…, so redirect URIs are built from this instead.
     * An https origin also switches the cookies to Secure + the `__Host-` prefix.
     */
    publicOrigin: string;
    /** Base name of the session cookie, e.g. 'cg_sid'. */
    cookieName: string;
    store: SessionStore;
    /**
     * At least 32 characters of secret material (`openssl rand -base64 32`, env
     * LOGTO_COOKIE_SECRET). Seals session rows and keys their ids. Changing it signs
     * everyone out: rows sealed under the old secret no longer open and are dropped.
     */
    sessionSecret: string;
    /** Map verified ID-token claims to the app's local user (upsert by `sub`). Called on every authenticated request. */
    resolveUser(claims: LogtoClaims): User | Promise<User>;
    /** Scopes; `openid` is always added by the SDK. Default: email, profile, offline_access, roles. */
    scopes?: string[];
    /** API resource indicators the app asks access tokens for (getAccessToken). */
    resources?: string[];
    /** Session lifetime, extended on each write. Default 14 days. */
    sessionTtlMs?: number;
    /** How long a session is trusted before Logto is asked again (refresh grant). Default 10 minutes. */
    revalidateAfterMs?: number;
    /** Timeout for each call to Logto. Default 8 seconds. */
    requestTimeoutMs?: number;
    paths?: {
        /** Registered redirect URI path. Default /api/auth/callback. */
        callback?: string;
        /** Where a failed callback lands (with ?auth_error=1). Default /. */
        afterError?: string;
        /** Registered post-sign-out redirect path. Default /. */
        afterSignOut?: string;
    };
    logger?: Pick<Console, 'error' | 'warn'>;
    /** Test seam: override parts of the SDK adapter (e.g. `requester`). */
    adapter?: Partial<ClientAdapter>;
}
export interface LogtoSession<User> {
    user: User;
    claims: LogtoClaims;
    sub: string;
}
/** Only same-site paths; blocks open redirects through ?returnTo=//evil.example. */
export declare function sanitizeReturnTo(raw: string | null | undefined): string;
export declare function readCookie(header: string | null | undefined, name: string): string | null;
/**
 * True when Logto answered and refused the grant (revoked or expired refresh
 * token, suspended or deleted user, invalid client). Network errors, timeouts,
 * 5xx and 429 are not refusals.
 */
export declare function isLogtoRefusal(err: unknown): boolean;
export declare function createLogtoAuth<User>(opts: LogtoAuthOptions<User>): {
    getUser: (request: RequestLike) => Promise<User | null>;
    getSession: (request: RequestLike) => Promise<LogtoSession<User> | null>;
    getAccessToken: (request: RequestLike, resource?: string) => Promise<string | null>;
    signIn: (ctx: RouteContext) => Promise<Response>;
    callback: (ctx: RouteContext) => Promise<Response>;
    signOut: (ctx: RouteContext) => Promise<Response>;
    revokeUser: (sub: string) => Promise<void>;
    cookieName: string;
};
export type LogtoAuth<User> = ReturnType<typeof createLogtoAuth<User>>;
