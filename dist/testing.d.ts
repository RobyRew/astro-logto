export interface FakeUser {
    id: string;
    username: string | null;
    name: string | null;
    avatar: string | null;
    primaryEmail: string | null;
    customData: Record<string, unknown>;
    isSuspended: boolean;
    roles: string[];
    createdAt: number;
    updatedAt: number;
}
export interface FakeHook {
    url: string;
    signingKey: string;
    events: string[];
}
export interface FakeLogtoOptions {
    port?: number;
    /** Traditional Web app(s) allowed to sign in: id → secret. */
    apps?: Record<string, string>;
    /** Machine-to-machine apps allowed to call the Management API: id → secret. */
    m2mApps?: Record<string, string>;
    accessTokenTtlSec?: number;
    idTokenTtlSec?: number;
    /** Users created at start. */
    users?: Array<Partial<FakeUser>>;
}
export interface FakeLogto {
    endpoint: string;
    /** Resource indicator of the Management API, as on a self-hosted Logto. */
    managementResource: string;
    users: Map<string, FakeUser>;
    addUser(user?: Partial<FakeUser>): FakeUser;
    updateUser(id: string, patch: Partial<FakeUser>): FakeUser;
    /** The user /oidc/auth approves without asking; null shows a pick list. */
    signInAs(id: string | null): void;
    /** Completes an authorization request (the URL the app redirected to) as `id`; returns the callback URL. */
    authorize(authorizationUrl: string, id: string): string;
    suspend(id: string): void;
    deleteUser(id: string): void;
    /** Make the token endpoint answer this status (e.g. 503), or null for normal service. */
    failTokenEndpoint(status: number | null): void;
    addHook(hook: FakeHook): void;
    /** Resolves when every webhook sent so far has been answered. */
    hooksSettled(): Promise<void>;
    requests: Array<{
        method: string;
        path: string;
    }>;
    close(): Promise<void>;
}
export declare function startFakeLogto(options?: FakeLogtoOptions): Promise<FakeLogto>;
