/**
 * Where sessions are kept. Rows are opaque: `blob` is sealed (AES-256-GCM) by
 * createLogtoAuth before it reaches the store, `id` is an HMAC of the cookie value,
 * and `userKey` is an HMAC of the Logto `sub` (null while sign-in is in progress).
 */
export interface SessionStore {
    /** The sealed blob, or null when the row is unknown or expired. */
    load(id: string): string | null | Promise<string | null>;
    save(id: string, blob: string, expiresAt: number, userKey: string | null): void | Promise<void>;
    drop(id: string): void | Promise<void>;
    /** Delete every session of one user (suspension, deletion, sign-out everywhere). */
    dropUser(userKey: string): void | Promise<void>;
    /** Delete rows that expired before `now` (called on sign-in). */
    prune?(now: number): void | Promise<void>;
}
/** In-memory store for tests and local experiments. */
export declare function memorySessionStore(): SessionStore & {
    size(): number;
    rows(): ReadonlyMap<string, {
        blob: string;
        expiresAt: number;
        userKey: string | null;
    }>;
};
