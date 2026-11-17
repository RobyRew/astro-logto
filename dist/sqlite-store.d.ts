import type { SessionStore } from './store.js';
export { memorySessionStore } from './store.js';
export type { SessionStore } from './store.js';
/**
 * Structural type for a synchronous SQLite handle: better-sqlite3's Database and
 * Node's built-in `node:sqlite` DatabaseSync both fit, and neither is a dependency.
 */
export interface SqliteLike {
    prepare(sql: string): {
        get(...params: unknown[]): unknown;
        all(...params: unknown[]): unknown[];
        run(...params: unknown[]): unknown;
    };
    exec(sql: string): unknown;
}
export interface SqliteStoreOptions {
    /** Default 'logto_sessions'. */
    table?: string;
    /** Column names, for apps whose schema predates this package. */
    columns?: {
        id?: string;
        data?: string;
        createdAt?: string;
        expiresAt?: string;
        userKey?: string;
    };
    /**
     * Create the table when missing, and add the user-key column to a table made by
     * 0.1.x. Without it the app's migrations own the table, and a table without the
     * user-key column is refused at startup.
     */
    createTable?: boolean;
}
/**
 * SessionStore on a SQLite table: id TEXT PK, data TEXT (sealed blob),
 * created_at / expires_at INTEGER (ms), user_key TEXT (indexed).
 */
export declare function sqliteSessionStore(db: SqliteLike, options?: SqliteStoreOptions): SessionStore;
