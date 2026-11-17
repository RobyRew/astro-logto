export declare const MIN_SESSION_SECRET_LENGTH = 32;
export interface SessionKeys {
    seal(plaintext: string, context: string): string;
    /** The plaintext, or null for a blob that is malformed, from another key, or tampered with. */
    open(sealed: string, context: string): string | null;
    rowId(sessionId: string): string;
    userKey(sub: string): string;
}
export declare function deriveSessionKeys(secret: string): SessionKeys;
