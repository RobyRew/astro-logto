export declare const LOGTO_SIGNATURE_HEADER = "logto-signature-sha-256";
/** The user entity Logto puts in `data` for user events (only the fields apps here read are typed). */
export interface LogtoUserEntity {
    id: string;
    username?: string | null;
    name?: string | null;
    avatar?: string | null;
    primaryEmail?: string | null;
    customData?: Record<string, unknown>;
    isSuspended?: boolean;
    [key: string]: unknown;
}
export interface LogtoWebhookEvent {
    hookId?: string;
    deliveryId?: string;
    event: string;
    createdAt?: string;
    data?: unknown;
    params?: Record<string, string>;
    [key: string]: unknown;
}
export declare class LogtoWebhookError extends Error {
    readonly status: 400 | 401 | 405 | 413;
    readonly code: string;
    constructor(status: 400 | 401 | 405 | 413, code: string);
}
/** Constant-time check of `logto-signature-sha-256` against HMAC-SHA256(signingKey, body). */
export declare function verifyLogtoSignature(body: Uint8Array | string, signature: string | null | undefined, signingKey: string): boolean;
export interface ReadWebhookOptions {
    /** Refuse events whose `createdAt` is older than this. Default 15 minutes; 0 turns the check off. */
    maxAgeMs?: number;
    /** Largest body accepted. Default 256 KiB. */
    maxBytes?: number;
    now?: () => number;
}
/** Verifies and parses one delivery. Throws LogtoWebhookError (status + code) when it is refused. */
export declare function readLogtoWebhook(request: Request, signingKey: string, options?: ReadWebhookOptions): Promise<LogtoWebhookEvent>;
/** The user entity of a user event, or null (User.Deleted carries `data: null`). */
export declare function webhookUser(event: LogtoWebhookEvent): LogtoUserEntity | null;
/** The Logto user id an event is about: `data.id`, else the route's `params.userId`. */
export declare function webhookUserId(event: LogtoWebhookEvent): string | null;
export interface LogtoWebhookHandlerOptions {
    signingKey: string;
    /**
     * Drops the user's local sessions. Called for User.Deleted and for a suspension,
     * before the matching callback below. Pass `auth.revokeUser` from createLogtoAuth.
     */
    revokeUser?(userId: string): void | Promise<void>;
    /** User.Data.Updated: copy what the app caches (username, name, avatar…). */
    onUserDataUpdated?(user: LogtoUserEntity, event: LogtoWebhookEvent): void | Promise<void>;
    onUserDeleted?(userId: string, event: LogtoWebhookEvent): void | Promise<void>;
    /** User.SuspensionStatus.Updated, after revokeUser when the user was suspended. */
    onUserSuspensionUpdated?(userId: string, suspended: boolean, event: LogtoWebhookEvent): void | Promise<void>;
    /** Any other event the webhook is subscribed to. */
    onOtherEvent?(event: LogtoWebhookEvent): void | Promise<void>;
    maxAgeMs?: number;
    maxBytes?: number;
    logger?: Pick<Console, 'error' | 'warn'>;
}
/**
 * A POST handler for one app's Logto webhook. Answers 401 to a bad signature (Logto
 * does not retry 4xx), 500 when a callback throws (Logto retries 5xx with the same
 * deliveryId), and 200 otherwise. A deliveryId that was already handled is
 * acknowledged without running the callbacks again.
 */
export declare function createLogtoWebhookHandler(options: LogtoWebhookHandlerOptions): (request: Request) => Promise<Response>;
