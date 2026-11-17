/** 3–20 characters: lowercase letters, digits and underscore; starts with a letter or underscore. */
export declare const HANDLE_PATTERN: RegExp;
/** The same rule as a string, for `<input pattern>` (which anchors it) and for docs. */
export declare const HANDLE_PATTERN_SOURCE = "[a-z_][a-z0-9_]{2,19}";
export declare const HANDLE_MIN_LENGTH = 3;
export declare const HANDLE_MAX_LENGTH = 20;
/**
 * Words nobody can pick as a handle: MapSwitch's original list, every app's
 * top-level routes (MapSwitch, ChatForge, spotify-versions-history, robyrew-id),
 * role and brand names, and words that read like system or staff accounts.
 * Words shorter than 3 characters or with a hyphen can never pass the pattern;
 * they stay listed so the list documents every route it was built from.
 */
export declare const RESERVED_HANDLES: ReadonlySet<string>;
export type HandleProblem = 'empty' | 'too_short' | 'too_long' | 'bad_start' | 'bad_chars' | 'reserved';
export type HandleCheck = {
    ok: true;
    handle: string;
} | {
    ok: false;
    handle: string;
    problem: HandleProblem;
};
/** What a person typed → the form the rule is checked against: trimmed, one leading @ dropped, lowercased. */
export declare function normalizeHandle(raw: string): string;
export declare function isReservedHandle(handle: string): boolean;
/**
 * True when `value` is exactly a handle (already normalized). Reserved words pass:
 * they only stop self-service picks, so a handle an admin assigned still shows.
 */
export declare function isHandle(value: unknown): value is string;
/** True when `handle` may be picked in self-service: a handle and not reserved. */
export declare function canChooseHandle(handle: unknown): handle is string;
/** Normalizes `raw` and says which part of the self-service rule it breaks, for form messages. */
export declare function checkHandle(raw: string): HandleCheck;
/** English messages for HandleProblem; apps with their own i18n map the codes themselves. */
export declare const HANDLE_PROBLEM_MESSAGES: Readonly<Record<HandleProblem, string>>;
/**
 * The handle carried by verified ID-token claims, or null. The Logto username is
 * used as-is: one that breaks the rule (Logto's own sign-up form allows capitals
 * and any length) is not lowercased into a handle someone else may hold.
 */
export declare function handleFromClaims(claims: {
    username?: unknown;
} | null | undefined): string | null;
/**
 * What an app shows for a person without a valid handle: `user-` and the first six
 * characters of their Logto user id. The hyphen keeps it outside the handle rule,
 * so it can never be mistaken for, or collide with, a chosen handle.
 */
export declare function fallbackHandle(sub: string): string;
/** The handle when there is a valid one, else the fallback. */
export declare function displayHandle(claims: {
    sub: string;
    username?: unknown;
}): string;
/**
 * A rule-abiding candidate for a legacy handle (an older app rule, or a Logto
 * username with capitals): lowercased, `-` `.` and spaces turned into `_`, other
 * characters dropped, a leading digit prefixed with `_`, cut to 20 characters.
 * Null when nothing usable is left or the result is reserved. It only proposes a
 * name; whether it is free is for the caller to check.
 */
export declare function suggestHandle(raw: string): string | null;
