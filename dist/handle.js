// The one @handle rule for every RobyRew app. The Logto `username` is the handle;
// apps read it from the ID token (`profile` scope) and display it only when it
// passes this rule. id.robyrew.com is the only place a handle is chosen or changed.
//
// Pure module: no Node built-ins, so browser code (a live availability hint in a
// form) can import it as well as servers.
/** 3–20 characters: lowercase letters, digits and underscore; starts with a letter or underscore. */
export const HANDLE_PATTERN = /^[a-z_][a-z0-9_]{2,19}$/;
/** The same rule as a string, for `<input pattern>` (which anchors it) and for docs. */
export const HANDLE_PATTERN_SOURCE = '[a-z_][a-z0-9_]{2,19}';
export const HANDLE_MIN_LENGTH = 3;
export const HANDLE_MAX_LENGTH = 20;
/**
 * Words nobody can pick as a handle: MapSwitch's original list, every app's
 * top-level routes (MapSwitch, ChatForge, spotify-versions-history, robyrew-id),
 * role and brand names, and words that read like system or staff accounts.
 * Words shorter than 3 characters or with a hyphen can never pass the pattern;
 * they stay listed so the list documents every route it was built from.
 */
export const RESERVED_HANDLES = new Set([
    // MapSwitch src/lib/share/slug.ts (before the global rule)
    'api', 'x', 'o', 'go', 'en', 'es', 'ca', 'ro', 'account', 'settings', 'use',
    'privacy', 'about', 'share', 'admin', 'www', 'app', 'assets', 'favicon',
    'robots', 'manifest', 'sw', 'offline', 'null', 'undefined',
    // MapSwitch routes
    'share-target', 'share_target', 'links', 'places', 'preferences', 'resolve', 'expand', 'geoip',
    // ChatForge routes
    'chat', 'dashboard', 'health', 'blobs', 'conversions', 'integrations', 'vault', 'me', 'auth', 'callback',
    // spotify-versions-history routes
    'r', 'release', 'releases', 'probes', 'catalog', 'counts', 'ingest', 'v1',
    // robyrew-id routes
    'avatars', 'avatar', 'directory', 'handle', 'handles', 'hooks', 'webhook', 'webhooks',
    // auth words
    'login', 'logout', 'signin', 'signout', 'sign_in', 'sign_out', 'signup', 'sign_up',
    'register', 'oauth', 'oidc', 'sso', 'session', 'sessions', 'token', 'tokens', 'password',
    // roles, staff and system accounts
    'root', 'system', 'sysadmin', 'administrator', 'moderator', 'moderators', 'mod', 'mods',
    'owner', 'staff', 'team', 'official', 'support', 'help', 'helpdesk', 'security', 'abuse',
    'postmaster', 'hostmaster', 'webmaster', 'noreply', 'no_reply', 'mailer_daemon', 'info',
    'contact', 'status', 'billing', 'legal', 'terms', 'docs', 'bot', 'bots',
    // brands
    'robyrew', 'logto', 'mapswitch', 'chatforge',
    // generic names that read as a page, not a person
    'user', 'users', 'profile', 'profiles', 'id', 'ids', 'new', 'edit', 'delete', 'search',
    'explore', 'home', 'index', 'static', 'public', 'cdn', 'media', 'files', 'download',
    'downloads', 'upload', 'uploads', 'well_known', 'everyone', 'here', 'all', 'nobody',
    'anonymous', 'guest', 'deleted', 'unknown', 'true', 'false', 'nan', 'void', 'test',
]);
/** What a person typed → the form the rule is checked against: trimmed, one leading @ dropped, lowercased. */
export function normalizeHandle(raw) {
    return raw.normalize('NFKC').trim().replace(/^@/, '').toLowerCase();
}
export function isReservedHandle(handle) {
    return RESERVED_HANDLES.has(handle);
}
/**
 * True when `value` is exactly a handle (already normalized). Reserved words pass:
 * they only stop self-service picks, so a handle an admin assigned still shows.
 */
export function isHandle(value) {
    return typeof value === 'string' && HANDLE_PATTERN.test(value);
}
/** True when `handle` may be picked in self-service: a handle and not reserved. */
export function canChooseHandle(handle) {
    return isHandle(handle) && !RESERVED_HANDLES.has(handle);
}
/** Normalizes `raw` and says which part of the self-service rule it breaks, for form messages. */
export function checkHandle(raw) {
    const handle = normalizeHandle(raw);
    if (!handle)
        return { ok: false, handle, problem: 'empty' };
    if (handle.length < HANDLE_MIN_LENGTH)
        return { ok: false, handle, problem: 'too_short' };
    if (handle.length > HANDLE_MAX_LENGTH)
        return { ok: false, handle, problem: 'too_long' };
    if (!/^[a-z0-9_]+$/.test(handle))
        return { ok: false, handle, problem: 'bad_chars' };
    if (!/^[a-z_]/.test(handle))
        return { ok: false, handle, problem: 'bad_start' };
    if (RESERVED_HANDLES.has(handle))
        return { ok: false, handle, problem: 'reserved' };
    return { ok: true, handle };
}
/** English messages for HandleProblem; apps with their own i18n map the codes themselves. */
export const HANDLE_PROBLEM_MESSAGES = {
    empty: 'Choose a handle.',
    too_short: `Use at least ${HANDLE_MIN_LENGTH} characters.`,
    too_long: `Use at most ${HANDLE_MAX_LENGTH} characters.`,
    bad_start: 'Start with a letter or an underscore.',
    bad_chars: 'Use only lowercase letters, digits and underscores.',
    reserved: 'That handle is reserved.',
};
/**
 * The handle carried by verified ID-token claims, or null. The Logto username is
 * used as-is: one that breaks the rule (Logto's own sign-up form allows capitals
 * and any length) is not lowercased into a handle someone else may hold.
 */
export function handleFromClaims(claims) {
    const username = claims?.username;
    return isHandle(username) ? username : null;
}
/**
 * What an app shows for a person without a valid handle: `user-` and the first six
 * characters of their Logto user id. The hyphen keeps it outside the handle rule,
 * so it can never be mistaken for, or collide with, a chosen handle.
 */
export function fallbackHandle(sub) {
    return `user-${sub.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6)}`;
}
/** The handle when there is a valid one, else the fallback. */
export function displayHandle(claims) {
    return handleFromClaims(claims) ?? fallbackHandle(claims.sub);
}
/**
 * A rule-abiding candidate for a legacy handle (an older app rule, or a Logto
 * username with capitals): lowercased, `-` `.` and spaces turned into `_`, other
 * characters dropped, a leading digit prefixed with `_`, cut to 20 characters.
 * Null when nothing usable is left or the result is reserved. It only proposes a
 * name; whether it is free is for the caller to check.
 */
export function suggestHandle(raw) {
    let s = normalizeHandle(raw).replace(/[-.\s]+/g, '_').replace(/[^a-z0-9_]/g, '');
    if (/^[0-9]/.test(s))
        s = `_${s}`;
    s = s.slice(0, HANDLE_MAX_LENGTH);
    return canChooseHandle(s) ? s : null;
}
