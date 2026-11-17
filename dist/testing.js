import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
const MANAGEMENT_RESOURCE = 'https://default.logto.app/api';
const USERNAME = /^[A-Z_a-z]\w*$/;
function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}
function send(res, status, body, headers = {}) {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
}
function redirect(res, location) {
    res.writeHead(302, { location });
    res.end();
}
function basicAuth(req) {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Basic '))
        return null;
    const [id, ...rest] = Buffer.from(header.slice(6), 'base64').toString('utf8').split(':');
    return id ? { id: decodeURIComponent(id), secret: decodeURIComponent(rest.join(':')) } : null;
}
const newId = () => randomBytes(9).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, 'x').slice(0, 12);
export async function startFakeLogto(options = {}) {
    const apps = options.apps ?? { 'app-id': 'app-secret' };
    const m2mApps = options.m2mApps ?? { 'm2m-id': 'm2m-secret' };
    const accessTtl = options.accessTokenTtlSec ?? 3600;
    const idTtl = options.idTokenTtlSec ?? 3600;
    const { publicKey, privateKey } = await generateKeyPair('ES384', { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: 'fake-1', alg: 'ES384', use: 'sig' };
    const users = new Map();
    const codes = new Map();
    const refreshTokens = new Map();
    const m2mTokens = new Set();
    const hooks = [];
    const pendingHooks = new Set();
    const requests = [];
    let approveAs = null;
    let tokenFailure = null;
    let endpoint = '';
    function addUser(user = {}) {
        const now = Date.now();
        const full = {
            id: user.id ?? newId(),
            username: user.username ?? null,
            name: user.name ?? null,
            avatar: user.avatar ?? null,
            primaryEmail: user.primaryEmail ?? null,
            customData: user.customData ?? {},
            isSuspended: user.isSuspended ?? false,
            roles: user.roles ?? [],
            createdAt: user.createdAt ?? now,
            updatedAt: now,
        };
        users.set(full.id, full);
        return full;
    }
    for (const user of options.users ?? [])
        addUser(user);
    function publicUser(u) {
        const { roles: _roles, ...rest } = u;
        return rest;
    }
    function fireHook(event, user, userId) {
        const payload = {
            hookId: 'fake-hook',
            deliveryId: randomBytes(8).toString('hex'),
            event,
            createdAt: new Date().toISOString(),
            params: { userId },
            data: user ? publicUser(user) : null,
        };
        const body = JSON.stringify(payload);
        for (const hook of hooks) {
            if (!hook.events.includes(event))
                continue;
            const signature = createHmac('sha256', hook.signingKey).update(body).digest('hex');
            const delivery = fetch(hook.url, {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'logto-signature-sha-256': signature },
                body,
            }).catch(() => undefined);
            pendingHooks.add(delivery);
            void delivery.finally(() => pendingHooks.delete(delivery));
        }
    }
    function updateUser(id, patch) {
        const user = users.get(id);
        if (!user)
            throw new Error(`fake logto: no user ${id}`);
        Object.assign(user, patch, { id, updatedAt: Date.now() });
        fireHook('User.Data.Updated', user, id);
        return user;
    }
    function revokeUserTokens(id) {
        for (const [token, grant] of refreshTokens)
            if (grant.sub === id)
                refreshTokens.delete(token);
    }
    async function issueTokens(sub, clientId, scopes) {
        const user = users.get(sub);
        const now = Math.floor(Date.now() / 1000);
        const claims = {};
        if (scopes.includes('profile'))
            Object.assign(claims, { name: user.name, username: user.username, picture: user.avatar });
        if (scopes.includes('email'))
            Object.assign(claims, { email: user.primaryEmail, email_verified: Boolean(user.primaryEmail) });
        if (scopes.includes('roles'))
            claims.roles = user.roles;
        const idToken = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'ES384', kid: 'fake-1' })
            .setIssuer(`${endpoint}/oidc`)
            .setAudience(clientId)
            .setSubject(sub)
            .setIssuedAt(now)
            .setExpirationTime(now + idTtl)
            .sign(privateKey);
        const refreshToken = randomBytes(24).toString('base64url');
        refreshTokens.set(refreshToken, { sub, clientId, scopes });
        return {
            access_token: randomBytes(24).toString('base64url'),
            id_token: idToken,
            refresh_token: refreshToken,
            expires_in: accessTtl,
            scope: scopes.join(' '),
            token_type: 'Bearer',
        };
    }
    const refuse = (res, status = 400) => send(res, status, { code: 'oidc.invalid_grant', message: 'Grant request is invalid.' });
    async function token(req, res, body) {
        if (tokenFailure)
            return send(res, tokenFailure, { code: 'unavailable', message: 'Service unavailable.' });
        const form = new URLSearchParams(body);
        const auth = basicAuth(req);
        const grant = form.get('grant_type');
        if (grant === 'client_credentials') {
            if (!auth || m2mApps[auth.id] !== auth.secret)
                return send(res, 401, { code: 'oidc.invalid_client', message: 'Client authentication failed.' });
            const accessToken = randomBytes(24).toString('base64url');
            m2mTokens.add(accessToken);
            return send(res, 200, { access_token: accessToken, expires_in: accessTtl, token_type: 'Bearer', scope: 'all' });
        }
        if (!auth || apps[auth.id] !== auth.secret)
            return send(res, 401, { code: 'oidc.invalid_client', message: 'Client authentication failed.' });
        if (grant === 'authorization_code') {
            const code = codes.get(form.get('code') ?? '');
            codes.delete(form.get('code') ?? '');
            const verifier = form.get('code_verifier') ?? '';
            const challenge = createHash('sha256').update(verifier).digest('base64url');
            if (!code || code.clientId !== auth.id || code.redirectUri !== form.get('redirect_uri') || code.challenge !== challenge)
                return refuse(res);
            const user = users.get(code.sub);
            if (!user || user.isSuspended)
                return refuse(res);
            return send(res, 200, await issueTokens(code.sub, auth.id, code.scopes));
        }
        if (grant === 'refresh_token') {
            const old = refreshTokens.get(form.get('refresh_token') ?? '');
            if (!old || old.clientId !== auth.id)
                return refuse(res);
            const user = users.get(old.sub);
            if (!user || user.isSuspended)
                return refuse(res);
            refreshTokens.delete(form.get('refresh_token') ?? '');
            return send(res, 200, await issueTokens(old.sub, auth.id, old.scopes));
        }
        return send(res, 400, { code: 'oidc.unsupported_grant_type', message: 'Unsupported grant type.' });
    }
    function approve(params, sub) {
        const code = randomBytes(16).toString('base64url');
        const redirectUri = params.get('redirect_uri') ?? '';
        codes.set(code, {
            sub,
            clientId: params.get('client_id') ?? '',
            redirectUri,
            challenge: params.get('code_challenge') ?? '',
            scopes: (params.get('scope') ?? '').split(' ').filter(Boolean),
        });
        const target = new URL(redirectUri);
        target.searchParams.set('code', code);
        target.searchParams.set('state', params.get('state') ?? '');
        return target.toString();
    }
    function authPage(res, params) {
        const rows = [...users.values()]
            .filter((u) => !u.isSuspended)
            .map((u) => {
            const q = new URLSearchParams(params);
            q.set('as', u.id);
            const label = `${u.username ?? '(no username)'} — ${u.name ?? ''} ${u.id}`;
            return `<li><a href="/oidc/auth?${q.toString().replace(/&/g, '&amp;')}">${label.replace(/[<>&"]/g, '')}</a></li>`;
        })
            .join('');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(`<!doctype html><meta charset="utf-8"><title>Fake Logto</title><h1>Fake Logto: sign in as</h1><ul>${rows}</ul>`);
    }
    function management(req, res, url, body) {
        const bearer = (req.headers.authorization ?? '').replace(/^Bearer /, '');
        if (!m2mTokens.has(bearer))
            return send(res, 401, { code: 'auth.unauthorized', message: 'Unauthorized.' });
        const match = /^\/api\/users(?:\/([^/]+))?(?:\/(custom-data|is-suspended))?$/.exec(url.pathname);
        if (!match)
            return send(res, 404, { code: 'guard.not_found', message: 'Not found.' });
        const [, id, sub] = match;
        if (!id) {
            if (req.method !== 'GET')
                return send(res, 405, {});
            const page = Math.max(1, Number(url.searchParams.get('page') ?? 1));
            const size = Math.min(100, Math.max(1, Number(url.searchParams.get('page_size') ?? 20)));
            let list = [...users.values()];
            const username = url.searchParams.get('search.username');
            if (username !== null)
                list = list.filter((u) => u.username === username);
            const slice = list.slice((page - 1) * size, page * size).map(publicUser);
            return send(res, 200, slice, { 'total-number': String(list.length) });
        }
        const user = users.get(decodeURIComponent(id));
        if (!user)
            return send(res, 404, { code: 'entity.not_exists_with_id', message: 'User not found.' });
        let input = {};
        if (body) {
            try {
                input = JSON.parse(body);
            }
            catch {
                return send(res, 400, { code: 'guard.invalid_input', message: 'Bad JSON.' });
            }
        }
        if (req.method === 'GET' && !sub)
            return send(res, 200, publicUser(user));
        if (req.method === 'DELETE' && !sub) {
            users.delete(user.id);
            revokeUserTokens(user.id);
            fireHook('User.Deleted', null, user.id);
            res.writeHead(204);
            return res.end();
        }
        if (req.method !== 'PATCH')
            return send(res, 405, {});
        if (sub === 'custom-data') {
            const customData = input.customData;
            return send(res, 200, updateUser(user.id, { customData: { ...user.customData, ...customData } }).customData);
        }
        if (sub === 'is-suspended') {
            const isSuspended = input.isSuspended === true;
            if (isSuspended)
                revokeUserTokens(user.id);
            Object.assign(user, { isSuspended, updatedAt: Date.now() });
            fireHook('User.SuspensionStatus.Updated', user, user.id);
            return send(res, 200, publicUser(user));
        }
        const patch = {};
        if ('username' in input) {
            const username = input.username;
            if (username !== null && (typeof username !== 'string' || !USERNAME.test(username))) {
                return send(res, 400, { code: 'guard.invalid_input', message: 'Invalid username.' });
            }
            if (username && [...users.values()].some((u) => u.id !== user.id && u.username === username)) {
                return send(res, 422, { code: 'user.username_already_in_use', message: 'This username is already in use.' });
            }
            patch.username = username;
        }
        if ('avatar' in input) {
            const avatar = input.avatar;
            if (avatar !== null && avatar !== '' && (typeof avatar !== 'string' || !/^https?:\/\//.test(avatar))) {
                return send(res, 400, { code: 'guard.invalid_input', message: 'Invalid avatar URL.' });
            }
            patch.avatar = avatar || null;
        }
        if ('name' in input)
            patch.name = input.name;
        if ('customData' in input)
            patch.customData = (input.customData ?? {});
        return send(res, 200, publicUser(updateUser(user.id, patch)));
    }
    const server = createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', endpoint);
        requests.push({ method: req.method ?? 'GET', path: url.pathname });
        try {
            const body = req.method === 'GET' ? '' : await readBody(req);
            switch (url.pathname) {
                case '/oidc/.well-known/openid-configuration':
                    return send(res, 200, {
                        issuer: `${endpoint}/oidc`,
                        authorization_endpoint: `${endpoint}/oidc/auth`,
                        token_endpoint: `${endpoint}/oidc/token`,
                        end_session_endpoint: `${endpoint}/oidc/session/end`,
                        revocation_endpoint: `${endpoint}/oidc/token/revocation`,
                        jwks_uri: `${endpoint}/oidc/jwks`,
                        userinfo_endpoint: `${endpoint}/oidc/me`,
                    });
                case '/oidc/jwks':
                    return send(res, 200, { keys: [jwk] });
                case '/oidc/auth': {
                    const as = url.searchParams.get('as') ?? approveAs;
                    if (as && users.get(as) && !users.get(as).isSuspended)
                        return redirect(res, approve(url.searchParams, as));
                    return authPage(res, url.searchParams);
                }
                case '/oidc/token':
                    return token(req, res, body);
                case '/oidc/token/revocation': {
                    const form = new URLSearchParams(body);
                    refreshTokens.delete(form.get('token') ?? '');
                    res.writeHead(200);
                    return res.end();
                }
                case '/oidc/session/end': {
                    const target = url.searchParams.get('post_logout_redirect_uri');
                    if (target)
                        return redirect(res, target);
                    res.writeHead(200, { 'content-type': 'text/plain' });
                    return res.end('signed out');
                }
                default:
                    if (url.pathname.startsWith('/api/'))
                        return management(req, res, url, body);
                    return send(res, 404, { code: 'not_found' });
            }
        }
        catch (err) {
            send(res, 500, { code: 'fake_error', message: err instanceof Error ? err.message : String(err) });
        }
    });
    await new Promise((resolve) => server.listen(options.port ?? 0, '127.0.0.1', resolve));
    endpoint = `http://127.0.0.1:${server.address().port}`;
    return {
        get endpoint() {
            return endpoint;
        },
        managementResource: MANAGEMENT_RESOURCE,
        users,
        addUser,
        updateUser,
        signInAs(id) {
            approveAs = id;
        },
        authorize(authorizationUrl, id) {
            return approve(new URL(authorizationUrl).searchParams, id);
        },
        suspend(id) {
            const user = users.get(id);
            if (!user)
                return;
            user.isSuspended = true;
            revokeUserTokens(id);
            fireHook('User.SuspensionStatus.Updated', user, id);
        },
        deleteUser(id) {
            users.delete(id);
            revokeUserTokens(id);
            fireHook('User.Deleted', null, id);
        },
        failTokenEndpoint(status) {
            tokenFailure = status;
        },
        addHook(hook) {
            hooks.push(hook);
        },
        async hooksSettled() {
            while (pendingHooks.size)
                await Promise.all([...pendingHooks]);
        },
        requests,
        close: () => new Promise((resolve, reject) => {
            server.closeAllConnections();
            server.close((err) => (err ? reject(err) : resolve()));
        }),
    };
}
