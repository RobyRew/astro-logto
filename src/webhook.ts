import { createHmac, timingSafeEqual } from 'node:crypto'

// Logto webhooks: Logto signs the raw request body with the webhook's signing key
// (HMAC-SHA256, hex digest) in the `logto-signature-sha-256` header, and retries a
// delivery that got a 5xx response, with the same `deliveryId`.
// Framework-agnostic: takes a standard Request, returns a Response. Does not import
// @logto/node, so an app can use it without the session part of this package.

export const LOGTO_SIGNATURE_HEADER = 'logto-signature-sha-256'

/** The user entity Logto puts in `data` for user events (only the fields apps here read are typed). */
export interface LogtoUserEntity {
  id: string
  username?: string | null
  name?: string | null
  avatar?: string | null
  primaryEmail?: string | null
  customData?: Record<string, unknown>
  isSuspended?: boolean
  [key: string]: unknown
}

export interface LogtoWebhookEvent {
  hookId?: string
  deliveryId?: string
  event: string
  createdAt?: string
  data?: unknown
  params?: Record<string, string>
  [key: string]: unknown
}

export class LogtoWebhookError extends Error {
  constructor(
    readonly status: 400 | 401 | 405 | 413,
    readonly code: string,
  ) {
    super(code)
    this.name = 'LogtoWebhookError'
  }
}

/** Constant-time check of `logto-signature-sha-256` against HMAC-SHA256(signingKey, body). */
export function verifyLogtoSignature(body: Uint8Array | string, signature: string | null | undefined, signingKey: string): boolean {
  if (!signature || !signingKey) return false
  const hex = signature.trim().replace(/^sha256=/i, '')
  if (!/^[0-9a-f]{64}$/i.test(hex)) return false
  const expected = createHmac('sha256', signingKey).update(body).digest()
  return timingSafeEqual(Buffer.from(hex, 'hex'), expected)
}

export interface ReadWebhookOptions {
  /** Refuse events whose `createdAt` is older than this. Default 15 minutes; 0 turns the check off. */
  maxAgeMs?: number
  /** Largest body accepted. Default 256 KiB. */
  maxBytes?: number
  now?: () => number
}

/** Verifies and parses one delivery. Throws LogtoWebhookError (status + code) when it is refused. */
export async function readLogtoWebhook(request: Request, signingKey: string, options: ReadWebhookOptions = {}): Promise<LogtoWebhookEvent> {
  const maxBytes = options.maxBytes ?? 256 * 1024
  const maxAgeMs = options.maxAgeMs ?? 15 * 60_000
  const now = options.now ?? Date.now
  if (request.method !== 'POST') throw new LogtoWebhookError(405, 'method_not_allowed')
  const declared = Number(request.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > maxBytes) throw new LogtoWebhookError(413, 'body_too_large')
  const body = new Uint8Array(await request.arrayBuffer())
  if (body.byteLength > maxBytes) throw new LogtoWebhookError(413, 'body_too_large')
  if (!verifyLogtoSignature(body, request.headers.get(LOGTO_SIGNATURE_HEADER), signingKey)) {
    throw new LogtoWebhookError(401, 'bad_signature')
  }
  let event: unknown
  try {
    event = JSON.parse(new TextDecoder().decode(body))
  } catch {
    throw new LogtoWebhookError(400, 'bad_json')
  }
  if (!event || typeof event !== 'object' || typeof (event as LogtoWebhookEvent).event !== 'string') {
    throw new LogtoWebhookError(400, 'bad_event')
  }
  const createdAt = Date.parse(String((event as LogtoWebhookEvent).createdAt ?? ''))
  if (maxAgeMs > 0 && Number.isFinite(createdAt) && now() - createdAt > maxAgeMs) {
    throw new LogtoWebhookError(400, 'stale_event')
  }
  return event as LogtoWebhookEvent
}

/** The user entity of a user event, or null (User.Deleted carries `data: null`). */
export function webhookUser(event: LogtoWebhookEvent): LogtoUserEntity | null {
  const data = event.data as LogtoUserEntity | null | undefined
  return data && typeof data === 'object' && typeof data.id === 'string' ? data : null
}

/** The Logto user id an event is about: `data.id`, else the route's `params.userId`. */
export function webhookUserId(event: LogtoWebhookEvent): string | null {
  const fromData = webhookUser(event)?.id
  if (fromData) return fromData
  const fromParams = event.params?.userId
  return typeof fromParams === 'string' && fromParams ? fromParams : null
}

export interface LogtoWebhookHandlerOptions {
  signingKey: string
  /**
   * Drops the user's local sessions. Called for User.Deleted and for a suspension,
   * before the matching callback below. Pass `auth.revokeUser` from createLogtoAuth.
   */
  revokeUser?(userId: string): void | Promise<void>
  /** User.Data.Updated: copy what the app caches (username, name, avatar…). */
  onUserDataUpdated?(user: LogtoUserEntity, event: LogtoWebhookEvent): void | Promise<void>
  onUserDeleted?(userId: string, event: LogtoWebhookEvent): void | Promise<void>
  /** User.SuspensionStatus.Updated, after revokeUser when the user was suspended. */
  onUserSuspensionUpdated?(userId: string, suspended: boolean, event: LogtoWebhookEvent): void | Promise<void>
  /** Any other event the webhook is subscribed to. */
  onOtherEvent?(event: LogtoWebhookEvent): void | Promise<void>
  maxAgeMs?: number
  maxBytes?: number
  logger?: Pick<Console, 'error' | 'warn'>
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })

/**
 * A POST handler for one app's Logto webhook. Answers 401 to a bad signature (Logto
 * does not retry 4xx), 500 when a callback throws (Logto retries 5xx with the same
 * deliveryId), and 200 otherwise. A deliveryId that was already handled is
 * acknowledged without running the callbacks again.
 */
export function createLogtoWebhookHandler(options: LogtoWebhookHandlerOptions): (request: Request) => Promise<Response> {
  if (!options.signingKey) throw new Error('createLogtoWebhookHandler: signingKey is required')
  const log = options.logger ?? console
  const handled = new Set<string>()
  const remember = (deliveryId: string | undefined) => {
    if (!deliveryId) return
    handled.add(deliveryId)
    if (handled.size > 1000) handled.delete(handled.values().next().value as string)
  }

  return async (request) => {
    let event: LogtoWebhookEvent
    try {
      event = await readLogtoWebhook(request, options.signingKey, { maxAgeMs: options.maxAgeMs, maxBytes: options.maxBytes })
    } catch (err) {
      if (err instanceof LogtoWebhookError) {
        log.warn(`[logto-webhook] refused: ${err.code}`)
        return json(err.status, { error: err.code })
      }
      throw err
    }
    if (event.deliveryId && handled.has(event.deliveryId)) return json(200, { ok: true, duplicate: true })

    try {
      const userId = webhookUserId(event)
      switch (event.event) {
        case 'User.Data.Updated': {
          const user = webhookUser(event)
          if (user) await options.onUserDataUpdated?.(user, event)
          break
        }
        case 'User.Deleted':
          if (userId) {
            await options.revokeUser?.(userId)
            await options.onUserDeleted?.(userId, event)
          }
          break
        case 'User.SuspensionStatus.Updated': {
          if (!userId) break
          // A payload without the flag is treated as a suspension: signing someone out
          // by mistake costs one sign-in, keeping a suspended user signed in costs more.
          const suspended = webhookUser(event)?.isSuspended !== false
          if (suspended) await options.revokeUser?.(userId)
          await options.onUserSuspensionUpdated?.(userId, suspended, event)
          break
        }
        default:
          await options.onOtherEvent?.(event)
      }
    } catch (err) {
      log.error(`[logto-webhook] ${event.event} failed:`, err instanceof Error ? err.message : String(err))
      return json(500, { error: 'handler_failed' })
    }
    remember(event.deliveryId)
    return json(200, { ok: true })
  }
}
