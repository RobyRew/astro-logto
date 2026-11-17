import { createHmac } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { createLogtoWebhookHandler, LOGTO_SIGNATURE_HEADER, readLogtoWebhook, verifyLogtoSignature } from './webhook.js'

const KEY = 'signing-key'
const sign = (body: string, key = KEY) => createHmac('sha256', key).update(body).digest('hex')

function delivery(payload: Record<string, unknown>, opts: { key?: string; signature?: string; method?: string } = {}) {
  const body = JSON.stringify({ createdAt: new Date().toISOString(), ...payload })
  return new Request('https://app.example.test/api/hooks/logto', {
    method: opts.method ?? 'POST',
    headers: { 'content-type': 'application/json', [LOGTO_SIGNATURE_HEADER]: opts.signature ?? sign(body, opts.key) },
    ...(opts.method === 'GET' ? {} : { body }),
  })
}

const quiet = { error: () => {}, warn: () => {} }

describe('verifyLogtoSignature', () => {
  it('accepts the hex HMAC of the raw body only', () => {
    expect(verifyLogtoSignature('{"a":1}', sign('{"a":1}'), KEY)).toBe(true)
    expect(verifyLogtoSignature('{"a":1}', `sha256=${sign('{"a":1}')}`, KEY)).toBe(true)
    expect(verifyLogtoSignature('{"a": 1}', sign('{"a":1}'), KEY)).toBe(false)
    expect(verifyLogtoSignature('{"a":1}', sign('{"a":1}', 'other'), KEY)).toBe(false)
    expect(verifyLogtoSignature('{"a":1}', null, KEY)).toBe(false)
    expect(verifyLogtoSignature('{"a":1}', 'zz', KEY)).toBe(false)
  })
})

describe('readLogtoWebhook', () => {
  it('refuses stale events and other methods', async () => {
    const old = JSON.stringify({ event: 'User.Data.Updated', createdAt: new Date(Date.now() - 3_600_000).toISOString() })
    const stale = new Request('https://x.test/h', { method: 'POST', body: old, headers: { [LOGTO_SIGNATURE_HEADER]: sign(old) } })
    await expect(readLogtoWebhook(stale, KEY)).rejects.toMatchObject({ status: 400, code: 'stale_event' })
    await expect(readLogtoWebhook(delivery({ event: 'X' }, { method: 'GET' }), KEY)).rejects.toMatchObject({ status: 405 })
  })
})

describe('createLogtoWebhookHandler', () => {
  it('answers 401 to a bad signature and runs nothing', async () => {
    const onUserDataUpdated = vi.fn()
    const handler = createLogtoWebhookHandler({ signingKey: KEY, onUserDataUpdated, logger: quiet })
    const res = await handler(delivery({ event: 'User.Data.Updated', data: { id: 'u1' } }, { key: 'wrong' }))
    expect(res.status).toBe(401)
    expect(onUserDataUpdated).not.toHaveBeenCalled()
  })

  it('passes user updates through and acknowledges a repeated delivery once', async () => {
    const onUserDataUpdated = vi.fn()
    const handler = createLogtoWebhookHandler({ signingKey: KEY, onUserDataUpdated, logger: quiet })
    const payload = { event: 'User.Data.Updated', deliveryId: 'd1', data: { id: 'u1', username: 'bob' } }
    expect((await handler(delivery(payload))).status).toBe(200)
    expect((await handler(delivery(payload))).status).toBe(200)
    expect(onUserDataUpdated).toHaveBeenCalledTimes(1)
    expect(onUserDataUpdated.mock.calls[0]![0]).toMatchObject({ id: 'u1', username: 'bob' })
  })

  it('revokes sessions on deletion (data: null, id from params) and on suspension', async () => {
    const revokeUser = vi.fn()
    const onUserSuspensionUpdated = vi.fn()
    const handler = createLogtoWebhookHandler({ signingKey: KEY, revokeUser, onUserSuspensionUpdated, logger: quiet })
    await handler(delivery({ event: 'User.Deleted', data: null, params: { userId: 'gone' } }))
    await handler(delivery({ event: 'User.SuspensionStatus.Updated', data: { id: 'sus', isSuspended: true } }))
    await handler(delivery({ event: 'User.SuspensionStatus.Updated', data: { id: 'back', isSuspended: false } }))
    expect(revokeUser.mock.calls.map((c) => c[0])).toEqual(['gone', 'sus'])
    expect(onUserSuspensionUpdated.mock.calls.map((c) => [c[0], c[1]])).toEqual([
      ['sus', true],
      ['back', false],
    ])
  })

  it('answers 500 when a callback throws, so Logto retries, and does not mark the delivery handled', async () => {
    let fail = true
    const onUserDataUpdated = vi.fn(() => {
      if (fail) throw new Error('db down')
    })
    const handler = createLogtoWebhookHandler({ signingKey: KEY, onUserDataUpdated, logger: quiet })
    const payload = { event: 'User.Data.Updated', deliveryId: 'retry-me', data: { id: 'u1' } }
    expect((await handler(delivery(payload))).status).toBe(500)
    fail = false
    expect((await handler(delivery(payload))).status).toBe(200)
    expect(onUserDataUpdated).toHaveBeenCalledTimes(2)
  })
})
