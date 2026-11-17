import { describe, expect, it } from 'vitest'
import { deriveSessionKeys } from './seal.js'

const SECRET = 'test-secret-test-secret-test-secret-0123'

describe('deriveSessionKeys', () => {
  it('refuses a short secret', () => {
    expect(() => deriveSessionKeys('short')).toThrow(/at least 32/)
  })

  it('seals and opens under the same id only', () => {
    const keys = deriveSessionKeys(SECRET)
    const sealed = keys.seal('{"a":1}', 'row-1')
    expect(sealed).toMatch(/^v1\.[\w-]+\.[\w-]+$/)
    expect(sealed).not.toContain('"a"')
    expect(keys.open(sealed, 'row-1')).toBe('{"a":1}')
    expect(keys.open(sealed, 'row-2')).toBeNull()
  })

  it('uses a fresh IV each time', () => {
    const keys = deriveSessionKeys(SECRET)
    expect(keys.seal('same', 'id')).not.toBe(keys.seal('same', 'id'))
  })

  it('rejects tampering, another key, plaintext and garbage', () => {
    const keys = deriveSessionKeys(SECRET)
    const sealed = keys.seal('payload', 'id')
    const [v, iv, body] = sealed.split('.')
    const flipped = `${v}.${iv}.${body!.slice(0, -2)}${body!.endsWith('A') ? 'B' : 'A'}${body!.slice(-1)}`
    expect(keys.open(flipped, 'id')).toBeNull()
    expect(deriveSessionKeys(`${SECRET}-other`).open(sealed, 'id')).toBeNull()
    expect(keys.open('{"idToken":"plaintext from 0.1"}', 'id')).toBeNull()
    expect(keys.open('v1.x.y', 'id')).toBeNull()
  })

  it('derives stable, secret-dependent ids', () => {
    const a = deriveSessionKeys(SECRET)
    const b = deriveSessionKeys(SECRET)
    expect(a.rowId('sid')).toBe(b.rowId('sid'))
    expect(a.rowId('sid')).not.toBe('sid')
    expect(a.rowId('sid')).not.toBe(a.userKey('sid'))
    expect(deriveSessionKeys(`${SECRET}-other`).rowId('sid')).not.toBe(a.rowId('sid'))
  })
})
