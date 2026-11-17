import { describe, expect, it } from 'vitest'
import {
  HANDLE_PATTERN,
  HANDLE_PATTERN_SOURCE,
  RESERVED_HANDLES,
  canChooseHandle,
  checkHandle,
  displayHandle,
  fallbackHandle,
  handleFromClaims,
  isHandle,
  normalizeHandle,
  suggestHandle,
} from './handle.js'

describe('handle rule', () => {
  it('accepts 3–20 of a–z 0–9 _ starting with a letter or underscore', () => {
    for (const ok of ['bob', '_bob', 'a_1', 'abcdefghijklmnopqrst', '___', 'x2kq9m']) expect(isHandle(ok), ok).toBe(true)
    for (const bad of ['ab', 'abcdefghijklmnopqrstu', '1bob', 'Bob', 'bo-b', 'bo.b', 'böb', '', ' bob', null, 42]) {
      expect(isHandle(bad), String(bad)).toBe(false)
    }
  })

  it('keeps the string form in step with the regex', () => {
    expect(HANDLE_PATTERN.source).toBe(`^${HANDLE_PATTERN_SOURCE}$`)
  })

  it('keeps reserved words out of self-service, including every app route listed', () => {
    for (const word of ['admin', 'api', 'settings', 'chat', 'release', 'avatars', 'moderator', 'robyrew', 'logto']) {
      expect(RESERVED_HANDLES.has(word), word).toBe(true)
      expect(canChooseHandle(word), word).toBe(false)
      // Still a handle: one an admin assigned is displayed.
      expect(isHandle(word), word).toBe(true)
    }
  })

  it('normalizes what people type', () => {
    expect(normalizeHandle('  @Bob_1 ')).toBe('bob_1')
    expect(normalizeHandle('ＢＯＢ')).toBe('bob')
  })

  it('names the broken part of the rule', () => {
    expect(checkHandle('@Bob')).toEqual({ ok: true, handle: 'bob' })
    expect(checkHandle('')).toMatchObject({ ok: false, problem: 'empty' })
    expect(checkHandle('ab')).toMatchObject({ ok: false, problem: 'too_short' })
    expect(checkHandle('a'.repeat(21))).toMatchObject({ ok: false, problem: 'too_long' })
    expect(checkHandle('bo-b')).toMatchObject({ ok: false, problem: 'bad_chars' })
    expect(checkHandle('1bob')).toMatchObject({ ok: false, problem: 'bad_start' })
    expect(checkHandle('Admin')).toMatchObject({ ok: false, handle: 'admin', problem: 'reserved' })
  })
})

describe('claims', () => {
  it('uses the Logto username only when it already passes the rule', () => {
    expect(handleFromClaims({ username: 'bob' })).toBe('bob')
    // Not lowercased: another account may hold `bob`.
    expect(handleFromClaims({ username: 'Bob' })).toBeNull()
    expect(handleFromClaims({ username: null })).toBeNull()
    expect(handleFromClaims({})).toBeNull()
    expect(handleFromClaims(null)).toBeNull()
  })

  it('falls back to user-<first six of sub>, which no handle can equal', () => {
    expect(fallbackHandle('X2kq9mAbc123')).toBe('user-x2kq9m')
    expect(isHandle(fallbackHandle('abcdef123'))).toBe(false)
    expect(handleFromClaims({ username: 'robyrew' })).toBe('robyrew')
    expect(displayHandle({ sub: 'abcdef123', username: 'Bob' })).toBe('user-abcdef')
    expect(displayHandle({ sub: 'abcdef123', username: 'bob' })).toBe('bob')
  })
})

describe('suggestHandle', () => {
  it('maps legacy handles into the rule', () => {
    expect(suggestHandle('my-name')).toBe('my_name')
    expect(suggestHandle('John.Smith')).toBe('john_smith')
    expect(suggestHandle('1abc')).toBe('_1abc')
    expect(suggestHandle('a-very-long-handle-from-mapswitch')).toBe('a_very_long_handle_f')
    expect(suggestHandle('ok_handle')).toBe('ok_handle')
  })

  it('gives up when nothing valid is left', () => {
    expect(suggestHandle('ab')).toBeNull()
    expect(suggestHandle('--')).toBeNull()
    expect(suggestHandle('admin')).toBeNull()
  })
})
