import { describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'
import { DatabaseSync } from 'node:sqlite'
import { sqliteSessionStore, type SqliteLike } from './sqlite-store.js'

const drivers: Array<[string, () => SqliteLike]> = [
  ['better-sqlite3', () => new Database(':memory:') as unknown as SqliteLike],
  ['node:sqlite', () => new DatabaseSync(':memory:') as unknown as SqliteLike],
]

describe.each(drivers)('sqliteSessionStore on %s', (_name, open) => {
  it('saves, loads, expires, prunes and drops per user', () => {
    const db = open()
    const store = sqliteSessionStore(db, { createTable: true })
    const now = Date.now()
    store.save('a', 'blob-a', now + 60_000, 'user-1')
    store.save('b', 'blob-b', now + 60_000, 'user-1')
    store.save('c', 'blob-c', now + 60_000, 'user-2')
    store.save('old', 'blob-old', now - 1, null)
    expect(store.load('a')).toBe('blob-a')
    expect(store.load('old')).toBeNull()
    store.prune!(now)
    expect((db.prepare('SELECT COUNT(*) AS n FROM logto_sessions').get() as { n: number }).n).toBe(3)
    store.save('a', 'blob-a2', now + 60_000, 'user-1')
    expect(store.load('a')).toBe('blob-a2')
    store.dropUser('user-1')
    expect(store.load('a')).toBeNull()
    expect(store.load('b')).toBeNull()
    expect(store.load('c')).toBe('blob-c')
    store.drop('c')
    expect(store.load('c')).toBeNull()
  })

  it('adds the user-key column to a 0.1.x table when it owns the table', () => {
    const db = open()
    db.exec('CREATE TABLE logto_sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)')
    db.prepare('INSERT INTO logto_sessions VALUES (?, ?, ?, ?)').run('legacy', '{"idToken":"x"}', Date.now(), Date.now() + 60_000)
    const store = sqliteSessionStore(db, { createTable: true })
    const columns = (db.prepare('PRAGMA table_info(logto_sessions)').all() as Array<{ name: string }>).map((c) => c.name)
    expect(columns).toContain('user_key')
    // The old plaintext row is still readable by the store; createLogtoAuth refuses to open it.
    expect(store.load('legacy')).toBe('{"idToken":"x"}')
  })

  it('maps legacy column names and refuses a table without the user-key column', () => {
    const db = open()
    db.exec('CREATE TABLE logto_sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL)')
    expect(() => sqliteSessionStore(db, { columns: { createdAt: 'createdAt', expiresAt: 'expiresAt' } })).toThrow(/ADD COLUMN user_key/)
    db.exec('ALTER TABLE logto_sessions ADD COLUMN userKey TEXT')
    const store = sqliteSessionStore(db, { columns: { createdAt: 'createdAt', expiresAt: 'expiresAt', userKey: 'userKey' } })
    store.save('x', 'blob', Date.now() + 1000, 'u')
    expect(store.load('x')).toBe('blob')
  })

  it('refuses unsafe identifiers and a missing table', () => {
    const db = open()
    expect(() => sqliteSessionStore(db, { table: 'x; DROP TABLE y' })).toThrow(/invalid identifier/)
    expect(() => sqliteSessionStore(db)).toThrow(/does not exist/)
  })
})
