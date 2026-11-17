import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto'

// Session rows at rest. One secret yields three independent keys (HKDF-SHA256):
//   - AES-256-GCM seals each row's JSON (OIDC tokens included); the row id is the
//     additional data, so a sealed blob copied under another id does not open.
//   - HMAC-SHA256 turns the cookie's session id into the row id, so the table (or
//     a backup of it) holds no value a browser could present as a cookie.
//   - A second HMAC key turns the Logto `sub` into the row's user key, used only to
//     drop every session of one user (suspension, deletion).

export const MIN_SESSION_SECRET_LENGTH = 32

const VERSION = 'v1'
const IV_BYTES = 12
const TAG_BYTES = 16

export interface SessionKeys {
  seal(plaintext: string, context: string): string
  /** The plaintext, or null for a blob that is malformed, from another key, or tampered with. */
  open(sealed: string, context: string): string | null
  rowId(sessionId: string): string
  userKey(sub: string): string
}

export function deriveSessionKeys(secret: string): SessionKeys {
  if (typeof secret !== 'string' || secret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error(
      `astro-logto: sessionSecret must be at least ${MIN_SESSION_SECRET_LENGTH} characters (openssl rand -base64 32)`,
    )
  }
  const ikm = Buffer.from(secret, 'utf8')
  const salt = Buffer.from('@robyrew/astro-logto', 'utf8')
  const derive = (info: string) => Buffer.from(hkdfSync('sha256', ikm, salt, info, 32))
  const sealKey = derive('session-seal/v1')
  const rowKey = derive('session-row-id/v1')
  const userKeyKey = derive('session-user-key/v1')
  const mac = (key: Buffer, value: string) => createHmac('sha256', key).update(value, 'utf8').digest('base64url')

  return {
    seal(plaintext, context) {
      const iv = randomBytes(IV_BYTES)
      const cipher = createCipheriv('aes-256-gcm', sealKey, iv, { authTagLength: TAG_BYTES })
      cipher.setAAD(Buffer.from(context, 'utf8'))
      const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()])
      return `${VERSION}.${iv.toString('base64url')}.${body.toString('base64url')}`
    },
    open(sealed, context) {
      if (typeof sealed !== 'string') return null
      const parts = sealed.split('.')
      if (parts.length !== 3 || parts[0] !== VERSION) return null
      try {
        const iv = Buffer.from(parts[1]!, 'base64url')
        const body = Buffer.from(parts[2]!, 'base64url')
        if (iv.length !== IV_BYTES || body.length < TAG_BYTES) return null
        const decipher = createDecipheriv('aes-256-gcm', sealKey, iv, { authTagLength: TAG_BYTES })
        decipher.setAAD(Buffer.from(context, 'utf8'))
        decipher.setAuthTag(body.subarray(body.length - TAG_BYTES))
        return Buffer.concat([decipher.update(body.subarray(0, body.length - TAG_BYTES)), decipher.final()]).toString('utf8')
      } catch {
        return null
      }
    },
    rowId: (sessionId) => mac(rowKey, sessionId),
    userKey: (sub) => mac(userKeyKey, sub),
  }
}
