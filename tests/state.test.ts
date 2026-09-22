import { describe, expect, it, vi } from 'vitest'
import {
  AuthorizationTransactions,
  BrowserSessions,
  FixedWindowRateLimiter,
  SESSION_COOKIE,
  expiredCookie,
  readCookie,
  secureCookie,
} from '../src/state.js'

const principal = { issuer: 'https://id.example', subject: 's', groups: [] }

describe('bounded one-use state', () => {
  it('consumes an exact transaction once and rejects expiry, mismatch, tampering, and capacity overflow', () => {
    const store = new AuthorizationTransactions(1000, 1)
    const tx = store.create('verifier', 'nonce', 100)
    expect(tx).toBeDefined()
    expect(store.create('v2', 'n2', 100)).toBeUndefined()
    expect(store.consume(tx?.id, 'wrong', 101)).toBeUndefined()
    expect(store.consume(tx?.id, tx?.state, 101)).toBeUndefined()
    const expired = store.create('v', 'n', 200)
    expect(store.consume(expired?.id, expired?.state, 1201)).toBeUndefined()
    expect(store.consume('bad', 'bad', 1)).toBeUndefined()
  })

  it('expires, idles, tampers, deletes, and bounds opaque sessions', () => {
    const sessions = new BrowserSessions(1000, 100, 1)
    const session = sessions.create(principal, 100)
    expect(session?.value).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(JSON.stringify(session)).not.toContain('subject')
    expect(sessions.create(principal, 100)).toBeUndefined()
    expect(sessions.read(session?.value, 150)?.principal.subject).toBe('s')
    expect(sessions.read(`${session?.value}x`, 151)).toBeUndefined()
    expect(sessions.read(session?.value, 251)).toBeUndefined()
    const next = sessions.create(principal, 300)
    sessions.delete(next?.value)
    expect(sessions.read(next?.value, 301)).toBeUndefined()
  })

  it('formats exact secure cookies and reads only exact names', () => {
    vi.spyOn(Date, 'now').mockReturnValue(0)
    expect(secureCookie(SESSION_COOKIE, 'opaque', 60)).toBe(
      '__Host-dsh-oidc-session=opaque; Max-Age=60; Path=/; HttpOnly; Secure; SameSite=Lax',
    )
    expect(expiredCookie(SESSION_COOKIE)).toContain('Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970')
    expect(readCookie('other=x; __Host-dsh-oidc-session=opaque', SESSION_COOKIE)).toBe('opaque')
    expect(readCookie(undefined, SESSION_COOKIE)).toBeUndefined()
    vi.restoreAllMocks()
  })

  it('rate limits a fixed window and resets at its edge', () => {
    const limiter = new FixedWindowRateLimiter(2, 100)
    expect(limiter.admit('k', 0)).toBe(true)
    expect(limiter.admit('k', 1)).toBe(true)
    expect(limiter.admit('k', 2)).toBe(false)
    expect(limiter.admit('k', 100)).toBe(true)
  })
})
