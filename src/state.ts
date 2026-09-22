import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Principal } from './policy.js'

const TOKEN_BYTES = 32
const SAFE_TOKEN = /^[A-Za-z0-9_-]{43}$/u
export const SESSION_COOKIE = '__Host-dsh-oidc-session'
export const TRANSACTION_COOKIE = '__Host-dsh-oidc-transaction'

export interface AuthorizationTransaction {
  readonly id: string
  readonly state: string
  readonly nonce: string
  readonly verifier: string
  readonly expiresAt: number
}

export interface SessionView {
  readonly principal: Principal
  readonly issuedAt: number
  readonly lastUsedAt: number
  readonly expiresAt: number
  readonly csrf: string
}

function opaqueToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url')
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url')
}

function equalToken(actual: string, expected: string): boolean {
  const a = Buffer.from(actual)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

export class AuthorizationTransactions {
  private readonly entries = new Map<string, AuthorizationTransaction>()

  constructor(
    private readonly maxAgeMilliseconds: number,
    private readonly maxEntries: number,
  ) {}

  create(verifier: string, nonce: string, now = Date.now()): AuthorizationTransaction | undefined {
    this.prune(now)
    if (this.entries.size >= this.maxEntries) return undefined
    const transaction = {
      id: opaqueToken(),
      state: opaqueToken(),
      nonce,
      verifier,
      expiresAt: now + this.maxAgeMilliseconds,
    }
    this.entries.set(digest(transaction.id), transaction)
    return transaction
  }

  consume(
    id: string | undefined,
    state: string | undefined,
    now = Date.now(),
  ): AuthorizationTransaction | undefined {
    if (id === undefined || !SAFE_TOKEN.test(id)) return undefined
    const key = digest(id)
    const transaction = this.entries.get(key)
    this.entries.delete(key)
    if (
      state === undefined ||
      !SAFE_TOKEN.test(state) ||
      transaction === undefined ||
      transaction.expiresAt <= now
    )
      return undefined
    return equalToken(id, transaction.id) && equalToken(state, transaction.state)
      ? transaction
      : undefined
  }

  get size(): number {
    return this.entries.size
  }

  private prune(now: number): void {
    for (const [key, value] of this.entries) if (value.expiresAt <= now) this.entries.delete(key)
  }
}

interface StoredSession extends SessionView {
  readonly idleTimeoutMilliseconds: number
}

export class BrowserSessions {
  private readonly entries = new Map<string, StoredSession>()

  constructor(
    private readonly maxAgeMilliseconds: number,
    private readonly idleTimeoutMilliseconds: number,
    private readonly maxEntries: number,
  ) {}

  create(
    principal: Principal,
    now = Date.now(),
  ): { readonly value: string; readonly expiresAt: number; readonly csrf: string } | undefined {
    this.prune(now)
    if (this.entries.size >= this.maxEntries) return undefined
    const value = opaqueToken()
    const csrf = opaqueToken()
    const expiresAt = now + this.maxAgeMilliseconds
    this.entries.set(digest(value), {
      principal,
      issuedAt: now,
      lastUsedAt: now,
      expiresAt,
      csrf,
      idleTimeoutMilliseconds: this.idleTimeoutMilliseconds,
    })
    return { value, expiresAt, csrf }
  }

  read(value: string | undefined, now = Date.now()): SessionView | undefined {
    if (value === undefined || !SAFE_TOKEN.test(value)) return undefined
    const key = digest(value)
    const session = this.entries.get(key)
    if (
      session === undefined ||
      session.expiresAt <= now ||
      session.lastUsedAt + session.idleTimeoutMilliseconds <= now
    ) {
      this.entries.delete(key)
      return undefined
    }
    const updated = { ...session, lastUsedAt: now }
    this.entries.set(key, updated)
    return updated
  }

  delete(value: string | undefined): void {
    if (value !== undefined && SAFE_TOKEN.test(value)) this.entries.delete(digest(value))
  }

  get size(): number {
    return this.entries.size
  }

  private prune(now: number): void {
    for (const [key, value] of this.entries) {
      if (value.expiresAt <= now || value.lastUsedAt + value.idleTimeoutMilliseconds <= now)
        this.entries.delete(key)
    }
  }
}

export class FixedWindowRateLimiter {
  private readonly windows = new Map<string, { count: number; start: number }>()
  constructor(
    private readonly limit: number,
    private readonly windowMilliseconds = 60_000,
  ) {}
  admit(key: string, now = Date.now()): boolean {
    const prior = this.windows.get(key)
    if (prior === undefined || prior.start + this.windowMilliseconds <= now) {
      this.windows.set(key, { count: 1, start: now })
      return true
    }
    if (prior.count >= this.limit) return false
    prior.count += 1
    return true
  }
}

export function readCookie(raw: string | undefined, name: string): string | undefined {
  if (raw === undefined) return undefined
  for (const segment of raw.split(';')) {
    const at = segment.indexOf('=')
    if (at !== -1 && segment.slice(0, at).trim() === name) return segment.slice(at + 1).trim()
  }
  return undefined
}

export function secureCookie(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${value}; Max-Age=${String(maxAgeSeconds)}; Path=/; HttpOnly; Secure; SameSite=Lax`
}

export function expiredCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax`
}
