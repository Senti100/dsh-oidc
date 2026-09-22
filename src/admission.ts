import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { CredentialRef, ResolvedCredential } from '@deepseek-ai/dsh-credentials'
import type { ResolvedConfig } from './config.js'
import type { OidcProtocol } from './oidc.js'
import { authorizeClaims } from './policy.js'
import {
  AuthorizationTransactions,
  BrowserSessions,
  FixedWindowRateLimiter,
  SESSION_COOKIE,
  TRANSACTION_COOKIE,
  expiredCookie,
  readCookie,
  secureCookie,
} from './state.js'

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
} as const

export interface AdmissionLogger {
  info(message: string): void
  warn(message: string): void
}

export interface CredentialResolver {
  resolve(reference: CredentialRef): Promise<ResolvedCredential | undefined>
}

export interface NativeConnectionLauncher {
  authenticatedUrl(baseUrl: string): string
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return typeof value === 'string' ? value : undefined
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  res.writeHead(405, { ...SECURITY_HEADERS, allow })
  res.end()
}

function plain(res: ServerResponse, status: number, body: string, head = false): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'text/plain; charset=utf-8' })
  res.end(head ? undefined : body)
}

function redirect(res: ServerResponse, location: string, cookies: readonly string[] = []): void {
  res.writeHead(303, {
    ...SECURITY_HEADERS,
    location,
    ...(cookies.length === 0 ? {} : { 'set-cookie': [...cookies] }),
  })
  res.end()
}

function formBody(req: IncomingMessage, maximum = 16_384): Promise<URLSearchParams | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let exceeded = false
    req.on('data', (chunk: Buffer) => {
      if (exceeded) return
      size += chunk.byteLength
      if (size > maximum) {
        exceeded = true
        chunks.length = 0
        resolve(undefined)
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (!exceeded) resolve(new URLSearchParams(Buffer.concat(chunks).toString('utf8')))
    })
    req.on('error', reject)
  })
}

export class OidcAdmission {
  private readonly transactions: AuthorizationTransactions
  private readonly sessions: BrowserSessions
  private readonly limiter: FixedWindowRateLimiter

  constructor(
    private readonly config: ResolvedConfig,
    private readonly credentials: CredentialResolver,
    private readonly connection: NativeConnectionLauncher,
    private readonly protocol: OidcProtocol,
    private readonly logger: AdmissionLogger,
  ) {
    this.transactions = new AuthorizationTransactions(
      config.transactionMaxAgeSeconds * 1000,
      config.maxTransactions,
    )
    this.sessions = new BrowserSessions(
      config.sessionMaxAgeSeconds * 1000,
      config.sessionIdleTimeoutSeconds * 1000,
      config.maxSessions,
    )
    this.limiter = new FixedWindowRateLimiter(config.loginRateLimitPerMinute)
  }

  private correlation(): string {
    return randomBytes(8).toString('hex')
  }

  private trustedRequest(req: IncomingMessage): boolean {
    return header(req, 'host') === this.config.publicOrigin.host
  }

  private sessionValue(req: IncomingMessage): string | undefined {
    return readCookie(header(req, 'cookie'), SESSION_COOKIE)
  }

  private async secret(): Promise<string | undefined> {
    const reference: CredentialRef | undefined = this.config.clientSecretRef
    if (reference === undefined) return undefined
    const resolved = await this.credentials.resolve(reference)
    if (resolved === undefined) throw new Error('configured OIDC client credential is unavailable')
    return resolved.value
  }

  async login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    if (header(req, 'sec-fetch-site') === 'cross-site') return plain(res, 403, 'forbidden\n')
    if (!this.limiter.admit('login')) return plain(res, 429, 'too many requests\n')
    const correlation = this.correlation()
    try {
      const started = await this.protocol.start(await this.secret())
      const transaction = this.transactions.create(started.verifier, started.nonce)
      if (transaction === undefined) return plain(res, 503, 'authentication unavailable\n')
      started.url.searchParams.set('state', transaction.state)
      redirect(res, started.url.href, [
        secureCookie(TRANSACTION_COOKIE, transaction.id, this.config.transactionMaxAgeSeconds),
      ])
      this.logger.info(`dsh-oidc login started correlation=${correlation}`)
    } catch {
      this.logger.warn(`dsh-oidc login failed correlation=${correlation}`)
      plain(res, 503, 'authentication unavailable\n')
    }
  }

  async callback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET') return methodNotAllowed(res, 'GET')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    const correlation = this.correlation()
    const incoming = new URL(req.url ?? '/auth/callback', this.config.publicOrigin)
    const transaction = this.transactions.consume(
      readCookie(header(req, 'cookie'), TRANSACTION_COOKIE),
      incoming.searchParams.getAll('state').length === 1
        ? (incoming.searchParams.get('state') ?? undefined)
        : undefined,
    )
    if (transaction === undefined) {
      this.logger.warn(`dsh-oidc callback rejected correlation=${correlation}`)
      return plain(res, 400, 'invalid authentication response\n')
    }
    try {
      const currentUrl = new URL(this.config.redirectUri)
      currentUrl.search = incoming.search
      const claims = await this.protocol.callback(await this.secret(), {
        verifier: transaction.verifier,
        nonce: transaction.nonce,
        state: transaction.state,
        currentUrl,
      })
      const principal = authorizeClaims(claims, this.config.issuer.href, this.config.policy)
      if (principal === undefined) {
        this.logger.warn(`dsh-oidc policy denied correlation=${correlation}`)
        return plain(res, 403, 'access denied\n')
      }
      const session = this.sessions.create(principal)
      if (session === undefined) return plain(res, 503, 'authentication unavailable\n')
      redirect(res, this.connection.authenticatedUrl(this.config.publicOrigin.href), [
        secureCookie(SESSION_COOKIE, session.value, this.config.sessionMaxAgeSeconds),
        expiredCookie(TRANSACTION_COOKIE),
      ])
      this.logger.info(`dsh-oidc login admitted correlation=${correlation}`)
    } catch {
      this.logger.warn(`dsh-oidc callback failed correlation=${correlation}`)
      plain(res, 400, 'invalid authentication response\n')
    }
  }

  check(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n', req.method === 'HEAD')
    const session = this.sessions.read(this.sessionValue(req))
    plain(
      res,
      session === undefined ? 401 : 204,
      session === undefined ? 'unauthorized\n' : '',
      req.method === 'HEAD',
    )
  }

  logoutConfirmation(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') return methodNotAllowed(res, 'GET, POST')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    if (header(req, 'sec-fetch-site') === 'cross-site') return plain(res, 403, 'forbidden\n')
    const session = this.sessions.read(this.sessionValue(req))
    if (session === undefined) return plain(res, 401, 'unauthorized\n')
    const html = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Sign out</title><form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="${session.csrf}"><button type="submit">Sign out</button></form>`
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy':
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    })
    res.end(html)
  }

  async logout(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') return methodNotAllowed(res, 'GET, POST')
    if (!this.trustedRequest(req) || header(req, 'origin') !== this.config.publicOrigin.origin)
      return plain(res, 403, 'forbidden\n')
    if (
      header(req, 'content-type')?.split(';', 1)[0]?.trim().toLowerCase() !==
      'application/x-www-form-urlencoded'
    )
      return plain(res, 415, 'unsupported media type\n')
    const value = this.sessionValue(req)
    const session = this.sessions.read(value)
    const body = await formBody(req)
    if (session === undefined || body?.get('csrf') !== session.csrf)
      return plain(res, 403, 'forbidden\n')
    this.sessions.delete(value)
    let destination = this.config.publicOrigin.href
    try {
      destination = (await this.protocol.logoutUrl(await this.secret()))?.href ?? destination
    } catch {
      // Local logout remains complete when optional provider logout is unavailable.
    }
    redirect(res, destination, [expiredCookie(SESSION_COOKIE)])
    this.logger.info(`dsh-oidc logout completed correlation=${this.correlation()}`)
  }
}
