import { Readable } from 'node:stream'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { OidcAdmission, type AdmissionLogger, type CredentialResolver } from '../src/admission.js'
import { resolveConfig } from '../src/config.js'
import type { AuthorizationStart, CallbackChecks, OidcProtocol } from '../src/oidc.js'
import { SESSION_COOKIE, TRANSACTION_COOKIE } from '../src/state.js'

interface CapturedResponse {
  status?: number
  headers?: Record<string, string | readonly string[]>
  body?: string
}

function response(): { value: ServerResponse; captured: CapturedResponse } {
  const captured: CapturedResponse = {}
  const value = {
    writeHead(status: number, headers?: Record<string, string | readonly string[]>) {
      captured.status = status
      if (headers !== undefined) captured.headers = headers
      return value
    },
    end(body?: string) {
      if (body !== undefined) captured.body = body
      return value
    },
  }
  return { value: value as ServerResponse, captured }
}

function request(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string,
): IncomingMessage {
  const value = Readable.from(body === undefined ? [] : [Buffer.from(body)])
  Object.assign(value, { method, url, headers: { host: 'dsh.example', ...headers } })
  return value as IncomingMessage
}

function cookieFrom(headers: CapturedResponse['headers'], name: string): string {
  const raw = headers?.['set-cookie']
  const values = typeof raw === 'string' ? [raw] : raw
  const found = values?.find((value) => value.startsWith(`${name}=`))
  if (found === undefined) throw new Error(`missing ${name}`)
  return found.split(';', 1)[0] ?? ''
}

class FakeProtocol implements OidcProtocol {
  startError = false
  callbackError = false
  claims: Readonly<Record<string, unknown>> = {
    iss: 'https://id.example/issuer',
    sub: 'allowed',
  }
  callbackChecks?: CallbackChecks
  logout = new URL('https://id.example/logout')

  async start(secret: string | undefined): Promise<AuthorizationStart> {
    expect(secret).toBe('rotating-secret')
    if (this.startError) throw new Error('secret-bearing provider error')
    return {
      url: new URL('https://id.example/authorize?client_id=client'),
      verifier: 'verifier',
      nonce: 'nonce',
    }
  }

  async callback(
    secret: string | undefined,
    checks: CallbackChecks,
  ): Promise<Readonly<Record<string, unknown>>> {
    expect(secret).toBe('rotating-secret')
    this.callbackChecks = checks
    if (this.callbackError) throw new Error('token-bearing provider error')
    return this.claims
  }

  async logoutUrl(): Promise<URL | undefined> {
    return this.logout
  }
}

const config = resolveConfig({
  issuer: 'https://id.example/issuer',
  clientId: 'client',
  clientSecretRef: 'OIDC_SECRET',
  publicOrigin: 'https://dsh.example',
  allowedSubjects: [{ issuer: 'https://id.example/issuer', subject: 'allowed' }],
})

function harness(): {
  admission: OidcAdmission
  protocol: FakeProtocol
  messages: string[]
} {
  const protocol = new FakeProtocol()
  const credentials: CredentialResolver = {
    resolve: vi.fn(async () => ({ value: 'rotating-secret', source: 'test' })),
  }
  const messages: string[] = []
  const logger: AdmissionLogger = {
    info: (message) => messages.push(message),
    warn: (message) => messages.push(message),
  }
  return {
    admission: new OidcAdmission(
      config,
      credentials,
      { authenticatedUrl: (origin) => `${origin}?token=native-bootstrap` },
      protocol,
      logger,
    ),
    protocol,
    messages,
  }
}

async function login(
  admission: OidcAdmission,
): Promise<{ cookie: string; state: string; captured: CapturedResponse }> {
  const res = response()
  await admission.login(request('GET', '/auth/login'), res.value)
  const cookie = cookieFrom(res.captured.headers, TRANSACTION_COOKIE)
  const state = new URL(String(res.captured.headers?.location)).searchParams.get('state')
  if (state === null) throw new Error('missing state')
  return { cookie, state, captured: res.captured }
}

beforeEach(() => vi.restoreAllMocks())

describe('OIDC route admission', () => {
  it('runs one-use authorization and bootstraps the unchanged native DSH connection', async () => {
    const { admission, protocol, messages } = harness()
    const started = await login(admission)
    expect(started.captured.status).toBe(303)
    expect(started.captured.headers?.['cache-control']).toBe('no-store')
    expect(started.cookie).toContain(`${TRANSACTION_COOKIE}=`)
    expect(String(started.captured.headers?.['set-cookie'])).toContain(
      'HttpOnly; Secure; SameSite=Lax',
    )

    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      callback.value,
    )
    expect(callback.captured.status).toBe(303)
    expect(callback.captured.headers?.location).toBe('https://dsh.example/?token=native-bootstrap')
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)
    expect(session).not.toContain('allowed')
    expect(protocol.callbackChecks).toMatchObject({
      verifier: 'verifier',
      nonce: 'nonce',
      state: started.state,
    })

    const check = response()
    admission.check(request('GET', '/auth/check', { cookie: session }), check.value)
    expect(check.captured.status).toBe(204)

    const restarted = response()
    harness().admission.check(request('GET', '/auth/check', { cookie: session }), restarted.value)
    expect(restarted.captured.status).toBe(401)

    const replay = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      replay.value,
    )
    expect(replay.captured.status).toBe(400)
    expect(messages.join('\n')).not.toMatch(/rotating-secret|code=|allowed|nonce|verifier/u)
  })

  it('fails closed for host, method, missing session, wrong state, provider failure, and policy denial', async () => {
    const { admission, protocol } = harness()
    const badHost = response()
    await admission.login(request('GET', '/auth/login', { host: 'evil.example' }), badHost.value)
    expect(badHost.captured.status).toBe(403)

    const forgedForwarded = response()
    await admission.login(
      request('GET', '/auth/login', { host: 'evil.example', 'x-forwarded-host': 'dsh.example' }),
      forgedForwarded.value,
    )
    expect(forgedForwarded.captured.status).toBe(403)

    const crossSite = response()
    await admission.login(
      request('GET', '/auth/login', { 'sec-fetch-site': 'cross-site' }),
      crossSite.value,
    )
    expect(crossSite.captured.status).toBe(403)

    const method = response()
    await admission.login(request('POST', '/auth/login'), method.value)
    expect(method.captured).toMatchObject({ status: 405, headers: { allow: 'GET, HEAD' } })

    const check = response()
    admission.check(request('HEAD', '/auth/check'), check.value)
    expect(check.captured.status).toBe(401)
    expect(check.captured.body).toBeUndefined()

    const first = await login(admission)
    const wrongState = response()
    await admission.callback(
      request('GET', '/auth/callback?state=wrong', { cookie: first.cookie }),
      wrongState.value,
    )
    expect(wrongState.captured.status).toBe(400)

    const duplicate = await login(admission)
    const duplicateState = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${duplicate.state}&state=${duplicate.state}`, {
        cookie: duplicate.cookie,
      }),
      duplicateState.value,
    )
    expect(duplicateState.captured.status).toBe(400)

    protocol.startError = true
    const failedStart = response()
    await admission.login(request('GET', '/auth/login'), failedStart.value)
    expect(failedStart.captured).toMatchObject({
      status: 503,
      body: 'authentication unavailable\n',
    })

    protocol.startError = false
    protocol.claims = { iss: config.issuer.href, sub: 'denied' }
    const second = await login(admission)
    const denied = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${second.state}`, { cookie: second.cookie }),
      denied.value,
    )
    expect(denied.captured.status).toBe(403)
  })

  it('requires same-origin CSRF POST logout and invalidates forward-auth immediately', async () => {
    const { admission } = harness()
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${started.state}&code=c`, { cookie: started.cookie }),
      callback.value,
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)

    const confirmation = response()
    admission.logoutConfirmation(
      request('GET', '/auth/logout', { cookie: session }),
      confirmation.value,
    )
    expect(confirmation.captured.status).toBe(200)
    expect(confirmation.captured.headers?.['content-security-policy']).toContain(
      "default-src 'none'",
    )
    const csrf = confirmation.captured.body?.match(/name="csrf" value="([^"]+)"/u)?.[1]
    expect(csrf).toBeDefined()

    const crossOrigin = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://evil.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${csrf}`,
      ),
      crossOrigin.value,
    )
    expect(crossOrigin.captured.status).toBe(403)

    const wrongMediaType = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        { cookie: session, origin: 'https://dsh.example', 'content-type': 'application/json' },
        '{}',
      ),
      wrongMediaType.value,
    )
    expect(wrongMediaType.captured.status).toBe(415)

    const oversized = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${'x'.repeat(17_000)}`,
      ),
      oversized.value,
    )
    expect(oversized.captured.status).toBe(403)

    const wrongCsrf = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        'csrf=wrong',
      ),
      wrongCsrf.value,
    )
    expect(wrongCsrf.captured.status).toBe(403)

    const logout = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${csrf}`,
      ),
      logout.value,
    )
    expect(logout.captured).toMatchObject({
      status: 303,
      headers: { location: 'https://id.example/logout' },
    })
    expect(String(logout.captured.headers?.['set-cookie'])).toContain('Max-Age=0')

    const stale = response()
    admission.check(request('GET', '/auth/check', { cookie: session }), stale.value)
    expect(stale.captured.status).toBe(401)
  })
})
