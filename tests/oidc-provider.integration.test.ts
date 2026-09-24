import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { resolveConfig } from '../src/config.js'
import { OpenIdClientProtocol, OidcValidationError, validateAuthorizedParty } from '../src/oidc.js'

interface CodeGrant {
  readonly challenge: string
  claims?: Readonly<Record<string, unknown>>
  corruptSignature?: boolean
}

class MockOidcProvider {
  readonly codes = new Map<string, CodeGrant>()
  discoveryMode: 'valid' | 'malformed' | 'wrong-issuer' | 'redirect' | 'timeout' = 'valid'
  private key!: CryptoKey
  private jwk!: JWK
  private server!: Server
  private directory!: string
  issuer!: string

  async start(): Promise<void> {
    this.directory = mkdtempSync(join(tmpdir(), 'dsh-oidc-provider-'))
    const keyPath = join(this.directory, 'tls-key.pem')
    const certPath = join(this.directory, 'tls-cert.pem')
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
        '-keyout',
        keyPath,
        '-out',
        certPath,
      ],
      { stdio: 'ignore' },
    )
    await this.rotate()
    this.server = createServer(
      { key: readFileSync(keyPath), cert: readFileSync(certPath) },
      (req, res) => {
        void this.handle(req, res)
      },
    )
    this.server.listen(0, '127.0.0.1')
    await once(this.server, 'listening')
    const address = this.server.address()
    if (address === null || typeof address === 'string')
      throw new Error('mock provider did not bind TCP')
    this.issuer = `https://127.0.0.1:${String(address.port)}`
  }

  async rotate(): Promise<void> {
    const pair = await generateKeyPair('RS256')
    this.key = pair.privateKey
    this.jwk = await exportJWK(pair.publicKey)
    this.jwk.kid = createHash('sha256')
      .update(String(Date.now()) + String(Math.random()))
      .digest('hex')
      .slice(0, 16)
    this.jwk.alg = 'RS256'
    this.jwk.use = 'sig'
  }

  issue(code: string, challenge: string, grant: Omit<CodeGrant, 'challenge'> = {}): void {
    this.codes.set(code, { challenge, ...grant })
  }

  private json(res: import('node:http').ServerResponse, status: number, value: unknown): void {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(value))
  }

  private async handle(
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse,
  ): Promise<void> {
    if (req.url === '/.well-known/openid-configuration') {
      if (this.discoveryMode === 'malformed') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end('{')
        return
      }
      if (this.discoveryMode === 'redirect') {
        res.writeHead(302, { location: `${this.issuer}/redirected-discovery` })
        res.end()
        return
      }
      if (this.discoveryMode === 'timeout') {
        setTimeout(() => this.json(res, 500, { error: 'late' }), 500)
        return
      }
      return this.json(res, 200, {
        issuer: this.discoveryMode === 'wrong-issuer' ? 'https://wrong.example' : this.issuer,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        jwks_uri: `${this.issuer}/jwks`,
        end_session_endpoint: `${this.issuer}/logout`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      })
    }
    if (req.url === '/jwks') return this.json(res, 200, { keys: [this.jwk] })
    if (req.url !== '/token' || req.method !== 'POST')
      return this.json(res, 404, { error: 'not_found' })
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
    const code = body.get('code')
    const verifier = body.get('code_verifier')
    const grant = code === null ? undefined : this.codes.get(code)
    if (code !== null) this.codes.delete(code)
    const challenge =
      verifier === null ? '' : createHash('sha256').update(verifier).digest('base64url')
    if (
      grant === undefined ||
      challenge !== grant.challenge ||
      body.get('redirect_uri') !== 'https://dsh.example/auth/callback'
    ) {
      return this.json(res, 400, {
        error: 'invalid_grant',
        error_description:
          grant === undefined
            ? 'authorization code unavailable or replayed'
            : 'PKCE or redirect verification failed',
      })
    }
    const now = Math.floor(Date.now() / 1000)
    const claims = {
      iss: this.issuer,
      sub: 'allowed',
      aud: 'client',
      iat: now,
      exp: now + 60,
      ...grant.claims,
    }
    let token = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: String(this.jwk.kid) })
      .sign(this.key)
    if (grant.corruptSignature === true) {
      const parts = token.split('.')
      const signature = parts[2]
      if (signature === undefined) throw new Error('mock token has no signature')
      parts[2] = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`
      token = parts.join('.')
    }
    this.json(res, 200, { access_token: 'not-retained', token_type: 'Bearer', id_token: token })
  }

  async stop(): Promise<void> {
    this.server.close()
    await once(this.server, 'close')
    rmSync(this.directory, { recursive: true, force: true })
  }
}

const provider = new MockOidcProvider()
let priorTls: string | undefined

beforeAll(async () => {
  priorTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  await provider.start()
})

afterAll(async () => {
  await provider.stop()
  if (priorTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = priorTls
})

function protocol(timeout = 10, maxAuthenticationAgeSeconds?: number): OpenIdClientProtocol {
  return new OpenIdClientProtocol(
    resolveConfig({
      issuer: provider.issuer,
      clientId: 'client',
      clientSecretRef: 'OIDC_SECRET',
      publicOrigin: 'https://dsh.example',
      allowedSubjects: [{ issuer: provider.issuer, subject: 'allowed' }],
      ...(maxAuthenticationAgeSeconds === undefined ? {} : { maxAuthenticationAgeSeconds }),
    }),
    timeout,
  )
}

async function prepared(
  code: string,
  claims?: Readonly<Record<string, unknown>>,
  corruptSignature = false,
  client = protocol(),
) {
  const started = await client.start('secret')
  const challenge = started.url.searchParams.get('code_challenge')
  const state = started.url.searchParams.get('state')
  if (challenge === null || state === null)
    throw new Error('authorization request missing proof parameters')
  provider.issue(code, challenge, { ...(claims === undefined ? {} : { claims }), corruptSignature })
  return {
    client,
    started,
    checks: {
      verifier: started.verifier,
      nonce: started.nonce,
      state,
      currentUrl: new URL(`https://dsh.example/auth/callback?code=${code}&state=${state}`),
    },
  }
}

async function rejectionText(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
    throw new Error('expected rejection')
  } catch (error) {
    const parts: string[] = []
    let current: unknown = error
    for (let depth = 0; depth < 6 && current instanceof Error; depth += 1) {
      const code = 'code' in current ? String(current.code) : ''
      const responseError =
        'error' in current && typeof current.error === 'string' ? ` ${current.error}` : ''
      const description =
        'error_description' in current && typeof current.error_description === 'string'
          ? ` ${current.error_description}`
          : ''
      parts.push(`${current.name} ${code} ${current.message}${responseError}${description}`)
      current = current.cause
    }
    return parts.join(' | ')
  }
}

describe('openid-client protocol integration', () => {
  it.each([
    ['malformed', 'OIDC_DISCOVERY_INVALID'],
    ['wrong-issuer', 'OIDC_DISCOVERY_INVALID'],
    ['redirect', 'OIDC_HTTP_REDIRECT'],
  ] as const)('fails closed on %s discovery with %s', async (mode, fingerprint) => {
    provider.discoveryMode = mode
    expect(await rejectionText(protocol().start('secret'))).toContain(fingerprint)
    provider.discoveryMode = 'valid'
  })

  it('bounds provider discovery time', async () => {
    provider.discoveryMode = 'timeout'
    expect(await rejectionText(protocol(0.05).start('secret'))).toContain('OIDC_HTTP_TIMEOUT')
    provider.discoveryMode = 'valid'
  })

  it('discovers, sends fixed code-flow PKCE parameters, and validates a signed ID token', async () => {
    const flow = await prepared('valid', { nonce: undefined })
    // Replace undefined nonce with the exact generated value before signing.
    provider.codes.get('valid')!.claims = { nonce: flow.started.nonce }
    expect(flow.started.url.origin).toBe(provider.issuer)
    expect(flow.started.url.searchParams).toMatchObject(expect.any(URLSearchParams))
    expect(flow.started.url.searchParams.get('redirect_uri')).toBe(
      'https://dsh.example/auth/callback',
    )
    expect(flow.started.url.searchParams.get('response_type')).toBe('code')
    expect(flow.started.url.searchParams.get('code_challenge_method')).toBe('S256')
    const claims = await flow.client.callback('secret', flow.checks)
    expect(claims).toMatchObject({
      iss: provider.issuer,
      sub: 'allowed',
      aud: 'client',
      nonce: flow.started.nonce,
    })
  })

  it.each([
    ['nonce', { nonce: 'wrong' }, /nonce/iu],
    ['issuer', { nonce: 'set-later', iss: 'https://wrong.example' }, /issuer|iss/iu],
    ['audience', { nonce: 'set-later', aud: 'other-client' }, /audience|aud/iu],
    ['expired', { nonce: 'set-later', exp: Math.floor(Date.now() / 1000) - 60 }, /expir|exp/iu],
    [
      'not-before',
      { nonce: 'set-later', nbf: Math.floor(Date.now() / 1000) + 3600 },
      /nbf|not.before/iu,
    ],
    [
      'future-iat',
      { nonce: 'set-later', iat: Math.floor(Date.now() / 1000) + 3600 },
      /OIDC_IAT_INVALID/u,
    ],
    ['missing-iat', { nonce: 'set-later', iat: undefined }, /iat.*missing/iu],
  ] as const)(
    'rejects %s token validation with a discriminating fingerprint',
    async (code, initial, fingerprint) => {
      const flow = await prepared(code, initial)
      const grant = provider.codes.get(code)!
      grant.claims = {
        ...initial,
        ...(initial.nonce === 'set-later' ? { nonce: flow.started.nonce } : {}),
      }
      expect(await rejectionText(flow.client.callback('secret', flow.checks))).toMatch(fingerprint)
    },
  )

  it('rejects a corrupt signature with a signature fingerprint', async () => {
    const flow = await prepared('signature', undefined, true)
    provider.codes.get('signature')!.claims = { nonce: flow.started.nonce }
    expect(await rejectionText(flow.client.callback('secret', flow.checks))).toMatch(/signature/iu)
  })

  it('rejects a wrong PKCE verifier as invalid_grant', async () => {
    const flow = await prepared('pkce')
    provider.codes.get('pkce')!.claims = { nonce: flow.started.nonce }
    expect(
      await rejectionText(
        flow.client.callback('secret', { ...flow.checks, verifier: 'wrong-verifier' }),
      ),
    ).toMatch(/invalid_grant.*PKCE/iu)
  })

  it('rejects authorization-code replay as invalid_grant', async () => {
    const flow = await prepared('replay')
    provider.codes.get('replay')!.claims = { nonce: flow.started.nonce }
    await flow.client.callback('secret', flow.checks)
    expect(await rejectionText(flow.client.callback('secret', flow.checks))).toMatch(
      /invalid_grant.*replayed/iu,
    )
  })

  it.each([
    ['scalar audience conflicting azp', { aud: 'client', azp: 'other' }, 'OIDC_AZP_MISMATCH'],
    [
      'multi audience conflicting azp',
      { aud: ['client', 'other'], azp: 'other' },
      'OIDC_AZP_MISMATCH',
    ],
    ['multi audience missing azp', { aud: ['client', 'other'] }, 'OIDC_AZP_REQUIRED'],
    ['malformed azp', { aud: 'client', azp: ['client'] }, 'OIDC_AZP_INVALID'],
  ] as const)('rejects %s', (_name, claims, code) => {
    expect(() => validateAuthorizedParty(claims, 'client')).toThrow(
      expect.objectContaining({ code }) as OidcValidationError,
    )
  })

  it('accepts an exact authorized party for scalar and array audiences', () => {
    expect(() => validateAuthorizedParty({ aud: 'client', azp: 'client' }, 'client')).not.toThrow()
    expect(() =>
      validateAuthorizedParty({ aud: ['client', 'other'], azp: 'client' }, 'client'),
    ).not.toThrow()
  })

  it.each([
    ['missing', undefined, /auth_time|AUTH_TIME_MISSING/iu],
    ['stale', Math.floor(Date.now() / 1000) - 3600, /too much time has elapsed/iu],
    ['malformed', 'recent', /auth_time|AUTH_TIME_INVALID/iu],
    ['future', Math.floor(Date.now() / 1000) + 3600, /auth_time|future/iu],
  ] as const)(
    'rejects %s auth_time when max authentication age is configured',
    async (name, authTime, fingerprint) => {
      const code = `auth-time-${name}`
      const client = protocol(10, 120)
      const flow = await prepared(code, { nonce: 'set-later', auth_time: authTime }, false, client)
      provider.codes.get(code)!.claims = { nonce: flow.started.nonce, auth_time: authTime }
      expect(flow.started.url.searchParams.get('max_age')).toBe('120')
      expect(await rejectionText(client.callback('secret', flow.checks))).toMatch(fingerprint)
    },
  )

  it('accepts a current auth_time when max authentication age is configured', async () => {
    const client = protocol(10, 120)
    const flow = await prepared('auth-time-valid', undefined, false, client)
    provider.codes.get('auth-time-valid')!.claims = {
      nonce: flow.started.nonce,
      auth_time: Math.floor(Date.now() / 1000),
    }
    await expect(client.callback('secret', flow.checks)).resolves.toMatchObject({ sub: 'allowed' })
  })

  it('accepts provider signing-key rotation through fresh discovery and JWKS', async () => {
    await provider.rotate()
    const flow = await prepared('rotated')
    provider.codes.get('rotated')!.claims = { nonce: flow.started.nonce }
    await expect(flow.client.callback('secret', flow.checks)).resolves.toMatchObject({
      sub: 'allowed',
    })
  })

  it('builds provider logout only when advertised', async () => {
    const url = await protocol().logoutUrl('secret')
    expect(url?.href).toContain(`${provider.issuer}/logout`)
    expect(url?.searchParams.get('post_logout_redirect_uri')).toBe('https://dsh.example/')
  })
})
