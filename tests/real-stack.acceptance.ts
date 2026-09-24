import { createHash, generateKeyPairSync } from 'node:crypto'
import { execFile, spawn, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { networkInterfaces, tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import * as connectionPlugin from '@deepseek-ai/dsh-client-connection'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { exportJWK, importPKCS8, SignJWT } from 'jose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import * as oidcPlugin from '../src/index.js'

interface HttpResult {
  readonly status: number
  readonly headers: string
  readonly body: string
}

const configuredCaddyBinary = process.env.DSH_OIDC_CADDY_BIN
if (configuredCaddyBinary === undefined || configuredCaddyBinary === '') {
  throw new Error('REAL_STACK_BLOCKED: DSH_OIDC_CADDY_BIN must name an actual Caddy binary')
}
const caddyBinary: string = configuredCaddyBinary

const originalTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED
const originalDshHome = process.env.DSH_HOME
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

let temporary = ''
let provider: Server | undefined
let caddy: ChildProcess | undefined
let context: Context | undefined
let webFiber: ReturnType<Context['plugin']> | undefined
let connectionFiber: ReturnType<Context['plugin']> | undefined
let oidcFiber: ReturnType<Context['plugin']> | undefined
let providerPort = 0
let dshPort = 0
let publicPort = 0
let publicOrigin = ''
let issuer = ''
let caPath = ''
let browserJar = ''
let preLogoutJar = ''
const execFileAsync = promisify(execFile)
const records = new Map<string, unknown>()
const issuedCodes = new Map<string, { challenge: string; nonce: string }>()
let caddyStderr = ''

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') return reject(new Error('no TCP port'))
      const port = address.port
      server.close((error) => (error === undefined ? resolve(port) : reject(error)))
    })
  })
}

async function curl(
  host: string,
  url: string,
  jar: string,
  extra: readonly string[] = [],
): Promise<HttpResult> {
  const headerPath = join(temporary, `headers-${crypto.randomUUID()}`)
  const bodyPath = join(temporary, `body-${crypto.randomUUID()}`)
  try {
    await execFileAsync(
      'curl',
      [
        '--silent',
        '--show-error',
        '--connect-timeout',
        '2',
        '--max-time',
        '10',
        '--cacert',
        caPath,
        '--resolve',
        `${host}:${String(publicPort)}:127.0.0.1`,
        '--cookie',
        jar,
        '--cookie-jar',
        jar,
        '--dump-header',
        headerPath,
        '--output',
        bodyPath,
        ...extra,
        url,
      ],
      { encoding: 'utf8', timeout: 12_000 },
    )
    const headers = readFileSync(headerPath, 'utf8')
    const status = Number(/^HTTP\/\S+ (\d{3})/mu.exec(headers)?.[1])
    return { status, headers, body: readFileSync(bodyPath, 'utf8') }
  } finally {
    rmSync(headerPath, { force: true })
    rmSync(bodyPath, { force: true })
  }
}

function location(result: HttpResult): string {
  const value = /^location:\s*(\S+)\s*$/imu.exec(result.headers)?.[1]
  if (value === undefined) throw new Error(`missing location on HTTP ${String(result.status)}`)
  return value
}

async function waitForCaddy(): Promise<void> {
  if (caddy === undefined) throw new Error('Caddy process was not initialized')
  let lastFailure = 'Caddy listener was not reachable'
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (caddy.exitCode !== null) {
      throw new Error(`Caddy exited early: ${String(caddy.exitCode)}\n${caddyStderr}`)
    }
    if (caPath !== '') {
      try {
        await execFileAsync(
          'curl',
          [
            '--silent',
            '--show-error',
            '--fail',
            '--max-time',
            '1',
            '--cacert',
            caPath,
            '--resolve',
            `id.test:${String(publicPort)}:127.0.0.1`,
            new URL('.well-known/openid-configuration', issuer).href,
          ],
          { encoding: 'utf8', timeout: 2_000 },
        )
        return
      } catch (error) {
        const failure = error as { code?: unknown; stderr?: unknown }
        const stderr = typeof failure.stderr === 'string' ? failure.stderr.trim() : '<no stderr>'
        lastFailure = `curl status ${String(failure.code)}: ${stderr}`
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  throw new Error(`Caddy did not become ready (${lastFailure})\n${caddyStderr}`)
}

async function setupStack(): Promise<void> {
  temporary = mkdtempSync(join(tmpdir(), 'dsh-oidc-real-stack-'))
  chmodSync(temporary, 0o700)
  const dshHome = join(temporary, 'dsh-home')
  mkdirSync(dshHome, { mode: 0o700 })
  process.env.DSH_HOME = dshHome
  browserJar = join(temporary, 'browser.cookies')
  preLogoutJar = join(temporary, 'pre-logout.cookies')
  writeFileSync(browserJar, '')

  publicPort = await freePort()
  publicOrigin = `https://dsh.test:${String(publicPort)}`
  // The plugin process must resolve its synthetic provider without mutating host DNS.
  issuer = `https://127.0.0.1:${String(publicPort)}/`

  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const signingKey = await importPKCS8(privatePem, 'RS256')
  const jwk = await exportJWK(publicKey)
  jwk.kid = 'synthetic-key'
  jwk.alg = 'RS256'
  jwk.use = 'sig'

  provider = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', issuer)
      if (url.pathname === '/.well-known/openid-configuration') {
        res.setHeader('content-type', 'application/json')
        res.end(
          JSON.stringify({
            issuer,
            authorization_endpoint: new URL('authorize', issuer).href,
            token_endpoint: new URL('token', issuer).href,
            jwks_uri: new URL('jwks', issuer).href,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
            token_endpoint_auth_methods_supported: ['none'],
          }),
        )
        return
      }
      if (url.pathname === '/jwks') {
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify({ keys: [jwk] }))
        return
      }
      if (url.pathname === '/authorize') {
        const state = url.searchParams.get('state')
        const nonce = url.searchParams.get('nonce')
        const challenge = url.searchParams.get('code_challenge')
        const redirectUri = url.searchParams.get('redirect_uri')
        if (state === null || nonce === null || challenge === null || redirectUri === null) {
          res.writeHead(400).end()
          return
        }
        const code = crypto.randomUUID()
        issuedCodes.set(code, { challenge, nonce })
        const callback = new URL(redirectUri)
        callback.searchParams.set('code', code)
        callback.searchParams.set('state', state)
        res.writeHead(302, { location: callback.href }).end()
        return
      }
      if (url.pathname === '/token' && req.method === 'POST') {
        const chunks: Buffer[] = []
        for await (const chunk of req) chunks.push(chunk as Buffer)
        const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
        const code = body.get('code')
        const verifier = body.get('code_verifier')
        const grant = code === null ? undefined : issuedCodes.get(code)
        if (code !== null) issuedCodes.delete(code)
        const challenge =
          verifier === null ? '' : createHash('sha256').update(verifier).digest('base64url')
        if (grant === undefined || grant.challenge !== challenge) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'invalid_grant' }))
          return
        }
        const now = Math.floor(Date.now() / 1000)
        const idToken = await new SignJWT({
          iss: issuer,
          sub: 'synthetic-operator',
          aud: 'synthetic-client',
          nonce: grant.nonce,
          iat: now,
          exp: now + 300,
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' })
          .sign(signingKey)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(
          JSON.stringify({
            access_token: 'synthetic-access',
            token_type: 'Bearer',
            id_token: idToken,
          }),
        )
        return
      }
      res.writeHead(404).end()
    })()
  })
  provider.listen(0, '127.0.0.1')
  await once(provider, 'listening')
  const providerAddress = provider.address()
  if (providerAddress === null || typeof providerAddress === 'string')
    throw new Error('provider bind failed')
  providerPort = providerAddress.port

  const runtime = new Context()
  context = runtime
  const credentialProvider = {
    resolve: async () => undefined,
    describe: async () => ({ configured: false, writable: true }),
    set: async () => undefined,
    unset: async () => undefined,
    readRecord: async (key: string) => records.get(key),
    describeRecord: async (key: string) => ({ configured: records.has(key), writable: true }),
    listRecords: async () => [],
    modifyRecord: async (key: string, mutate: (value: unknown) => Promise<unknown>) => {
      const replacement = await mutate(records.get(key))
      if (replacement !== undefined) records.set(key, replacement)
      return records.get(key)
    },
    deleteRecord: async (key: string) => {
      records.delete(key)
    },
  }
  runtime.provide('credentials', credentialProvider)
  webFiber = runtime.plugin(WebServer, { host: '127.0.0.1', port: 0 })
  await webFiber
  dshPort = runtime.webServer.port
  connectionFiber = runtime.plugin(connectionPlugin, {
    trustedHosts: [`dsh.test:${String(publicPort)}`],
  })
  await connectionFiber
  runtime.webServer.registerFallback((req, res) => {
    if (!runtime.connection.authorizeIndex(req, res)) return
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(runtime.webServer.renderIndex('<!doctype html><title>Synthetic DSH</title>'))
  })
  runtime.connection.fetch.register({
    path: '/api/probe',
    methods: ['GET', 'HEAD'],
    requestBody: 'buffered',
    fetch: async () => new Response('api-ok\n'),
  })
  oidcFiber = runtime.plugin(oidcPlugin, {
    issuer,
    clientId: 'synthetic-client',
    publicOrigin,
    allowedSubjects: [{ issuer, subject: 'synthetic-operator' }],
  })
  await oidcFiber

  const caddyfile = join(temporary, 'Caddyfile')
  writeFileSync(
    caddyfile,
    `{
  auto_https disable_redirects
}
https://127.0.0.1:${String(publicPort)} {
  tls internal
  reverse_proxy 127.0.0.1:${String(providerPort)}
}
https://dsh.test:${String(publicPort)} {
  tls internal
  request_header -Authorization
  request_header -Proxy-Authorization
  request_header -X-Dsh-Oidc-Client-Ip
  request_header -X-Forwarded-User
  request_header -X-Forwarded-Email
  request_header -X-Auth-Request-User
  request_header -X-Auth-Request-Email
  request_header -X-Remote-User
  request_header -Remote-User
  handle /auth/* {
    reverse_proxy 127.0.0.1:${String(dshPort)} {
      header_up Host dsh.test:${String(publicPort)}
      header_up X-Dsh-Oidc-Client-Ip {remote_host}
    }
  }
  handle {
    forward_auth 127.0.0.1:${String(dshPort)} {
      uri /auth/check
      header_up Host dsh.test:${String(publicPort)}
      header_up X-Dsh-Oidc-Client-Ip {remote_host}
      header_up -Connection
      header_up -Upgrade
    }
    reverse_proxy 127.0.0.1:${String(dshPort)} {
      header_up Host dsh.test:${String(publicPort)}
    }
  }
}
`,
  )
  const caddyData = join(temporary, 'caddy-data')
  const caddyConfig = join(temporary, 'caddy-config')
  const caddyProcess = spawn(
    caddyBinary,
    ['run', '--config', caddyfile, '--adapter', 'caddyfile'],
    {
      env: { ...process.env, XDG_DATA_HOME: caddyData, XDG_CONFIG_HOME: caddyConfig },
      stdio: ['ignore', 'ignore', 'pipe'],
    },
  )
  caddy = caddyProcess
  caddyProcess.stderr.setEncoding('utf8')
  caddyProcess.stderr.on('data', (chunk: string) => {
    caddyStderr = (caddyStderr + chunk).slice(-8_192)
  })
  caPath = join(caddyData, 'caddy/pki/authorities/local/root.crt')
  await waitForCaddy()
}

async function cleanupStack(): Promise<void> {
  const failures: Error[] = []
  const run = async (label: string, cleanup: () => void | Promise<void>): Promise<void> => {
    try {
      await cleanup()
    } catch (error) {
      failures.push(new Error(`real-stack cleanup failed for ${label}`, { cause: error }))
    }
  }

  await run('Caddy', async () => {
    const child = caddy
    caddy = undefined
    if (child === undefined || child.exitCode !== null) return
    const exited = once(child, 'exit').then(() => true)
    child.kill('SIGTERM')
    if (
      !(await Promise.race([
        exited,
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000)),
      ]))
    ) {
      child.kill('SIGKILL')
      if (
        !(await Promise.race([
          exited,
          new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000)),
        ]))
      ) {
        throw new Error('Caddy did not exit after SIGKILL')
      }
    }
  })
  await run('OIDC fiber', async () => {
    const fiber = oidcFiber
    oidcFiber = undefined
    await fiber?.dispose()
  })
  await run('connection fiber', async () => {
    const fiber = connectionFiber
    connectionFiber = undefined
    await fiber?.dispose()
  })
  await run('webserver fiber', async () => {
    const fiber = webFiber
    webFiber = undefined
    await fiber?.dispose()
  })
  await run('provider', async () => {
    const server = provider
    provider = undefined
    if (server === undefined || !server.listening) return
    server.closeAllConnections()
    await Promise.race([
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)))
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('provider did not close')), 2_000),
      ),
    ])
  })
  await run('private temporary directory', () => {
    if (temporary !== '') rmSync(temporary, { recursive: true, force: true })
    temporary = ''
  })

  if (originalTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTls
  if (originalDshHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = originalDshHome

  if (failures.length > 0) throw new AggregateError(failures, 'real-stack cleanup failed')
}

beforeAll(async () => {
  try {
    await setupStack()
  } catch (setupError) {
    try {
      await cleanupStack()
    } catch (cleanupError) {
      throw new AggregateError([setupError, cleanupError], 'real-stack setup and cleanup failed', {
        cause: cleanupError,
      })
    }
    throw setupError
  }
}, 30_000)

afterAll(cleanupStack)

describe('real DSH and Caddy acceptance', { concurrent: false }, () => {
  it('loads exact routes through real Cordis composition and completes both browser sessions', async () => {
    const login = await curl('dsh.test', `${publicOrigin}/auth/login`, browserJar)
    expect(login.status).toBe(303)
    const authorize = await curl('id.test', location(login), browserJar)
    expect(authorize.status).toBe(302)
    const callback = await curl('dsh.test', location(authorize), browserJar)
    expect(callback.status, callback.body).toBe(303)
    const nativeBootstrap = location(callback)
    expect(nativeBootstrap).toMatch(/^https:\/\/dsh\.test:\d+\/\?token=/u)
    const exchange = await curl('dsh.test', nativeBootstrap, browserJar)
    expect(exchange.status).toBe(303)
    expect(location(exchange)).toBe('/')
    const cleanRoot = await curl(
      'dsh.test',
      new URL(location(exchange), publicOrigin).href,
      browserJar,
    )
    expect(cleanRoot.status).toBe(200)
    expect(cleanRoot.body).toContain('Synthetic DSH')
    writeFileSync(preLogoutJar, readFileSync(browserJar))
  })

  it('serves an authenticated native /api exact Fetch route', async () => {
    const api = await curl('dsh.test', `${publicOrigin}/api/probe`, browserJar)
    expect(api).toMatchObject({ status: 200, body: 'api-ok\n' })
  })

  it.each(['/asset.js', '/uploads/file', '/events', '/stream'])(
    'blocks unauthenticated application path %s before DSH',
    async (path) => {
      const emptyJar = join(temporary, `empty-${path.replaceAll('/', '_')}.cookies`)
      writeFileSync(emptyJar, '')
      expect((await curl('dsh.test', publicOrigin + path, emptyJar)).status).toBe(401)
    },
  )

  it('blocks unauthenticated WebSocket upgrade before the upstream upgrade path', async () => {
    const emptyJar = join(temporary, 'empty-websocket.cookies')
    writeFileSync(emptyJar, '')
    const result = await curl('dsh.test', `${publicOrigin}/socket`, emptyJar, [
      '--http1.1',
      '--header',
      'Connection: Upgrade',
      '--header',
      'Upgrade: websocket',
      '--header',
      'Sec-WebSocket-Key: c3ludGhldGljLWtleQ==',
      '--header',
      'Sec-WebSocket-Version: 13',
    ])
    expect(result.status, result.body).toBe(401)
  })

  it('logs out the outer session and denies the stale native cookie', async () => {
    const confirmation = await curl('dsh.test', `${publicOrigin}/auth/logout`, browserJar)
    expect(confirmation.status).toBe(200)
    const csrf = /name="csrf" value="([^"]+)"/u.exec(confirmation.body)?.[1]
    expect(csrf).toBeDefined()
    const logout = await curl('dsh.test', `${publicOrigin}/auth/logout`, browserJar, [
      '--request',
      'POST',
      '--header',
      `Origin: ${publicOrigin}`,
      '--header',
      'Content-Type: application/x-www-form-urlencoded',
      '--data',
      `csrf=${encodeURIComponent(csrf ?? '')}`,
    ])
    expect(logout.status).toBe(303)
    const staleOnly = join(temporary, 'stale-native.cookies')
    const staleRows = readFileSync(preLogoutJar, 'utf8')
      .split('\n')
      .filter((line) => !line.includes('__Host-dsh-oidc-session'))
      .join('\n')
    writeFileSync(staleOnly, staleRows)
    expect((await curl('dsh.test', `${publicOrigin}/api/probe`, staleOnly)).status).toBe(401)
  })

  it('removes all OIDC routes on unload', async () => {
    if (oidcFiber === undefined) throw new Error('OIDC fiber was not initialized')
    const directUrl = `http://127.0.0.1:${String(dshPort)}/auth/check`
    const directHeaders = { host: `dsh.test:${String(publicPort)}` }
    const beforeUnload = await fetch(directUrl, { headers: directHeaders })
    expect(beforeUnload.status).toBe(403)
    const fiber = oidcFiber
    oidcFiber = undefined
    await fiber.dispose()
    const afterUnload = await fetch(directUrl, { headers: directHeaders })
    expect(afterUnload.status).toBe(401)
    expect(await afterUnload.text()).toContain('dsh web authentication required')
  })

  it('keeps DSH loopback-only in the test topology', async () => {
    if (context === undefined) throw new Error('Cordis context was not initialized')
    expect(context.webServer.host).toBe('127.0.0.1')
    const externalAddresses = Object.values(networkInterfaces())
      .flat()
      .filter(
        (address): address is NonNullable<typeof address> =>
          address !== undefined && !address.internal && address.family === 'IPv4',
      )
    for (const address of externalAddresses) {
      await expect(
        fetch(`http://${address.address}:${String(dshPort)}/`, {
          signal: AbortSignal.timeout(250),
        }),
      ).rejects.toThrow()
    }
  })
})
