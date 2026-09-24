import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { execFile, spawn, type ChildProcess } from 'node:child_process'
import { createServer, request as httpRequest, type Server } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { networkInterfaces } from 'node:os'
import { dirname, join } from 'node:path'
import { once } from 'node:events'
import { promisify } from 'node:util'
import { exportJWK, importPKCS8, SignJWT } from 'jose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

interface HttpResult {
  readonly status: number
  readonly headers: string
  readonly body: string
}

interface BrowserModule {
  readonly chromium: {
    executablePath(): string
    launch(options: Record<string, unknown>): Promise<Browser>
  }
}

interface Browser {
  newContext(options?: Record<string, unknown>): Promise<BrowserContext>
  close(): Promise<void>
}

interface BrowserContext {
  newPage(): Promise<Page>
  cookies(urls?: string | readonly string[]): Promise<Cookie[]>
  addCookies(cookies: readonly Cookie[]): Promise<void>
  close(): Promise<void>
  request: {
    post(url: string, options: Record<string, unknown>): Promise<{ status(): number }>
  }
}

interface Cookie {
  readonly name: string
  readonly value: string
  readonly domain: string
  readonly path: string
  readonly expires: number
  readonly httpOnly: boolean
  readonly secure: boolean
  readonly sameSite: 'Strict' | 'Lax' | 'None'
}

interface Page {
  goto(url: string, options?: Record<string, unknown>): Promise<{ status(): number } | null>
  title(): Promise<string>
  url(): string
  locator(selector: string): {
    getAttribute(name: string): Promise<string | null>
    inputValue(): Promise<string>
  }
  waitForNavigation(options?: Record<string, unknown>): Promise<{ status(): number } | null>
  evaluate<R, A>(callback: (argument: A) => R | Promise<R>, argument: A): Promise<R>
}

const execFileAsync = promisify(execFile)
const caddyBinary = required('DSH_OIDC_CADDY_BIN')
const runRoot = required('DSH_OIDC_FULL_PROFILE_RUN_ROOT')
const runtime = required('DSH_OIDC_RUNTIME')
const dshHome = required('DSH_HOME')
const controlledFailure = process.env.DSH_OIDC_CONTROLLED_SETUP_FAILURE === '1'
const stackRoot = join(runRoot, controlledFailure ? 'failure-stack' : 'stack')
const profilePatch = join(dshHome, 'profiles/web/cordis.patch.yml')
const credentialReference = 'DSH_OIDC_TEST_CLIENT_SECRET'

let provider: Server | undefined
let caddy: ChildProcess | undefined
let dsh: ChildProcess | undefined
let browser: Browser | undefined
let context: BrowserContext | undefined
let page: Page | undefined
let providerPort = 0
let publicPort = 0
let adminPort = 0
let dshPort = 0
let issuer = ''
let publicOrigin = ''
let caPath = ''
let caddyStderr = ''
let dshOutput = ''
let clientSecret = ''
let clientSecretUsed = false
let realAssetPath = ''
let nativeCookieHeader = ''
const issuedCodes = new Map<string, { challenge: string; nonce: string }>()

function required(name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '')
    throw new Error(`FULL_PROFILE_BLOCKED: ${name} is required`)
  return value
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

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

function findDshPackage(name: string): string {
  const store = join(runtime, 'node_modules/.pnpm')
  for (const entry of readdirSync(store)) {
    const candidate = join(store, entry, 'node_modules', ...name.split('/'), 'package.json')
    if (existsSync(candidate)) return candidate
  }
  throw new Error(`installed package was not found: ${name}`)
}

function attestDshClosure(): number {
  const store = join(runtime, 'node_modules/.pnpm')
  const observed = new Map<string, string>()
  for (const entry of readdirSync(store)) {
    const scope = join(store, entry, 'node_modules/@deepseek-ai')
    if (!existsSync(scope)) continue
    for (const child of readdirSync(scope)) {
      if (child !== 'dsh' && !child.startsWith('dsh-')) continue
      const manifestPath = join(scope, child, 'package.json')
      if (!existsSync(manifestPath)) continue
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
        name?: unknown
        version?: unknown
      }
      if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') {
        throw new Error(`invalid installed DSH manifest: ${manifestPath}`)
      }
      if (manifest.version !== '0.1.5-rc.1') {
        throw new Error(`DSH closure drift: ${manifest.name}@${manifest.version}`)
      }
      observed.set(manifest.name, manifest.version)
    }
  }
  for (const requiredName of [
    '@deepseek-ai/dsh',
    '@deepseek-ai/dsh-web-app',
    '@deepseek-ai/dsh-credentials-local',
    '@deepseek-ai/dsh-client-connection',
    '@deepseek-ai/dsh-client-file-upload',
    '@deepseek-ai/dsh-api-gateway',
    '@deepseek-ai/dsh-web-frontend',
  ]) {
    if (!observed.has(requiredName)) throw new Error(`required DSH owner absent: ${requiredName}`)
  }
  return observed.size
}

async function curl(host: string, url: string, extra: readonly string[] = []): Promise<HttpResult> {
  const headerPath = join(stackRoot, `headers-${randomUUID()}`)
  const bodyPath = join(stackRoot, `body-${randomUUID()}`)
  try {
    await execFileAsync(
      'curl',
      [
        '--silent',
        '--show-error',
        '--connect-timeout',
        '2',
        '--max-time',
        '8',
        '--cacert',
        caPath,
        '--resolve',
        `${host}:${String(publicPort)}:127.0.0.1`,
        '--dump-header',
        headerPath,
        '--output',
        bodyPath,
        ...extra,
        url,
      ],
      { encoding: 'utf8', timeout: 10_000 },
    )
    const headers = readFileSync(headerPath, 'utf8')
    return {
      status: Number(/^HTTP\/\S+ (\d{3})/mu.exec(headers)?.[1]),
      headers,
      body: readFileSync(bodyPath, 'utf8'),
    }
  } finally {
    rmSync(headerPath, { force: true })
    rmSync(bodyPath, { force: true })
  }
}

function caddyfile(upstreamPort?: number): string {
  const application =
    upstreamPort === undefined
      ? 'respond "DSH starting" 503'
      : `request_header -Authorization
  request_header -Proxy-Authorization
  request_header -X-Dsh-Oidc-Client-Ip
  request_header -X-Forwarded-User
  request_header -X-Forwarded-Email
  request_header -X-Auth-Request-User
  request_header -X-Auth-Request-Email
  request_header -X-Remote-User
  request_header -Remote-User
  handle /auth/* {
    reverse_proxy 127.0.0.1:${String(upstreamPort)} {
      header_up Host dsh.test:${String(publicPort)}
      header_up X-Dsh-Oidc-Client-Ip {remote_host}
    }
  }
  handle {
    forward_auth 127.0.0.1:${String(upstreamPort)} {
      uri /auth/check
      header_up Host dsh.test:${String(publicPort)}
      header_up X-Dsh-Oidc-Client-Ip {remote_host}
      header_up -Connection
      header_up -Upgrade
    }
    reverse_proxy 127.0.0.1:${String(upstreamPort)} {
      header_up Host dsh.test:${String(publicPort)}
    }
  }`
  return `{
  admin 127.0.0.1:${String(adminPort)}
  auto_https disable_redirects
}
https://127.0.0.1:${String(publicPort)} {
  tls internal
  reverse_proxy 127.0.0.1:${String(providerPort)}
}
https://dsh.test:${String(publicPort)} {
  tls internal
  ${application}
}
`
}

async function waitForCaddy(): Promise<void> {
  const deadline = Date.now() + 15_000
  let last = 'not ready'
  while (Date.now() < deadline) {
    if (caddy?.exitCode !== null) throw new Error(`Caddy exited early\n${caddyStderr}`)
    if (existsSync(caPath)) {
      try {
        const discovery = await curl(
          '127.0.0.1',
          new URL('.well-known/openid-configuration', issuer).href,
        )
        if (discovery.status === 200) return
        last = `HTTP ${String(discovery.status)}`
      } catch (error) {
        last = error instanceof Error ? error.message : String(error)
      }
    }
    await delay(50)
  }
  throw new Error(`Caddy readiness deadline exceeded: ${last}\n${caddyStderr}`)
}

async function reloadCaddy(upstreamPort: number): Promise<void> {
  const config = join(stackRoot, 'Caddyfile')
  const replacement = join(stackRoot, 'Caddyfile.next')
  writeFileSync(replacement, caddyfile(upstreamPort), { mode: 0o600 })
  renameSync(replacement, config)
  await execFileAsync(caddyBinary, ['reload', '--config', config, '--adapter', 'caddyfile'], {
    env: caddyEnvironment(),
    encoding: 'utf8',
    timeout: 10_000,
  })
}

function caddyEnvironment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    XDG_DATA_HOME: join(stackRoot, 'caddy-data'),
    XDG_CONFIG_HOME: join(stackRoot, 'caddy-config'),
  }
}

function writeProfilePatch(): void {
  const contents = `- insert:
    - id: senti100-oidc
      name: '@senti100/dsh-oidc'
      inject: [webServer, connection, credentials]
      config:
        issuer: '${issuer}'
        clientId: 'synthetic-client'
        clientSecretRef: '${credentialReference}'
        publicOrigin: '${publicOrigin}/'
        allowedSubjects:
          - issuer: '${issuer}'
            subject: 'synthetic-operator'
`
  writeFileSync(profilePatch, contents, { mode: 0o600 })
}

function writeCredentials(): void {
  clientSecret = randomBytes(32).toString('base64url')
  const credentials = join(dshHome, '.credentials.yaml')
  writeFileSync(credentials, `version: 1\nrefs:\n  ${credentialReference}: '${clientSecret}'\n`, {
    mode: 0o600,
  })
  chmodSync(credentials, 0o600)
}

async function startProvider(): Promise<void> {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const signingKey = await importPKCS8(
    privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    'RS256',
  )
  const jwk = await exportJWK(publicKey)
  jwk.kid = 'synthetic-key'
  jwk.alg = 'RS256'
  jwk.use = 'sig'
  provider = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', issuer)
      if (url.pathname === '/.well-known/openid-configuration') {
        response.setHeader('content-type', 'application/json')
        response.end(
          JSON.stringify({
            issuer,
            authorization_endpoint: new URL('authorize', issuer).href,
            token_endpoint: new URL('token', issuer).href,
            jwks_uri: new URL('jwks', issuer).href,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
          }),
        )
        return
      }
      if (url.pathname === '/jwks') {
        response.setHeader('content-type', 'application/json')
        response.end(JSON.stringify({ keys: [jwk] }))
        return
      }
      if (url.pathname === '/authorize') {
        const state = url.searchParams.get('state')
        const nonce = url.searchParams.get('nonce')
        const challenge = url.searchParams.get('code_challenge')
        const redirectUri = url.searchParams.get('redirect_uri')
        if (state === null || nonce === null || challenge === null || redirectUri === null) {
          response.writeHead(400).end()
          return
        }
        const code = randomUUID()
        issuedCodes.set(code, { challenge, nonce })
        const callback = new URL(redirectUri)
        callback.searchParams.set('code', code)
        callback.searchParams.set('state', state)
        response.writeHead(302, { location: callback.href }).end()
        return
      }
      if (url.pathname === '/token' && request.method === 'POST') {
        const chunks: Buffer[] = []
        for await (const chunk of request) chunks.push(chunk as Buffer)
        const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
        const code = body.get('code')
        const verifier = body.get('code_verifier')
        const secretValid = body.get('client_secret') === clientSecret
        const clientValid = body.get('client_id') === 'synthetic-client'
        const grant = code === null ? undefined : issuedCodes.get(code)
        if (code !== null) issuedCodes.delete(code)
        const challenge =
          verifier === null ? '' : createHash('sha256').update(verifier).digest('base64url')
        if (!secretValid || !clientValid || grant === undefined || grant.challenge !== challenge) {
          response.writeHead(400, { 'content-type': 'application/json' })
          response.end(JSON.stringify({ error: 'invalid_client' }))
          return
        }
        clientSecretUsed = true
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
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(
          JSON.stringify({
            access_token: 'synthetic-access',
            token_type: 'Bearer',
            id_token: idToken,
          }),
        )
        return
      }
      response.writeHead(404).end()
    })().catch(() => response.writeHead(500).end())
  })
  provider.listen(0, '127.0.0.1')
  await once(provider, 'listening')
  const address = provider.address()
  if (address === null || typeof address === 'string') throw new Error('provider bind failed')
  providerPort = address.port
}

async function startDsh(): Promise<void> {
  const binary = join(runtime, 'node_modules/.bin/dsh')
  const hmrOverlay = join(stackRoot, 'hmr.patch.yml')
  writeFileSync(hmrOverlay, "- id: hmr\n  disabled: false\n  config:\n    root: ['.']\n", {
    mode: 0o600,
  })
  const child = spawn(
    binary,
    [
      '--profile',
      'web',
      '--patch',
      hmrOverlay,
      '--no-open',
      '--port',
      '0',
      '--trusted-host',
      `dsh.test:${String(publicPort)}`,
    ],
    {
      env: {
        ...process.env,
        DSH_HOME: dshHome,
        DSH_TELEMETRY_DISABLED: '1',
        NODE_EXTRA_CA_CERTS: caPath,
        PATH: `${join(runtime, 'node_modules/.bin')}:${process.env.PATH ?? ''}`,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  dsh = child
  const consume = (chunk: Buffer | string): void => {
    const text = String(chunk).replace(/([?&]token=)[^\s&]+/gu, '$1<redacted>')
    dshOutput = (dshOutput + text).slice(-16_384)
  }
  child.stdout.on('data', consume)
  child.stderr.on('data', consume)
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`DSH exited before readiness\n${dshOutput}`)
    const launch = /dsh web:\s+http:\/\/127\.0\.0\.1:(\d+)\/\?token=<redacted>/u.exec(dshOutput)
    if (launch !== null) {
      dshPort = Number(launch[1])
      return
    }
    await delay(50)
  }
  throw new Error(`DSH readiness deadline exceeded\n${dshOutput}`)
}

async function waitForOidcRoute(): Promise<void> {
  const deadline = Date.now() + 15_000
  while (Date.now() < deadline) {
    if (dsh?.exitCode !== null) throw new Error(`DSH exited after launch\n${dshOutput}`)
    try {
      if ((await directDsh('/auth/check')).status === 401) return
    } catch {
      // The public launch line can precede the first accepted connection briefly.
    }
    await delay(50)
  }
  throw new Error(`OIDC route readiness deadline exceeded\n${dshOutput}`)
}

function directDsh(path: string, cookie = ''): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        host: '127.0.0.1',
        port: dshPort,
        path,
        headers: {
          Host: `dsh.test:${String(publicPort)}`,
          'X-Dsh-Oidc-Client-Ip': '127.0.0.1',
          ...(cookie === '' ? {} : { Cookie: cookie }),
        },
        signal: AbortSignal.timeout(2_000),
      },
      (response) => {
        const chunks: Buffer[] = []
        response.on('data', (chunk: Buffer) => chunks.push(chunk))
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        )
      },
    )
    request.once('error', reject)
    request.end()
  })
}

function logoutThroughProxy(cookie: string, csrf: string): Promise<number> {
  const body = new URLSearchParams({ csrf }).toString()
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        host: '127.0.0.1',
        port: publicPort,
        path: '/auth/logout',
        method: 'POST',
        servername: 'dsh.test',
        rejectUnauthorized: false,
        headers: {
          Host: `dsh.test:${String(publicPort)}`,
          Origin: publicOrigin,
          Cookie: cookie,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
        signal: AbortSignal.timeout(3_000),
      },
      (response) => {
        response.resume()
        response.on('end', () => resolve(response.statusCode ?? 0))
      },
    )
    request.once('error', reject)
    request.end(body)
  })
}

async function waitForClosed(port: number): Promise<void> {
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    const open = await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      socket.once('connect', () => {
        socket.destroy()
        resolve(true)
      })
      socket.once('error', () => resolve(false))
      socket.setTimeout(250, () => {
        socket.destroy()
        resolve(false)
      })
    })
    if (!open) return
    await delay(50)
  }
  throw new Error(`listener remained open on 127.0.0.1:${String(port)}`)
}

async function stopChild(label: string, child: ChildProcess | undefined, requireClean = false) {
  if (child === undefined || child.exitCode !== null) return
  const exit = once(child, 'exit') as Promise<[number | null, NodeJS.Signals | null]>
  child.kill('SIGTERM')
  const result = await Promise.race([exit, delay(6_000).then(() => undefined)])
  if (result === undefined) {
    child.kill('SIGKILL')
    const killed = await Promise.race([exit, delay(2_000).then(() => undefined)])
    if (killed === undefined) throw new Error(`${label} did not exit after SIGKILL`)
    if (requireClean) throw new Error(`${label} required kill fallback`)
    return
  }
  if (requireClean && result[0] !== 0) {
    throw new Error(`${label} exited with ${String(result[0])}/${String(result[1])}`)
  }
}

async function setupStack(): Promise<void> {
  rmSync(stackRoot, { recursive: true, force: true })
  mkdirSync(stackRoot, { recursive: true, mode: 0o700 })
  chmodSync(stackRoot, 0o700)
  const closureCount = attestDshClosure()
  if (closureCount < 200)
    throw new Error(`installed DSH closure was unexpectedly small: ${closureCount}`)
  const frontendManifest = findDshPackage('@deepseek-ai/dsh-web-frontend')
  const frontendIndex = readFileSync(join(dirname(frontendManifest), 'dist/index.html'), 'utf8')
  const asset = /<script[^>]+src="([^"?]+\.js)"/u.exec(frontendIndex)?.[1]
  if (asset === undefined || !asset.includes('-'))
    throw new Error('real hashed frontend asset not found')
  realAssetPath = new URL(asset, 'https://dsh.test/').pathname

  publicPort = await freePort()
  adminPort = await freePort()
  publicOrigin = `https://dsh.test:${String(publicPort)}`
  issuer = `https://127.0.0.1:${String(publicPort)}/`
  writeCredentials()
  writeProfilePatch()
  await startProvider()

  const config = join(stackRoot, 'Caddyfile')
  writeFileSync(config, caddyfile(), { mode: 0o600 })
  caddy = spawn(caddyBinary, ['run', '--config', config, '--adapter', 'caddyfile'], {
    env: caddyEnvironment(),
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  caddy.stderr?.setEncoding('utf8')
  caddy.stderr?.on('data', (chunk: string) => {
    caddyStderr = (caddyStderr + chunk)
      .replace(/([?&]token=)[^\s&]+/gu, '$1<redacted>')
      .slice(-8192)
  })
  caPath = join(stackRoot, 'caddy-data/caddy/pki/authorities/local/root.crt')
  await waitForCaddy()
  if (controlledFailure) throw new Error('CONTROLLED_SETUP_FAILURE')

  await startDsh()
  await waitForOidcRoute()
  await reloadCaddy(dshPort)
  const playwright = (await import(
    `${join(runtime, 'node_modules/playwright/index.mjs')}?acceptance=${randomUUID()}`
  )) as BrowserModule
  const executable = playwright.chromium.executablePath()
  if (!existsSync(executable)) {
    throw new Error('FULL_PROFILE_BLOCKED: pinned Playwright Chromium is not installed')
  }
  browser = await playwright.chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP dsh.test 127.0.0.1'],
  })
  context = await browser.newContext({ ignoreHTTPSErrors: true })
  page = await context.newPage()
}

async function cleanupStack(): Promise<void> {
  const failures: Error[] = []
  const clean = async (label: string, action: () => void | Promise<void>): Promise<void> => {
    try {
      await action()
    } catch (error) {
      failures.push(new Error(`cleanup failed for ${label}`, { cause: error }))
    }
  }
  await clean('browser context', async () => context?.close())
  context = undefined
  page = undefined
  await clean('browser', async () => browser?.close())
  browser = undefined
  await clean('DSH', async () => stopChild('DSH', dsh, true))
  dsh = undefined
  await clean('Caddy', async () => stopChild('Caddy', caddy))
  caddy = undefined
  await clean('provider', async () => {
    const server = provider
    provider = undefined
    if (server === undefined || !server.listening) return
    server.closeAllConnections()
    await Promise.race([
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error === undefined ? resolve() : reject(error))),
      ),
      delay(2_000).then(() => {
        throw new Error('provider close deadline exceeded')
      }),
    ])
  })
  for (const port of [dshPort, publicPort, providerPort, adminPort].filter((value) => value > 0)) {
    await clean(`listener ${String(port)}`, async () => waitForClosed(port))
  }
  clientSecret = ''
  issuedCodes.clear()
  await clean('private stack root', () => rmSync(stackRoot, { recursive: true, force: true }))
  if (existsSync(stackRoot)) failures.push(new Error('private stack root remained'))
  if (failures.length > 0) throw new AggregateError(failures, 'full-profile cleanup failed')
}

beforeAll(async () => {
  try {
    await setupStack()
  } catch (setupError) {
    try {
      await cleanupStack()
    } catch (cleanupError) {
      throw new AggregateError([setupError, cleanupError], 'setup and cleanup failed', {
        cause: cleanupError,
      })
    }
    throw setupError
  }
}, 90_000)

afterAll(cleanupStack, 20_000)

describe('published DSH 0.1.5-rc.1 full Web profile', { concurrent: false }, () => {
  it('denies every application owner before outer login', async () => {
    if (page === undefined) throw new Error('browser page absent')
    for (const path of [
      '/',
      realAssetPath,
      '/api/__acceptance_missing__',
      '/events',
      '/api/remote.mux',
    ]) {
      const response = await page.goto(publicOrigin + path, { waitUntil: 'domcontentloaded' })
      expect(response?.status(), path).toBe(401)
    }
    const upload = await curl(
      'dsh.test',
      `${publicOrigin}/api/session/uploadFileBinary?sessionId=x`,
      [
        '--request',
        'POST',
        '--header',
        'Content-Type: application/octet-stream',
        '--data-binary',
        'x',
      ],
    )
    expect(upload.status).toBe(401)
    const opened = await page.evaluate(
      (url) =>
        new Promise<boolean>((resolve) => {
          const socket = new WebSocket(url)
          socket.addEventListener('open', () => {
            socket.close()
            resolve(true)
          })
          socket.addEventListener('error', () => resolve(false))
          setTimeout(() => resolve(false), 2_000)
        }),
      `wss://dsh.test:${String(publicPort)}/api/remote.mux`,
    )
    expect(opened).toBe(false)
  })

  it('uses the real browser for OIDC, native bootstrap, root, API, upload, and WebSocket', async () => {
    if (page === undefined || context === undefined) throw new Error('browser context absent')
    const response = await page.goto(`${publicOrigin}/auth/login`, {
      waitUntil: 'domcontentloaded',
    })
    expect(response?.status()).toBe(200)
    expect(page.url()).toBe(`${publicOrigin}/`)
    expect(await page.title()).toBe('DeepSeek Harness')
    const cookies = await context.cookies(publicOrigin)
    expect(cookies.some((cookie) => cookie.name === '__Host-dsh-oidc-session')).toBe(true)
    expect(cookies.some((cookie) => cookie.name !== '__Host-dsh-oidc-session')).toBe(true)
    expect(clientSecretUsed).toBe(true)

    const ownerResults = await page.evaluate(
      async ({ assetPath }) => {
        const asset = await fetch(assetPath)
        const missing = await fetch('/api/__acceptance_missing__')
        const upload = await fetch(
          '/api/session/uploadFileBinary?sessionId=synthetic-missing-session',
          {
            method: 'POST',
            headers: { 'content-type': 'application/octet-stream' },
            body: new Uint8Array([1, 2, 3]),
          },
        )
        return {
          assetStatus: asset.status,
          missingStatus: missing.status,
          missingType: missing.headers.get('content-type'),
          uploadStatus: upload.status,
          uploadType: upload.headers.get('content-type'),
          uploadBody: (await upload.json()) as unknown,
        }
      },
      { assetPath: realAssetPath },
    )
    expect(ownerResults.assetStatus).toBe(200)
    expect(ownerResults.missingStatus).toBe(404)
    expect(ownerResults.missingType).not.toContain('text/html')
    expect(ownerResults.uploadStatus).toBe(200)
    expect(ownerResults.uploadType).toContain('application/json')
    expect(ownerResults.uploadBody).toMatchObject({
      ok: false,
      error: { code: 'session/not-found' },
    })

    const websocketOpened = await page.evaluate(
      (url) =>
        new Promise<boolean>((resolve) => {
          const socket = new WebSocket(url)
          const timeout = setTimeout(() => resolve(false), 5_000)
          socket.addEventListener('open', () => {
            clearTimeout(timeout)
            socket.close()
            resolve(true)
          })
          socket.addEventListener('error', () => {
            clearTimeout(timeout)
            resolve(false)
          })
        }),
      `wss://dsh.test:${String(publicPort)}/api/remote.mux`,
    )
    expect(websocketOpened).toBe(true)
  })

  it('denies a stale native cookie after CSRF-protected outer logout', async () => {
    if (page === undefined || context === undefined || browser === undefined) {
      throw new Error('browser context absent')
    }
    const allCookies = await context.cookies(publicOrigin)
    const nativeCookies = allCookies.filter((cookie) => cookie.name.startsWith('dsh-auth-'))
    expect(nativeCookies.length).toBeGreaterThan(0)
    nativeCookieHeader = nativeCookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ')
    expect((await directDsh('/', nativeCookieHeader)).status).toBe(200)
    await page.goto(`${publicOrigin}/auth/logout`, { waitUntil: 'domcontentloaded' })
    const csrf = await page.locator('input[name="csrf"]').inputValue()
    expect(csrf.length).toBeGreaterThan(20)
    const fullCookieHeader = allCookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ')
    expect(await logoutThroughProxy(fullCookieHeader, csrf)).toBe(303)

    const staleContext = await browser.newContext({ ignoreHTTPSErrors: true })
    try {
      await staleContext.addCookies(nativeCookies)
      const stalePage = await staleContext.newPage()
      const denied = await stalePage.goto(`${publicOrigin}/`, { waitUntil: 'domcontentloaded' })
      expect(denied?.status()).toBe(401)
    } finally {
      await staleContext.close()
    }
  })

  it('live-unloads the packed plugin and exposes the real frontend fallback 404', async () => {
    expect((await directDsh('/auth/check', nativeCookieHeader)).status).toBe(401)
    const replacement = `${profilePatch}.next`
    writeFileSync(replacement, '[]\n', { mode: 0o600 })
    renameSync(replacement, profilePatch)
    const deadline = Date.now() + 15_000
    let status = 401
    let body = ''
    while (Date.now() < deadline) {
      if (dsh?.exitCode !== null) throw new Error(`DSH exited during live unload\n${dshOutput}`)
      const response = await directDsh('/auth/check', nativeCookieHeader)
      status = response.status
      body = response.body
      if (status === 404) break
      await delay(50)
    }
    expect(status, body).toBe(404)
  })

  it('binds the real DSH listener only to loopback', async () => {
    const external = Object.values(networkInterfaces())
      .flat()
      .filter(
        (address): address is NonNullable<typeof address> =>
          address !== undefined && !address.internal && address.family === 'IPv4',
      )
    for (const address of external) {
      await expect(
        fetch(`http://${address.address}:${String(dshPort)}/`, {
          signal: AbortSignal.timeout(500),
        }),
      ).rejects.toThrow()
    }
  })
})
