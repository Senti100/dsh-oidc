import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const caddy = readFileSync(new URL('../examples/Caddyfile', import.meta.url), 'utf8')
const patch = readFileSync(new URL('../examples/cordis.patch.yml', import.meta.url), 'utf8')
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')

describe('proxy and composition security examples', () => {
  it('preserves native Connection and adds a Host-only plugin', () => {
    expect(patch).toContain("name: '@senti100/dsh-oidc'")
    expect(patch).toContain("name: '@deepseek-ai/dsh-client-connection'")
    expect(patch).toContain('inject: [webServer, connection, credentials]')
    expect(patch).toContain('clientSecretRef:')
    expect(patch).not.toMatch(/clientSecret:\s/u)
    expect(patch).toContain('trustedHosts:')
    expect(patch).toContain('printUrl: false')
    expect(patch).toContain('openBrowser: false')
  })

  it('routes auth directly and gates every remaining path before one reverse proxy', () => {
    const authAt = caddy.indexOf('handle /auth/*')
    const genericAt = caddy.indexOf('handle {', authAt)
    const forwardAt = caddy.indexOf('forward_auth 127.0.0.1:3080', genericAt)
    const applicationProxyAt = caddy.indexOf('reverse_proxy 127.0.0.1:3080', forwardAt)
    expect(authAt).toBeGreaterThan(0)
    expect(genericAt).toBeGreaterThan(authAt)
    expect(forwardAt).toBeGreaterThan(genericAt)
    expect(applicationProxyAt).toBeGreaterThan(forwardAt)
    for (const path of ['root', 'assets', '/api', 'uploads', 'SSE', 'WebSocket'])
      expect(readme).toContain(path)
  })

  it('fixes public Host, strips identity headers, omits query logs, and documents HTTPS-only reachability', () => {
    expect(caddy).toContain('header_up Host {host}')
    expect(caddy).toContain('request_header -Authorization')
    expect(caddy).toContain('request_header -Proxy-Authorization')
    expect(caddy).toContain('request_header -X-Dsh-Oidc-Client-Ip')
    expect(caddy).toContain('header_up X-Dsh-Oidc-Client-Ip {remote_host}')
    expect(caddy).toContain('request_header -X-Forwarded-User')
    expect(caddy).toContain('request_header -X-Forwarded-Email')
    expect(caddy).toContain('request_header -X-Auth-Request-User')
    expect(caddy).toContain('request_header -X-Auth-Request-Email')
    expect(caddy).toContain('request_header -X-Remote-User')
    expect(caddy).toContain('request_header -Remote-User')
    expect(caddy).toContain('request>uri query delete')
    expect(caddy).toContain('Strict-Transport-Security')
    expect(caddy).not.toMatch(/http:\/\/dsh\.example/u)
    expect(readme).toContain('do not expose HTTP port 80')
  })

  it('states shared-operator behavior and stale-cookie denial', () => {
    expect(readme).toContain('Every admitted user shares the same DSH home')
    expect(readme).toContain('stale native DSH cookie')
    expect(readme).toContain('forward_auth /auth/check')
  })
})
