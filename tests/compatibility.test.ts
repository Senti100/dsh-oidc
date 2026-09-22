import { describe, expect, it } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import { apply, inject, name } from '../src/index.js'

function acceptsNativeConnection(
  connection: Pick<HostConnectionHandle, 'authenticatedUrl'>,
): string {
  return connection.authenticatedUrl('https://dsh.example/')
}

function pluginDependencies(
  ctx: Pick<Context, 'connection' | 'credentials' | 'webServer'>,
): [HostConnectionHandle, CredentialProvider, WebServer] {
  return [ctx.connection, ctx.credentials, ctx.webServer]
}

describe('DSH public compatibility surface', () => {
  it('uses only the 0.1.5-rc.1 public seam', () => {
    expect(name).toBe('senti100-oidc')
    expect(inject).toEqual(['webServer', 'connection', 'credentials'])
    expect(typeof apply).toBe('function')
    expect(acceptsNativeConnection({ authenticatedUrl: (url) => `${url}?token=test` })).toContain(
      '?token=test',
    )
    expect(pluginDependencies).toBeTypeOf('function')
  })

  it('pins exact pre-stable peer versions in package metadata', async () => {
    const manifest = (await import('../package.json', { with: { type: 'json' } })).default
    expect(manifest.peerDependencies).toMatchObject({
      '@deepseek-ai/dsh-client-connection': '0.1.5-rc.1',
      '@deepseek-ai/dsh-credentials': '0.1.5-rc.1',
      '@deepseek-ai/dsh-host-webserver': '0.1.5-rc.1',
    })
    expect(manifest.exports).not.toHaveProperty('./client')
  })

  it('registers the complete exact authentication route set through the public webserver seam', () => {
    const routes: Array<{ kind: string; path: string }> = []
    const effects: Array<() => void> = []
    const ctx = {
      credentials: {},
      connection: {},
      logger: {},
      webServer: {
        register(route: { kind: string; path: string }) {
          routes.push(route)
          return () => undefined
        },
      },
      effect(factory: () => () => void) {
        effects.push(factory())
      },
    } as unknown as Context

    apply(ctx, {
      issuer: 'https://id.example/tenant',
      clientId: 'client',
      publicOrigin: 'https://dsh.example',
      allowedSubjects: [{ issuer: 'https://id.example/tenant', subject: 'operator' }],
    })

    expect(routes.map(({ kind, path }) => ({ kind, path }))).toEqual([
      { kind: 'exact', path: '/auth/login' },
      { kind: 'exact', path: '/auth/callback' },
      { kind: 'exact', path: '/auth/check' },
      { kind: 'exact', path: '/auth/logout' },
    ])
    expect(effects).toHaveLength(4)
    for (const dispose of effects) dispose()
  })
})
