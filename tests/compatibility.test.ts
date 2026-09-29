import { describe, expect, it } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import { apply, inject, name } from '../src/index.js'
import { assertRuntimeCompatibility, supportedRuntimePackages } from '../src/compatibility.js'

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
  it('uses only the 0.2.0-rc.2 public seam', () => {
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
      '@deepseek-ai/dsh-client-connection': '0.2.0-rc.2',
      '@deepseek-ai/dsh-credentials': '0.2.0-rc.2',
      '@deepseek-ai/dsh-host-webserver': '0.2.0-rc.2',
    })
    expect(manifest.exports).not.toHaveProperty('./client')
  })

  it('retains the historical 0.1.7 source-only audit without claiming runtime support', async () => {
    const fixture = (
      await import('./fixtures/dsh-0.1.7-alpha.2-public-seams.json', { with: { type: 'json' } })
    ).default
    expect(fixture).toMatchObject({
      upstreamVersion: '0.1.7-alpha.2',
      sourceRevision: '00102833dfaee1da9f48a3a8eae9d34005a75218',
      sourceCompatibleAtRevision: true,
      runtimeSupported: false,
    })
    expect(Object.values(fixture.publicSeams).every(Boolean)).toBe(true)
  })

  it.each(Object.entries(supportedRuntimePackages))(
    'accepts exact runtime metadata for %s@%s',
    async () => {
      await expect(
        assertRuntimeCompatibility(async (requested) => ({
          version: supportedRuntimePackages[requested],
        })),
      ).resolves.toBeUndefined()
    },
  )

  it.each(Object.entries(supportedRuntimePackages))(
    'refuses mismatched runtime metadata for %s before registration',
    async (packageName) => {
      await expect(
        assertRuntimeCompatibility(async (requested) => ({
          version:
            requested === packageName ? '0.0.0-unsupported' : supportedRuntimePackages[requested],
        })),
      ).rejects.toMatchObject({
        name: 'RuntimeCompatibilityError',
        code: 'DSH_OIDC_UNSUPPORTED_RUNTIME',
        packageName,
        observedVersion: '0.0.0-unsupported',
      })
    },
  )

  it.each([
    ['@deepseek-ai/cordis', '4.0.2'],
    ['@deepseek-ai/dsh-client-connection', '0.1.5-rc.1'],
    ['@deepseek-ai/dsh-credentials', '0.1.5-rc.1'],
    ['@deepseek-ai/dsh-host-webserver', '0.1.5-rc.1'],
  ])(
    'rejects a stale prior-release peer %s@%s in an otherwise upgraded graph',
    async (name, version) => {
      await expect(
        assertRuntimeCompatibility(async (requested) => ({
          version: requested === name ? version : supportedRuntimePackages[requested],
        })),
      ).rejects.toMatchObject({ packageName: name, observedVersion: version })
    },
  )

  it('records the inspected target source and real-stack compatibility contract', async () => {
    const fixture = (
      await import('./fixtures/dsh-0.2.0-rc.2-public-seams.json', { with: { type: 'json' } })
    ).default
    expect(fixture.upstreamVersion).toBe('0.2.0-rc.2')
    expect(fixture.sourceRevision).toBe('639ed015397290b3745d163aafe02ffee4aa3f84')
    expect(fixture.runtimePackages).toEqual(supportedRuntimePackages)
    // This fixture is an audit record, not a substitute for the real-stack gate.
    expect(fixture.proxyRequired).toBe(true)
  })

  it('refuses unreadable public metadata with a sanitized marker', async () => {
    await expect(
      assertRuntimeCompatibility(async () => Promise.reject(new Error('/private/path'))),
    ).rejects.toMatchObject({ observedVersion: '<unreadable>' })
  })

  it('does not echo malformed metadata as an observed version', async () => {
    await expect(
      assertRuntimeCompatibility(async () => ({ version: 'secret\n/private/path'.repeat(20) })),
    ).rejects.toMatchObject({ observedVersion: '<invalid>' })
  })

  it('registers the complete exact authentication route set through the public webserver seam', async () => {
    const routes: Array<{ kind: string; path: string }> = []
    const effects: Array<() => void> = []
    const ctx = {
      credentials: {},
      connection: {},
      logger: {},
      webServer: {
        register(route: { kind: string; path: string }) {
          routes.push(route)
          return () => {
            const index = routes.indexOf(route)
            if (index !== -1) routes.splice(index, 1)
          }
        },
      },
      effect(factory: () => () => void) {
        effects.push(factory())
      },
    } as unknown as Context

    await apply(ctx, {
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
    expect(routes).toEqual([])
  })
})
