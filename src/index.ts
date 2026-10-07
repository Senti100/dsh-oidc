import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-connection'
import type {} from '@deepseek-ai/dsh-credentials'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import { OidcAdmission } from './admission.js'
import { assertRuntimeCompatibility } from './compatibility.js'
import { Config, resolveConfig, type Config as OidcConfig } from './config.js'
import { OpenIdClientProtocol } from './oidc.js'

export { Config }
export type { OidcConfig as ConfigType }
export { authorizeClaims, type Principal } from './policy.js'
export { resolveConfig } from './config.js'
export const name = 'senti100-oidc'
export const inject = ['webServer', 'connection', 'credentials']

/** Register Host-only OIDC routes alongside the unchanged native Connection plugin. */
export async function apply(ctx: Context, rawConfig: OidcConfig): Promise<void> {
  const config = resolveConfig(rawConfig)
  await assertRuntimeCompatibility()
  const admission = new OidcAdmission(
    config,
    ctx.credentials,
    ctx.connection,
    new OpenIdClientProtocol(config),
    ctx.logger,
  )
  const routes: readonly WebRoute[] = [
    { kind: 'exact', path: '/auth/login', handler: (req, res) => admission.login(req, res) },
    { kind: 'exact', path: '/auth/callback', handler: (req, res) => admission.callback(req, res) },
    { kind: 'exact', path: '/auth/check', handler: (req, res) => admission.check(req, res) },
    {
      kind: 'exact',
      path: '/auth/signin',
      handler: (req, res) => admission.signin(req, res),
    },
    {
      kind: 'exact',
      path: '/auth/logout',
      handler: (req, res) =>
        req.method === 'POST' ? admission.logout(req, res) : admission.logoutConfirmation(req, res),
    },
  ]
  for (const route of routes)
    ctx.effect(() => ctx.webServer.register(route), `dsh-oidc: ${route.path}`)
}
