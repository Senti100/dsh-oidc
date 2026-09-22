import * as oidc from 'openid-client'
import type { ResolvedConfig } from './config.js'

export interface AuthorizationStart {
  readonly url: URL
  readonly verifier: string
  readonly nonce: string
}

export interface CallbackChecks {
  readonly verifier: string
  readonly nonce: string
  readonly state: string
  readonly currentUrl: URL
}

export interface OidcProtocol {
  start(clientSecret: string | undefined): Promise<AuthorizationStart>
  callback(
    clientSecret: string | undefined,
    checks: CallbackChecks,
  ): Promise<Readonly<Record<string, unknown>>>
  logoutUrl(clientSecret: string | undefined): Promise<URL | undefined>
}

const safeFetch: oidc.CustomFetch = async (input, init) =>
  fetch(input, { ...init, redirect: 'manual' } as RequestInit)

/** Standards implementation backed by openid-client discovery, JWKS, and token validation. */
export class OpenIdClientProtocol implements OidcProtocol {
  constructor(
    private readonly config: ResolvedConfig,
    private readonly requestTimeoutSeconds = 10,
  ) {}

  private async discover(clientSecret: string | undefined): Promise<oidc.Configuration> {
    const metadata: Partial<oidc.ClientMetadata> = {
      redirect_uris: [this.config.redirectUri],
      response_types: ['code'],
      [oidc.clockTolerance]: this.config.clockToleranceSeconds,
    }
    const clientAuth =
      clientSecret === undefined ? oidc.None() : oidc.ClientSecretPost(clientSecret)
    return oidc.discovery(this.config.issuer, this.config.clientId, metadata, clientAuth, {
      [oidc.customFetch]: safeFetch,
      timeout: this.requestTimeoutSeconds,
      execute: [oidc.enableNonRepudiationChecks],
    })
  }

  async start(clientSecret: string | undefined): Promise<AuthorizationStart> {
    const configuration = await this.discover(clientSecret)
    const verifier = oidc.randomPKCECodeVerifier()
    const challenge = await oidc.calculatePKCECodeChallenge(verifier)
    const nonce = oidc.randomNonce()
    const state = oidc.randomState()
    const parameters: Record<string, string> = {
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      nonce,
      state,
    }
    if (this.config.maxAuthenticationAgeSeconds !== undefined) {
      parameters.max_age = String(this.config.maxAuthenticationAgeSeconds)
    }
    return { url: oidc.buildAuthorizationUrl(configuration, parameters), verifier, nonce }
  }

  async callback(
    clientSecret: string | undefined,
    checks: CallbackChecks,
  ): Promise<Readonly<Record<string, unknown>>> {
    const configuration = await this.discover(clientSecret)
    const tokens = await oidc.authorizationCodeGrant(configuration, checks.currentUrl, {
      pkceCodeVerifier: checks.verifier,
      expectedState: checks.state,
      expectedNonce: checks.nonce,
      idTokenExpected: true,
      ...(this.config.maxAuthenticationAgeSeconds === undefined
        ? {}
        : { maxAge: this.config.maxAuthenticationAgeSeconds }),
    })
    const claims = tokens.claims()
    if (claims === undefined) throw new Error('validated ID token claims are missing')
    const issuedAt = claims.iat
    const latestIssuedAt = Math.floor(Date.now() / 1000) + this.config.clockToleranceSeconds
    if (!Number.isSafeInteger(issuedAt) || issuedAt > latestIssuedAt) {
      throw new Error('validated ID token has an invalid issuance time')
    }
    return claims
  }

  async logoutUrl(clientSecret: string | undefined): Promise<URL | undefined> {
    if (!this.config.rpInitiatedLogout) return undefined
    const configuration = await this.discover(clientSecret)
    if (configuration.serverMetadata().end_session_endpoint === undefined) return undefined
    return oidc.buildEndSessionUrl(configuration, {
      client_id: this.config.clientId,
      post_logout_redirect_uri: this.config.publicOrigin.href,
    })
  }
}
