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

export type OidcValidationCode =
  | 'OIDC_AZP_INVALID'
  | 'OIDC_AZP_MISMATCH'
  | 'OIDC_AZP_REQUIRED'
  | 'OIDC_AUTH_TIME_FUTURE'
  | 'OIDC_AUTH_TIME_INVALID'
  | 'OIDC_AUTH_TIME_MISSING'
  | 'OIDC_AUTH_TIME_STALE'
  | 'OIDC_DISCOVERY_INVALID'
  | 'OIDC_HTTP_REDIRECT'
  | 'OIDC_HTTP_TIMEOUT'
  | 'OIDC_IAT_INVALID'

export class OidcValidationError extends Error {
  constructor(
    readonly code: OidcValidationCode,
    options?: ErrorOptions,
  ) {
    super(`dsh-oidc: ${code}`, options)
    this.name = 'OidcValidationError'
  }
}

export function validateAuthorizedParty(
  claims: Readonly<Record<string, unknown>>,
  clientId: string,
): void {
  const { aud, azp } = claims
  if (Array.isArray(aud) && aud.length > 1 && azp === undefined)
    throw new OidcValidationError('OIDC_AZP_REQUIRED')
  if (azp !== undefined && typeof azp !== 'string')
    throw new OidcValidationError('OIDC_AZP_INVALID')
  if (typeof azp === 'string' && azp !== clientId)
    throw new OidcValidationError('OIDC_AZP_MISMATCH')
}

export function validateAuthenticationTime(
  claims: Readonly<Record<string, unknown>>,
  maximumAgeSeconds: number | undefined,
  clockToleranceSeconds: number,
  nowSeconds = Math.floor(Date.now() / 1000),
): void {
  if (maximumAgeSeconds === undefined) return
  const authTime = claims.auth_time
  if (authTime === undefined) throw new OidcValidationError('OIDC_AUTH_TIME_MISSING')
  if (!Number.isSafeInteger(authTime)) throw new OidcValidationError('OIDC_AUTH_TIME_INVALID')
  if ((authTime as number) > nowSeconds + clockToleranceSeconds)
    throw new OidcValidationError('OIDC_AUTH_TIME_FUTURE')
  if ((authTime as number) + maximumAgeSeconds + clockToleranceSeconds < nowSeconds)
    throw new OidcValidationError('OIDC_AUTH_TIME_STALE')
}

const safeFetch: oidc.CustomFetch = async (input, init) => {
  let response: Response
  try {
    response = await fetch(input, { ...init, redirect: 'manual' } as RequestInit)
  } catch (error) {
    const name = error instanceof Error ? error.name : ''
    if (name === 'AbortError' || name === 'TimeoutError') {
      throw new OidcValidationError('OIDC_HTTP_TIMEOUT', { cause: error })
    }
    throw error
  }
  if (response.status >= 300 && response.status < 400) {
    throw new OidcValidationError('OIDC_HTTP_REDIRECT')
  }
  return response
}

function findValidationError(error: unknown): OidcValidationError | undefined {
  let current = error
  for (let depth = 0; depth < 6 && current instanceof Error; depth += 1) {
    if (current instanceof OidcValidationError) return current
    current = current.cause
  }
  return undefined
}

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
    try {
      return await oidc.discovery(this.config.issuer, this.config.clientId, metadata, clientAuth, {
        [oidc.customFetch]: safeFetch,
        timeout: this.requestTimeoutSeconds,
        execute: [oidc.enableNonRepudiationChecks],
      })
    } catch (error) {
      const deterministic = findValidationError(error)
      if (deterministic !== undefined) throw deterministic
      throw new OidcValidationError('OIDC_DISCOVERY_INVALID', { cause: error })
    }
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
    validateAuthorizedParty(claims, this.config.clientId)
    validateAuthenticationTime(
      claims,
      this.config.maxAuthenticationAgeSeconds,
      this.config.clockToleranceSeconds,
    )
    const issuedAt = claims.iat
    const latestIssuedAt = Math.floor(Date.now() / 1000) + this.config.clockToleranceSeconds
    if (!Number.isSafeInteger(issuedAt) || issuedAt > latestIssuedAt) {
      throw new OidcValidationError('OIDC_IAT_INVALID')
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
