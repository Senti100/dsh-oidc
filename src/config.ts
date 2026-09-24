import z from '@deepseek-ai/schemastery'
import { credentialRef, type CredentialRef } from '@deepseek-ai/dsh-credentials'

/** Host-only OIDC admission configuration. */
export interface Config {
  issuer: string
  clientId: string
  clientSecretRef?: string
  publicOrigin: string
  scopes?: string[]
  sessionMaxAgeSeconds?: number
  sessionIdleTimeoutSeconds?: number
  transactionMaxAgeSeconds?: number
  allowedSubjects?: Array<{ issuer: string; subject: string }> | undefined
  allowedEmails?: string[] | undefined
  allowedGroups?: string[] | undefined
  groupMode?: 'any' | 'all'
  groupsClaim?: string
  requiredClaims?: Record<string, string[]>
  rpInitiatedLogout?: boolean
  clockToleranceSeconds?: number
  maxAuthenticationAgeSeconds?: number
  maxTransactions?: number
  maxSessions?: number
  loginRateLimitPerMinute?: number
}

export const Config: z<Config> = z.object({
  issuer: z.string().required(),
  clientId: z.string().required(),
  clientSecretRef: z.string(),
  publicOrigin: z.string().required(),
  scopes: z.array(String).default(['openid', 'profile', 'email']),
  sessionMaxAgeSeconds: z
    .natural()
    .min(60)
    .default(8 * 60 * 60),
  sessionIdleTimeoutSeconds: z
    .natural()
    .min(60)
    .default(30 * 60),
  transactionMaxAgeSeconds: z
    .natural()
    .min(30)
    .max(5 * 60)
    .default(5 * 60),
  allowedSubjects: z.union([
    z.array(z.object({ issuer: z.string().required(), subject: z.string().required() })),
    z.const(undefined),
  ]),
  allowedEmails: z.union([z.array(String), z.const(undefined)]),
  allowedGroups: z.union([z.array(String), z.const(undefined)]),
  groupMode: z.union([z.const('any'), z.const('all')]).default('any'),
  groupsClaim: z.string().default('groups'),
  requiredClaims: z.dict(z.array(String)).default({}),
  rpInitiatedLogout: z.boolean().default(true),
  clockToleranceSeconds: z.natural().max(300).default(30),
  maxAuthenticationAgeSeconds: z.natural().min(1),
  maxTransactions: z.natural().min(1).max(10_000).default(1_000),
  maxSessions: z.natural().min(1).max(100_000).default(10_000),
  loginRateLimitPerMinute: z.natural().min(1).max(1_000).default(20),
})

export interface AuthorizationPolicy {
  readonly allowedSubjects: ReadonlySet<string>
  readonly allowedEmails: ReadonlySet<string>
  readonly allowedGroups: ReadonlySet<string>
  readonly groupMode: 'any' | 'all'
  readonly groupsClaim: string
  readonly requiredClaims: ReadonlyMap<string, ReadonlySet<string>>
}

export interface ResolvedConfig {
  readonly issuer: URL
  readonly clientId: string
  readonly clientSecretRef?: CredentialRef
  readonly publicOrigin: URL
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly sessionMaxAgeSeconds: number
  readonly sessionIdleTimeoutSeconds: number
  readonly transactionMaxAgeSeconds: number
  readonly policy: AuthorizationPolicy
  readonly rpInitiatedLogout: boolean
  readonly clockToleranceSeconds: number
  readonly maxAuthenticationAgeSeconds?: number
  readonly maxTransactions: number
  readonly maxSessions: number
  readonly loginRateLimitPerMinute: number
}

function exactHttpsUrl(value: string, field: string): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error(`dsh-oidc: ${field} must be an absolute URL`)
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(
      `dsh-oidc: ${field} must be an HTTPS URL without credentials, query, or fragment`,
    )
  }
  return url
}

function exactStrings(values: readonly string[] | undefined, field: string): readonly string[] {
  const result = values ?? []
  if (result.some((value) => value.length === 0 || value.trim() !== value)) {
    throw new Error(
      `dsh-oidc: ${field} values must be non-empty exact strings without surrounding whitespace`,
    )
  }
  if (new Set(result).size !== result.length)
    throw new Error(`dsh-oidc: ${field} contains duplicates`)
  return result
}

/** Validate configuration before any route is registered. */
export function resolveConfig(config: Config): ResolvedConfig {
  const issuer = exactHttpsUrl(config.issuer, 'issuer')

  const publicOrigin = exactHttpsUrl(config.publicOrigin, 'publicOrigin')
  if (publicOrigin.pathname !== '/')
    throw new Error('dsh-oidc: publicOrigin must be an origin with path /')
  const scopes = exactStrings(config.scopes ?? ['openid', 'profile', 'email'], 'scopes')
  if (!scopes.includes('openid')) throw new Error('dsh-oidc: scopes must include openid')
  if (config.clientId.length === 0 || config.clientId.trim() !== config.clientId)
    throw new Error('dsh-oidc: clientId must be a non-empty exact string')
  if (config.allowedSubjects !== undefined && config.allowedSubjects.length === 0)
    throw new Error('dsh-oidc: allowedSubjects must not be explicitly empty')
  if (config.allowedEmails !== undefined && config.allowedEmails.length === 0)
    throw new Error('dsh-oidc: allowedEmails must not be explicitly empty')
  if (config.allowedGroups !== undefined && config.allowedGroups.length === 0)
    throw new Error('dsh-oidc: allowedGroups must not be explicitly empty')
  const allowedSubjects = (config.allowedSubjects ?? []).map(
    ({ issuer: allowedIssuer, subject }) => {
      const exactIssuer = exactHttpsUrl(allowedIssuer, 'allowedSubjects.issuer').href
      const [exactSubject] = exactStrings([subject], 'allowedSubjects.subject')
      return `${exactIssuer}\u0000${exactSubject}`
    },
  )
  if (new Set(allowedSubjects).size !== allowedSubjects.length)
    throw new Error('dsh-oidc: allowedSubjects contains duplicates')
  const allowedEmails = exactStrings(config.allowedEmails, 'allowedEmails')
  const allowedGroups = exactStrings(config.allowedGroups, 'allowedGroups')
  if (
    allowedSubjects.length === 0 &&
    allowedEmails.length === 0 &&
    allowedGroups.length === 0 &&
    Object.keys(config.requiredClaims ?? {}).length === 0
  )
    throw new Error('dsh-oidc: at least one allow policy is required')
  const groupsClaim = config.groupsClaim ?? 'groups'
  if (groupsClaim.length === 0 || groupsClaim.trim() !== groupsClaim)
    throw new Error('dsh-oidc: groupsClaim must be a non-empty exact string')
  const requiredClaims = new Map(
    Object.entries(config.requiredClaims ?? {}).map(([claim, values]) => {
      if (claim.length === 0 || claim.trim() !== claim)
        throw new Error('dsh-oidc: requiredClaims keys must be non-empty exact strings')
      const allowed = exactStrings(values, `requiredClaims.${claim}`)
      if (allowed.length === 0)
        throw new Error(`dsh-oidc: requiredClaims.${claim} must not be empty`)
      return [claim, new Set(allowed)] as const
    }),
  )
  const sessionMaxAgeSeconds = config.sessionMaxAgeSeconds ?? 8 * 60 * 60
  const sessionIdleTimeoutSeconds = config.sessionIdleTimeoutSeconds ?? 30 * 60
  if (sessionIdleTimeoutSeconds > sessionMaxAgeSeconds)
    throw new Error('dsh-oidc: session idle timeout must not exceed absolute lifetime')
  return {
    issuer,
    clientId: config.clientId,
    ...(config.clientSecretRef === undefined
      ? {}
      : { clientSecretRef: credentialRef(config.clientSecretRef) }),
    publicOrigin,
    redirectUri: new URL('/auth/callback', publicOrigin).href,
    scopes,
    sessionMaxAgeSeconds,
    sessionIdleTimeoutSeconds,
    transactionMaxAgeSeconds: config.transactionMaxAgeSeconds ?? 5 * 60,
    policy: {
      allowedSubjects: new Set(allowedSubjects),
      allowedEmails: new Set(allowedEmails),
      allowedGroups: new Set(allowedGroups),
      groupMode: config.groupMode ?? 'any',
      groupsClaim,
      requiredClaims,
    },
    rpInitiatedLogout: config.rpInitiatedLogout ?? true,
    clockToleranceSeconds: config.clockToleranceSeconds ?? 30,
    ...(config.maxAuthenticationAgeSeconds === undefined
      ? {}
      : { maxAuthenticationAgeSeconds: config.maxAuthenticationAgeSeconds }),
    maxTransactions: config.maxTransactions ?? 1_000,
    maxSessions: config.maxSessions ?? 10_000,
    loginRateLimitPerMinute: config.loginRateLimitPerMinute ?? 20,
  }
}
