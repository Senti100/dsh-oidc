import { describe, expect, it } from 'vitest'
import { resolveConfig } from '../src/config.js'
import { authorizeClaims } from '../src/policy.js'

const base = {
  issuer: 'https://id.example/application/o/dsh/',
  clientId: 'client',
  publicOrigin: 'https://dsh.example',
  allowedSubjects: [{ issuer: 'https://id.example/application/o/dsh/', subject: 'subject-1' }],
}

describe('configuration and policy', () => {
  it('resolves fixed URLs, defaults, and credential references', () => {
    const config = resolveConfig({ ...base, clientSecretRef: 'OIDC_CLIENT_SECRET' })
    expect(config.issuer.href).toBe('https://id.example/application/o/dsh/')
    expect(config.publicOrigin.href).toBe('https://dsh.example/')
    expect(config.redirectUri).toBe('https://dsh.example/auth/callback')
    expect(config.clientSecretRef).toBe('OIDC_CLIENT_SECRET')
    expect(config.scopes).toContain('openid')
  })

  it.each([
    [{ ...base, issuer: 'http://id.example' }, /HTTPS/u],
    [{ ...base, publicOrigin: 'https://dsh.example/path' }, /path \/?/u],
    [{ ...base, scopes: ['profile'] }, /openid/u],
    [{ ...base, allowedSubjects: [] }, /explicitly empty/u],
    [{ ...base, allowedSubjects: [{ issuer: base.issuer, subject: ' x' }] }, /exact strings/u],
    [
      {
        ...base,
        allowedSubjects: [
          { issuer: base.issuer, subject: 'x' },
          { issuer: base.issuer, subject: 'x' },
        ],
      },
      /duplicates/u,
    ],
    [{ ...base, sessionMaxAgeSeconds: 60, sessionIdleTimeoutSeconds: 61 }, /idle timeout/u],
    [{ ...base, requiredClaims: { department: [] } }, /must not be empty/u],
  ])('rejects invalid config %#', (input, pattern) => {
    expect(() => resolveConfig(input)).toThrow(pattern)
  })

  it('ANDs configured categories while allowing values within a category', () => {
    const policy = resolveConfig({
      ...base,
      allowedGroups: ['operators'],
      requiredClaims: { department: ['engineering', 'security'] },
    }).policy
    const issuer = 'https://id.example/application/o/dsh/'
    expect(
      authorizeClaims(
        { iss: issuer, sub: 'subject-1', groups: ['operators'], department: 'engineering' },
        issuer,
        policy,
      )?.subject,
    ).toBe('subject-1')
    expect(
      authorizeClaims(
        { iss: issuer, sub: 'subject-1', groups: ['operators'], department: ['security'] },
        issuer,
        policy,
      )?.groups,
    ).toEqual(['operators'])
    expect(
      authorizeClaims(
        { iss: issuer, sub: 'other', groups: ['operators'], department: 'engineering' },
        issuer,
        policy,
      ),
    ).toBeUndefined()
    expect(
      authorizeClaims(
        { iss: issuer, sub: 'subject-1', groups: ['OPERATORS'], department: 'engineering' },
        issuer,
        policy,
      ),
    ).toBeUndefined()
  })

  it('enforces all-group mode and rejects malformed or duplicate group claims', () => {
    const groupOnly = {
      issuer: base.issuer,
      clientId: base.clientId,
      publicOrigin: base.publicOrigin,
    }
    const policy = resolveConfig({
      ...groupOnly,
      allowedGroups: ['a', 'b'],
      groupMode: 'all',
    }).policy
    const claims = { iss: 'https://id.example/application/o/dsh', sub: 's' }
    expect(
      authorizeClaims({ ...claims, groups: ['a', 'b'], name: 'Operator' }, claims.iss, policy)
        ?.displayName,
    ).toBe('Operator')
    expect(authorizeClaims({ ...claims, groups: ['a'] }, claims.iss, policy)).toBeUndefined()
    expect(authorizeClaims({ ...claims, groups: 'a' }, claims.iss, policy)).toBeUndefined()
    expect(
      authorizeClaims({ ...claims, groups: ['a', 'a', 'b'] }, claims.iss, policy),
    ).toBeUndefined()
    expect(
      authorizeClaims(
        { ...claims, groups: Array.from({ length: 257 }, (_, index) => `g${String(index)}`) },
        claims.iss,
        policy,
      ),
    ).toBeUndefined()
    expect(
      authorizeClaims({ ...claims, groups: ['a', 2, 'b'] }, claims.iss, policy),
    ).toBeUndefined()
  })

  it('treats email as an exact additional category rather than identity', () => {
    const policy = resolveConfig({ ...base, allowedEmails: ['operator@example.test'] }).policy
    const claims = { iss: base.issuer, sub: 'subject-1' }
    expect(
      authorizeClaims({ ...claims, email: 'operator@example.test' }, base.issuer, policy),
    ).toBeDefined()
    expect(
      authorizeClaims({ ...claims, email: 'Operator@example.test' }, base.issuer, policy),
    ).toBeUndefined()
    expect(
      authorizeClaims({ ...claims, email: ['operator@example.test'] }, base.issuer, policy),
    ).toBeUndefined()
  })
})
