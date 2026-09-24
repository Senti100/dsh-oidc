const SUPPORTED_RUNTIME_PACKAGES = {
  '@deepseek-ai/cordis': '4.0.2',
  '@deepseek-ai/dsh-client-connection': '0.1.5-rc.1',
  '@deepseek-ai/dsh-credentials': '0.1.5-rc.1',
  '@deepseek-ai/dsh-host-webserver': '0.1.5-rc.1',
} as const

export type SupportedRuntimePackage = keyof typeof SUPPORTED_RUNTIME_PACKAGES
export type PackageMetadataLoader = (packageName: SupportedRuntimePackage) => Promise<unknown>

export class RuntimeCompatibilityError extends Error {
  readonly code = 'DSH_OIDC_UNSUPPORTED_RUNTIME'

  constructor(
    readonly packageName: SupportedRuntimePackage,
    readonly supportedVersion: string,
    readonly observedVersion: string,
  ) {
    super(
      `dsh-oidc: incompatible runtime package ${packageName}; supported=${supportedVersion}; observed=${observedVersion}`,
    )
    this.name = 'RuntimeCompatibilityError'
  }
}

const loadPublicPackageMetadata: PackageMetadataLoader = async (packageName) => {
  const namespace: unknown = await import(`${packageName}/package.json`, { with: { type: 'json' } })
  if (typeof namespace !== 'object' || namespace === null || !('default' in namespace))
    return undefined
  return namespace.default
}

/** Refuse unsupported or unreadable DSH package metadata before route registration. */
export async function assertRuntimeCompatibility(
  loadMetadata: PackageMetadataLoader = loadPublicPackageMetadata,
): Promise<void> {
  for (const [packageName, supportedVersion] of Object.entries(SUPPORTED_RUNTIME_PACKAGES) as Array<
    [SupportedRuntimePackage, string]
  >) {
    let observedVersion = '<unreadable>'
    try {
      const metadata = await loadMetadata(packageName)
      if (
        typeof metadata === 'object' &&
        metadata !== null &&
        'version' in metadata &&
        typeof metadata.version === 'string' &&
        /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/u.test(metadata.version)
      ) {
        observedVersion = metadata.version
      } else {
        observedVersion = '<invalid>'
      }
    } catch {
      // The sanitized observed marker below intentionally omits loader details and paths.
    }
    if (observedVersion !== supportedVersion) {
      throw new RuntimeCompatibilityError(packageName, supportedVersion, observedVersion)
    }
  }
}

export const supportedRuntimePackages: Readonly<Record<SupportedRuntimePackage, string>> =
  SUPPORTED_RUNTIME_PACKAGES
