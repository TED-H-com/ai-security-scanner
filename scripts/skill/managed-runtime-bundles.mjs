// Manifest digests of managed-runtime bundles inside published desktop installers.
// The bootstrap reuses an installed bundle only when its manifest is listed.
export const RECOGNIZED_MANAGED_RUNTIME_BUNDLES = Object.freeze([
  Object.freeze({
    platform: 'linux', arch: Object.freeze(['x64']), product_version: '0.6.2',
    manifest_sha256: 'd8e495ff77a57e7166821e6207e330a3790b6496ea2023dd367de077490912e5',
    installed_paths: Object.freeze(['/usr/lib/ai-security-scanner/managed-runtime']),
  }),
  Object.freeze({
    platform: 'darwin', arch: Object.freeze(['x64', 'arm64']), product_version: '0.6.2',
    manifest_sha256: '470fd782236000a33b18a084379c8c260097cf6c5ea988963e70d4ab90b6a24b',
    installed_paths: Object.freeze(['/Applications/ai-security-scanner.app/Contents/Resources/managed-runtime']),
  }),
  Object.freeze({
    platform: 'win32', arch: Object.freeze(['x64']), product_version: '0.6.2',
    manifest_sha256: 'b530cf8f62196dd54e6b31b815202f565b3abb32593ee79c1ec834ded662edd0',
    installed_paths: Object.freeze([]),
  }),
]);
