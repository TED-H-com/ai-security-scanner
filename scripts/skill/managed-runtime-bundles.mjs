// Manifest digests of managed-runtime bundles inside published desktop installers.
// The bootstrap reuses an installed bundle only when its manifest is listed.
// Windows install folders depend on the user, so they are named by an
// environment variable and fixed path components (per-user installer, then MSI).
export const RECOGNIZED_MANAGED_RUNTIME_BUNDLES = Object.freeze([
  Object.freeze({
    platform: 'linux', arch: Object.freeze(['x64']), product_version: '0.6.2',
    manifest_sha256: 'd8e495ff77a57e7166821e6207e330a3790b6496ea2023dd367de077490912e5',
    installed_paths: Object.freeze(['/usr/lib/ai-security-scanner/managed-runtime']),
    installed_locations: Object.freeze([]),
    release_source: Object.freeze({
      kind: 'deb',
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.6.2/ai-security-scanner_0.6.2_amd64.deb',
      bytes: 84427266, sha256: 'd7a579978d811e8b516e5623f9ecfcb83d71aad6f0e2f63af351d73f98183a32',
      inner_path: 'usr/lib/ai-security-scanner/managed-runtime', extracted_bytes: 423333863,
    }),
  }),
  Object.freeze({
    platform: 'darwin', arch: Object.freeze(['x64', 'arm64']), product_version: '0.6.2',
    manifest_sha256: '470fd782236000a33b18a084379c8c260097cf6c5ea988963e70d4ab90b6a24b',
    installed_paths: Object.freeze(['/Applications/ai-security-scanner.app/Contents/Resources/managed-runtime']),
    installed_locations: Object.freeze([]),
    release_source: Object.freeze({
      kind: 'tar.gz',
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.6.2/ai-security-scanner_0.6.2_universal.app.tar.gz',
      bytes: 143685789, sha256: 'a815e381943a853acc7e2a50d3241241ec8d925dfff847ebaea9937ecf4ed56f',
      inner_path: 'ai-security-scanner.app/Contents/Resources/managed-runtime', extracted_bytes: 181947360,
    }),
  }),
  Object.freeze({
    platform: 'win32', arch: Object.freeze(['x64']), product_version: '0.7.0',
    manifest_sha256: 'b530cf8f62196dd54e6b31b815202f565b3abb32593ee79c1ec834ded662edd0',
    installed_paths: Object.freeze([]),
    installed_locations: Object.freeze([
      Object.freeze({ environment: 'LOCALAPPDATA', components: Object.freeze(['ai-security-scanner', 'managed-runtime']) }),
      Object.freeze({ environment: 'ProgramFiles', components: Object.freeze(['ai-security-scanner', 'managed-runtime']) }),
    ]),
    release_source: Object.freeze({
      kind: 'tar.gz',
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.7.0/managed-runtime-windows-x86_64.tar.gz',
      bytes: 20027651, sha256: '1997f8b626ac117a6720dd4f0ada8988c22a3d70628e1a271cd9c7f0fa405b92',
      inner_path: 'managed-runtime', extracted_bytes: 51750290,
    }),
  }),
]);
