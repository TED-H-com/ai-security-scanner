// Pinned prebuilt release CLI executables, matched only on clean release checkouts.
// Each entry in PREBUILT_CORES must be frozen and follow this shape:
// {
//   product_version: '<release version>',
//   input_sha256: '<64 hex: collectInputManifest(...).inputDigest of the release source>',
//   recipe: '<RECIPE of the release source, for example skill-bootstrap-v1>',
//   rust_version: '<Rust version that built the release, for example 1.98.0>',
//   platform: 'linux' | 'darwin' | 'win32',
//   targets: { x64: '<Rust target that runs on this Node architecture>', arm64: '...' },
//   features: ['cli'],            // exactly what build-identity reports; Windows also has 'installer-runtime-cache'
//   release_source: { url: 'https://…', bytes: <integer>, sha256: '<64 hex>' },
// }
export const PREBUILT_CORES = Object.freeze([]);
