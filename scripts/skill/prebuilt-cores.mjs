// Public v0.7.0 CLI bytes verified against the frozen promotion and provenance.
// Source and asset evidence: docs/release/v0.7.0-publication.json.
export const PREBUILT_CORES = Object.freeze([
  Object.freeze({
    product_version: '0.7.0',
    input_sha256: '04c5ee93a86468a82528985b9e6fdc2f50c2416045c8619b7356191bc2333967',
    recipe: 'skill-bootstrap-v1',
    rust_version: '1.98.0',
    platform: 'linux',
    targets: Object.freeze({ x64: 'x86_64-unknown-linux-gnu' }),
    features: Object.freeze(['cli']),
    release_source: Object.freeze({
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.7.0/ai-security-scanner-cli-0.7.0-linux-x86_64',
      bytes: 40165224, sha256: '2fee7f9112748c22206dda0a24dcf3da0c81fa37b23d24c50b672a78e0018215',
    }),
  }),
  Object.freeze({
    product_version: '0.7.0',
    input_sha256: '04c5ee93a86468a82528985b9e6fdc2f50c2416045c8619b7356191bc2333967',
    recipe: 'skill-bootstrap-v1',
    rust_version: '1.98.0',
    platform: 'darwin',
    targets: Object.freeze({ x64: 'x86_64-apple-darwin', arm64: 'aarch64-apple-darwin' }),
    features: Object.freeze(['cli']),
    release_source: Object.freeze({
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.7.0/ai-security-scanner-cli-0.7.0-macos-universal',
      bytes: 70691344, sha256: 'a9be72874c5bd62b9a3248d1354a287e3f0ffd74c5d63349a5ca42fcd53e6ff8',
    }),
  }),
  Object.freeze({
    product_version: '0.7.0',
    input_sha256: '04c5ee93a86468a82528985b9e6fdc2f50c2416045c8619b7356191bc2333967',
    recipe: 'skill-bootstrap-v1',
    rust_version: '1.98.0',
    platform: 'win32',
    targets: Object.freeze({ x64: 'x86_64-pc-windows-msvc' }),
    features: Object.freeze(['cli', 'installer-runtime-cache']),
    release_source: Object.freeze({
      url: 'https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.7.0/ai-security-scanner-cli-0.7.0-windows-x86_64.exe',
      bytes: 35261440, sha256: 'a68015c5d4b658f7e557f9160a113aa60199d7adca1aea8f0c2f21389dc43518',
    }),
  }),
]);
