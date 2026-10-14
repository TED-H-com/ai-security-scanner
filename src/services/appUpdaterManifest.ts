import { PUBLICATION_ORIGINS } from "../../scripts/publication-origins.mjs";

export interface AppUpdateManifestCandidate {
  version: string;
  rawJson: Record<string, unknown>;
}

export type AppUpdaterRuntime =
  | { platform: "linux" | "windows"; architecture: "x86_64" }
  | { platform: "macos"; architecture: "aarch64" | "universal" | "x86_64" };

interface RequiredPayloadGroup {
  keys: readonly string[];
  suffix: string;
}

const EXPECTED_RELEASE_PATH = ["ai-security-scanner", "releases", "download"] as const;
const RELEASE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;

const normalizePlatform = (
  value: string | undefined,
): AppUpdaterRuntime["platform"] | undefined => {
  switch (value?.trim().toLocaleLowerCase("en-US")) {
    case "linux":
      return "linux";
    case "darwin":
    case "macos":
      return "macos";
    case "windows":
      return "windows";
    default:
      return undefined;
  }
};

const normalizeArchitecture = (
  value: string | undefined,
): AppUpdaterRuntime["architecture"] | undefined => {
  switch (value?.trim().toLocaleLowerCase("en-US")) {
    case "aarch64":
    case "arm64":
      return "aarch64";
    case "universal":
    case "universal-apple-darwin":
      return "universal";
    case "x64":
    case "x86_64":
      return "x86_64";
    default:
      return undefined;
  }
};

export const resolveAppUpdaterRuntime = (
  platform: string | undefined,
  architecture: string | undefined,
): AppUpdaterRuntime => {
  const normalizedPlatform = normalizePlatform(platform);
  const normalizedArchitecture = normalizeArchitecture(architecture);
  if (!normalizedPlatform || !normalizedArchitecture) {
    throw new Error("This operating system or processor is not supported by the app updater.");
  }
  if (normalizedPlatform === "macos") {
    return { platform: normalizedPlatform, architecture: normalizedArchitecture };
  }
  if (normalizedArchitecture !== "x86_64") {
    throw new Error("This operating system or processor is not supported by the app updater.");
  }
  return { platform: normalizedPlatform, architecture: normalizedArchitecture };
};

const requiredPayloadGroups = (runtime: AppUpdaterRuntime): readonly RequiredPayloadGroup[] => {
  if (runtime.platform === "windows") {
    return [{ keys: ["windows-x86_64", "windows-x86_64-nsis"], suffix: ".exe" }];
  }
  if (runtime.platform === "linux") {
    return [{ keys: ["linux-x86_64", "linux-x86_64-appimage"], suffix: ".AppImage" }];
  }
  if (runtime.architecture === "universal") {
    return [{
      keys: [
        "darwin-x86_64",
        "darwin-x86_64-app",
        "darwin-aarch64",
        "darwin-aarch64-app",
      ],
      suffix: ".app.tar.gz",
    }];
  }
  const architecture = runtime.architecture;
  return [{
    keys: [`darwin-${architecture}`, `darwin-${architecture}-app`],
    suffix: ".app.tar.gz",
  }];
};

const validatePayloadEntry = (
  target: string,
  value: unknown,
  version: string,
  expectedSuffix: string,
): { url: string; signature: string } => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The update manifest is missing the required ${target} payload.`);
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.signature !== "string" ||
    record.signature.length < 64 ||
    record.signature.length > 32 * 1024 ||
    !/^[A-Za-z0-9+/=]+$/u.test(record.signature)
  ) {
    throw new Error(`The update manifest has an invalid signature for ${target}.`);
  }
  if (typeof record.url !== "string" || record.url.length > 2_048) {
    throw new Error(`The update manifest has an invalid download location for ${target}.`);
  }

  let url: URL;
  try {
    url = new URL(record.url);
  } catch {
    throw new Error(`The update manifest has an invalid download location for ${target}.`);
  }
  let pathParts: string[];
  try {
    pathParts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    throw new Error(`The update manifest has an invalid download location for ${target}.`);
  }
  const payloadName = pathParts[5] ?? "";
  if (
    url.protocol !== "https:" ||
    url.hostname !== "github.com" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    pathParts.length !== 6 ||
    !PUBLICATION_ORIGINS.some((origin) => origin.repository === `${pathParts[0]}/${pathParts[1]}`) ||
    EXPECTED_RELEASE_PATH.some((part, index) => pathParts[index + 1] !== part) ||
    pathParts[4] !== `v${version}` ||
    !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/u.test(payloadName) ||
    !payloadName.includes(version) ||
    !payloadName.endsWith(expectedSuffix)
  ) {
    throw new Error(`The update manifest has an untrusted download location for ${target}.`);
  }
  return { url: record.url, signature: record.signature };
};

/**
 * Validate only the signed payloads this running app can select. A release may
 * publish platforms independently; an unrelated platform must not make this
 * installed app unusable or prevent it from applying its own valid update.
 */
export const validateAppUpdateManifest = (
  update: AppUpdateManifestCandidate,
  runtime: AppUpdaterRuntime,
): void => {
  const raw = update.rawJson;
  if (
    typeof update.version !== "string" ||
    update.version.length > 128 ||
    !RELEASE_VERSION.test(update.version) ||
    raw.version !== update.version ||
    !raw.platforms ||
    typeof raw.platforms !== "object" ||
    Array.isArray(raw.platforms)
  ) {
    throw new Error("The update manifest has an invalid version or platform section.");
  }

  const platforms = raw.platforms as Record<string, unknown>;
  for (const group of requiredPayloadGroups(runtime)) {
    const validated = group.keys.map((key) =>
      validatePayloadEntry(key, platforms[key], update.version, group.suffix));
    const first = validated[0];
    if (!first || validated.some((candidate) =>
      candidate.url !== first.url || candidate.signature !== first.signature)) {
      throw new Error("The update manifest fallback does not reference the same signed payload.");
    }
  }
};
