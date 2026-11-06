import { prepareDeployedWebsiteTarget, type WebsiteInputError } from "./caseForm.ts";

export type InternalDeviceScanProfile = "internal_device_https";

export type InternalDeviceEndpointError = WebsiteInputError | "https_required";

const GREENBONE_TEMPLATE_REVISION =
  "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df";

/**
 * These are reporting VTs, not inventory VTs. Each one can emit a Greenbone
 * security result for an exact TLS service. Their discovery and collection
 * dependencies are resolved by the pinned feed rather than copied into this
 * product-owned allowlist.
 */
export const internalDeviceTlsVulnerabilityOids = [
  // Deprecated protocols and protocol-level attacks.
  "1.3.6.1.4.1.25623.1.0.111012",
  "1.3.6.1.4.1.25623.1.0.117274",
  "1.3.6.1.4.1.25623.1.0.802087",
  "1.3.6.1.4.1.25623.1.0.108094",
  // Anonymous, null, and weak cipher suites.
  "1.3.6.1.4.1.25623.1.0.108147",
  "1.3.6.1.4.1.25623.1.0.108022",
  "1.3.6.1.4.1.25623.1.0.103440",
  // Expired, weakly signed, or undersized server certificates.
  "1.3.6.1.4.1.25623.1.0.103955",
  "1.3.6.1.4.1.25623.1.0.105880",
  "1.3.6.1.4.1.25623.1.0.150710",
  "1.3.6.1.4.1.25623.1.0.150749",
] as const;

export const internalDeviceHttpsProfile = {
  scanProfile: "internal_device_https" as const,
  label: { en: "HTTPS management-service security", zhTW: "HTTPS 管理服務安全" },
  exampleUrl: "https://10.20.0.10",
  coverageNote: {
    en: "Checks the exact HTTPS management service for TLS protocol, cipher, and certificate weaknesses. It does not sign in or assess the whole device, its configuration, or firmware CVEs.",
    zhTW: "檢查這個精確 HTTPS 管理服務的 TLS 協定、cipher 與憑證弱點；不會登入，也不會檢查整台設備、設備設定或韌體 CVE。",
  },
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  allowedTemplateIds: [...internalDeviceTlsVulnerabilityOids],
} as const;

export const internalDeviceProfileFromScanProfile = (
  profile: string | undefined,
): typeof internalDeviceHttpsProfile | undefined =>
  profile === internalDeviceHttpsProfile.scanProfile ? internalDeviceHttpsProfile : undefined;

export interface PreparedInternalDeviceEndpoint {
  scanProfile: InternalDeviceScanProfile;
  /** Canonical host or address passed to the native exact-target boundary. */
  target: string;
  /** Human-reviewable network boundary; URL paths do not widen the scanner. */
  origin: string;
  protocol: "https";
  ports: [number];
  enteredPath: string;
  queryWasRemoved: boolean;
  engineIds: ["greenbone"];
  ratePolicy: {
    requestsPerSecond: number;
    concurrency: number;
    timeoutSeconds: number;
  };
  templatePolicy: {
    revision: string;
    allowedTemplateIds: string[];
    allowHeadless: false;
    allowOutOfBand: false;
    allowFuzzing: false;
    allowFileUpload: false;
    allowDenialOfService: false;
    allowCredentialAttacks: false;
  };
}

export type PrepareInternalDeviceEndpointResult =
  | { ok: true; value: PreparedInternalDeviceEndpoint }
  | { ok: false; error: InternalDeviceEndpointError };

/**
 * Converts one exact HTTPS management URL into the immutable part of a generic
 * Greenbone authorization/route. Authority and sensitive-network consent
 * remain explicit caller inputs and are never inferred here.
 */
export const prepareInternalDeviceEndpoint = (
  input: string,
): PrepareInternalDeviceEndpointResult => {
  const prepared = prepareDeployedWebsiteTarget(input);
  if (!prepared.ok) return prepared;
  if (prepared.value.service.protocol !== "https") {
    return { ok: false, error: "https_required" };
  }

  const { target, service } = prepared.value;
  const originHost = target.includes(":") ? `[${target}]` : target;
  return {
    ok: true,
    value: {
      scanProfile: internalDeviceHttpsProfile.scanProfile,
      target,
      origin: `https://${originHost}:${service.port}`,
      protocol: "https",
      ports: [service.port],
      enteredPath: service.path,
      queryWasRemoved: service.queryWasRemoved,
      engineIds: ["greenbone"],
      ratePolicy: { ...internalDeviceHttpsProfile.ratePolicy },
      templatePolicy: {
        revision: internalDeviceHttpsProfile.templateRevision,
        allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
    },
  };
};
