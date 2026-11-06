export type InternalHostScanProfile = "internal_host_greenbone_remote_safe";

export const INTERNAL_HOST_PROFILE_ID = "greenbone_remote_safe_v1" as const;

/**
 * Wire `DeclaredHostScanProfile` values the adapter translates into UI names.
 * The names differ on purpose: the wire keeps the upstream profile id, the UI
 * type uses the internal-host scan-profile vocabulary.
 */
export const declaredHostScanProfileByWire = {
  [INTERNAL_HOST_PROFILE_ID]: "internal_host_greenbone_remote_safe",
} as const satisfies Record<string, InternalHostScanProfile>;

export const INTERNAL_HOST_GREENBONE_REVISION =
  "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df" as const;

export const INTERNAL_HOST_DEFAULT_PORTS = [
  22,
  23,
  25,
  80,
  443,
  445,
  3389,
  5900,
  8080,
  8443,
] as const;

export const internalHostGreenboneProfile = {
  scanProfile: "internal_host_greenbone_remote_safe" as const,
  profileId: INTERNAL_HOST_PROFILE_ID,
  label: { en: "Internal system", zhTW: "內部系統" },
  exampleTarget: "server.example.internal",
  engineIds: ["greenbone"] as const,
  templateRevision: INTERNAL_HOST_GREENBONE_REVISION,
  allowedTemplateIds: [] as string[],
  defaultPorts: [...INTERNAL_HOST_DEFAULT_PORTS],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
} as const;

export type InternalHostInputError =
  | "empty_target"
  | "url_not_allowed"
  | "credentials_not_allowed"
  | "cidr_not_allowed"
  | "service_coordinate_not_allowed"
  | "invalid_target";

export type InternalHostPortsError =
  | "invalid_ports"
  | "port_out_of_range"
  | "too_many_ports";

export type PrepareInternalHostResult =
  | { ok: true; value: string }
  | { ok: false; error: InternalHostInputError };

export type ParseInternalHostPortsResult =
  | { ok: true; value: number[] }
  | { ok: false; error: InternalHostPortsError };

const parseIpv4 = (value: string): number[] | undefined => {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) {
    return undefined;
  }
  const octets = parts.map(Number);
  return octets.every((octet) => octet <= 255) ? octets : undefined;
};

const parseIpv6 = (value: string): number[] | undefined => {
  let candidate = value.toLocaleLowerCase("en-US");
  if (!candidate.includes(":") || candidate.includes("%")) return undefined;
  if (candidate.includes(".")) {
    const separator = candidate.lastIndexOf(":");
    const ipv4 = parseIpv4(candidate.slice(separator + 1));
    if (separator < 0 || !ipv4) return undefined;
    candidate = `${candidate.slice(0, separator)}:${(((ipv4[0] ?? 0) << 8) | (ipv4[1] ?? 0)).toString(16)}:${(((ipv4[2] ?? 0) << 8) | (ipv4[3] ?? 0)).toString(16)}`;
  }
  const halves = candidate.split("::");
  if (halves.length > 2) return undefined;
  const parseHalf = (half: string): number[] | undefined => {
    if (!half) return [];
    const segments = half.split(":");
    return segments.every((segment) => /^[0-9a-f]{1,4}$/u.test(segment))
      ? segments.map((segment) => Number.parseInt(segment, 16))
      : undefined;
  };
  const left = parseHalf(halves[0] ?? "");
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;
  const omitted = 8 - left.length - right.length;
  return omitted > 0 ? [...left, ...Array<number>(omitted).fill(0), ...right] : undefined;
};

const canonicalIpv6 = (segments: number[]): string => {
  const hexadecimal = segments.map((segment) => segment.toString(16));
  let longestStart = -1;
  let longestLength = 0;
  for (let start = 0; start < segments.length;) {
    if (segments[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < segments.length && segments[end] === 0) end += 1;
    if (end - start > longestLength) {
      longestStart = start;
      longestLength = end - start;
    }
    start = end;
  }
  return longestLength >= 2
    ? `${hexadecimal.slice(0, longestStart).join(":")}::${hexadecimal.slice(longestStart + longestLength).join(":")}`
    : hexadecimal.join(":");
};

const canonicalHostname = (input: string): string | undefined => {
  const candidate = input.replace(/\.+$/u, "");
  try {
    const suffix = ".canonical-target.invalid";
    const parsed = new URL(`http://${candidate}${suffix}/`);
    const converted = parsed.hostname.replace(/\.$/u, "").toLocaleLowerCase("en-US");
    if (parsed.username || parsed.password || parsed.port || !converted.endsWith(suffix)) return undefined;
    const hostname = converted.slice(0, -suffix.length);
    if (hostname.length > 253 || !hostname.includes(".")) return undefined;
    return hostname.split(".").every((label) =>
      label.length > 0
      && label.length <= 63
      && !label.startsWith("-")
      && !label.endsWith("-")
      && /^[a-z0-9-]+$/u.test(label))
      ? hostname
      : undefined;
  } catch {
    return undefined;
  }
};

/** Non-contacting validation and canonicalization for one exact hostname or IP. */
export const prepareInternalHostTarget = (input: string): PrepareInternalHostResult => {
  const target = input.trim();
  if (!target) return { ok: false, error: "empty_target" };
  if (target.includes("@")) return { ok: false, error: "credentials_not_allowed" };
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(target)) return { ok: false, error: "url_not_allowed" };
  if (target.includes("/")) {
    return /^.+\/[0-9]{1,3}$/u.test(target)
      ? { ok: false, error: "cidr_not_allowed" }
      : { ok: false, error: "url_not_allowed" };
  }
  if (/[?#\\\[\]*\s\0\r\n]/u.test(target) || target.includes("%")) {
    return { ok: false, error: "invalid_target" };
  }
  const ipv4 = parseIpv4(target);
  if (ipv4) return { ok: true, value: ipv4.join(".") };
  const ipv6 = parseIpv6(target);
  if (ipv6) return { ok: true, value: canonicalIpv6(ipv6) };
  if (target.includes(":")) return { ok: false, error: "service_coordinate_not_allowed" };
  const hostname = canonicalHostname(target);
  return hostname
    ? { ok: true, value: hostname }
    : { ok: false, error: "invalid_target" };
};

/** Blank means the reviewed defaults. Custom ports are normalized to a sorted unique list. */
export const parseInternalHostPorts = (input: string): ParseInternalHostPortsResult => {
  const value = input.trim();
  if (!value) return { ok: true, value: [...INTERNAL_HOST_DEFAULT_PORTS] };
  const entries = value.split(",").map((entry) => entry.trim());
  if (entries.some((entry) => !/^(?:[1-9][0-9]{0,4})$/u.test(entry))) {
    return { ok: false, error: "invalid_ports" };
  }
  const ports = entries.map(Number);
  if (ports.some((port) => port > 65_535)) return { ok: false, error: "port_out_of_range" };
  const unique = [...new Set(ports)].sort((left, right) => left - right);
  if (unique.length > 64) return { ok: false, error: "too_many_ports" };
  return { ok: true, value: unique };
};
