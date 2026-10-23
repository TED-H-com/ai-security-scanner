import type { TransportProtocol } from "./types";

export const websiteQuickProfile = {
  templateRevision: "nuclei-templates@f938a3dd530c283e9387b518b97911152ff5846c",
  profileId: "nuclei_web_safe_v1",
  engineIds: ["nuclei"],
  ratePolicy: {
    requestsPerSecond: 10,
    concurrency: 5,
    timeoutSeconds: 10,
  },
  allowedTemplateIds: [] as string[],
} as const;

export const websitePassiveProfile = {
  templateRevision: "zaproxy@2665d972f6d587ba4773a95053ac39af3fdf8df9",
  profileId: "zap_passive_v1",
  engineIds: ["zap"],
  ratePolicy: { requestsPerSecond: 5, concurrency: 5, timeoutSeconds: 10 },
  allowedTemplateIds: [] as string[],
} as const;

export const websiteQuickOrigin = (
  target: string,
  protocol: Extract<TransportProtocol, "http" | "https">,
  port: number,
): string => {
  const host = target.includes(":") && !target.startsWith("[") ? `[${target}]` : target;
  return `${protocol}://${host}:${port}`;
};
