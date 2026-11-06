import type { ExternalScopeRequest, ModelEndpointInput } from "./types";

export const garakProbeIds = ["dan.Dan_11_0", "dan.Dan_10_0", "dan.Dan_9_0", "ansiescape.AnsiEscaped"];
export const garakSourceRevision = "7aa740fe7412cc9bc33cdc39ca211843223cd3e1";

export const validatedModelEndpoint = (endpoint: string, model: string): ModelEndpointInput | undefined => {
  endpoint = endpoint.trim(); model = model.trim();
  if (endpoint.length > 512 || /[^\x21-\x7e]|[\\?#%]/u.test(endpoint)
    || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u.test(model)) return undefined;
  const path = endpoint.startsWith("https://") ? endpoint.slice(8).split("/").slice(1) : [];
  if (!path.length || path.some((part) => ["", ".", ".."].includes(part))) return undefined;
  try {
    const url = new URL(endpoint);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.port === "0") return undefined;
    return { endpoint: url.href, model };
  } catch { return undefined; }
};

export const modelEndpointScope = (input: ModelEndpointInput, privateNetwork: boolean, confirmation: string): ExternalScopeRequest => {
  const url = new URL(input.endpoint);
  return {
    target: url.hostname.replace(/^\[|\]$/gu, ""), ports: [Number(url.port || 443)], protocol: "https", activity: "active_external",
    ratePolicy: { requestsPerSecond: 1, concurrency: 1, timeoutSeconds: 20 },
    templatePolicy: {
      revision: garakSourceRevision, profileId: "garak_https_v1", allowedTemplateIds: [],
      allowHeadless: false, allowOutOfBand: false, allowFuzzing: false, allowFileUpload: false,
      allowDenialOfService: false, allowCredentialAttacks: false,
    },
    assertedAuthority: confirmation, allowSensitiveNetworks: privateNetwork,
  };
};
