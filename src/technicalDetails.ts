const maximumCharacters = 4_096;
const maximumInputCharacters = maximumCharacters * 4;
const secretAssignment = /\b(client[_ -]?secret|admin(?:istrator)?[_ -]?password|password|refresh[_ -]?token|access[_ -]?token|id[_ -]?token|session[_ -]?token|secret[_ -]?access[_ -]?key|code[_ -]?verifier|(?:x[_ -]?)?api[_ -]?key|private[_ -]?key)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu;
const sensitiveHeader = /(\b(?:authorization|proxy-authorization|x-api-key)\b\s*:\s*)[^\r\n]*/giu;
const bearerCredential = /\bbearer\s+[a-z0-9._~+/=-]+/giu;
const basicCredential = /\bbasic\s+[a-z0-9._~+/=-]+/giu;
const jwtCredential = /\b[a-z0-9_-]{16,}\.[a-z0-9_-]{16,}\.[a-z0-9_-]{8,}\b/giu;
const awsAccessKey = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu;
const privateKeyBlock = /-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-\r\n]*PRIVATE KEY-----|$)/giu;

/**
 * Creates a bounded, display-safe version of backend diagnostics for an
 * opt-in technical-details disclosure. It never changes stored evidence.
 */
export const maskSecrets = (value: string): string => {
  return value
    .replace(privateKeyBlock, "[REDACTED PRIVATE KEY]")
    .replace(sensitiveHeader, (_match, prefix: string) => `${prefix}[REDACTED]`)
    .replace(secretAssignment, (_match, name: string, separator: string) => `${name}${separator}[REDACTED]`)
    .replace(bearerCredential, "Bearer [REDACTED]")
    .replace(basicCredential, "Basic [REDACTED]")
    .replace(jwtCredential, "[REDACTED JWT]")
    .replace(awsAccessKey, "[REDACTED AWS ACCESS KEY]");
};

export const displaySafeTechnicalDetail = (value: unknown): string | undefined => {
  const raw = value instanceof Error
    ? value.message
    : typeof value === "string" || typeof value === "number"
      ? String(value)
      : undefined;
  if (!raw) return undefined;

  const boundedInput = Array.from(raw).slice(0, maximumInputCharacters).join("");
  const normalized = maskSecrets(
    boundedInput
      .replaceAll("\r\n", "\n")
      .replaceAll("\r", "\n")
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, " ")
  ).trim();
  if (!normalized) return undefined;

  const characters = Array.from(normalized);
  return characters.length <= maximumCharacters
    ? normalized
    : `${characters.slice(0, maximumCharacters).join("")}…`;
};
