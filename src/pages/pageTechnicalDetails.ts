const maximumCharacters = 4_096;
const maximumInputCharacters = maximumCharacters * 4;

/**
 * Bounds and defensively redacts backend-provided text before it is shown in
 * an opt-in technical disclosure. This does not modify stored case evidence.
 */
import { maskSecrets } from "../technicalDetails.ts";

export const displayTechnicalDetail = (value: unknown): string | undefined => {
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
