"use strict";
// Product transport only. Detector/schema semantics remain in the pinned modules.
const findings = require("./upstream/skills/security-audit/validate-findings.cjs");
const ledger = require("./upstream/skills/security-audit/validate-coverage-ledger.cjs");
const schema = require("./upstream/skills/security-audit/report-schema.json");
const { TextDecoder } = require("node:util");
const LIMITS = findings.LIMITS;
const JsonStructureError = Error;

// Verbatim upstream findings CLI preflight (MIT, see upstream/LICENSE).
// Upstream does not export it; the parity test holds this copy byte-for-byte.
function enforceJsonTextLimits(contents) {
  const containers = [];
  let inString = false;
  let escaped = false;

  function markArrayItem() {
    const container = containers[containers.length - 1];
    if (!container || container.type !== "array" || !container.expectsItem) return;
    container.expectsItem = false;
    container.items++;
    if (container.items > LIMITS.arrayItems) {
      throw new JsonStructureError(`input exceeds ${LIMITS.arrayItems} item array limit`);
    }
  }

  for (let index = 0; index < contents.length; index++) {
    const character = contents[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        inString = false;
      }
      continue;
    }

    if (character === "\"") {
      markArrayItem();
      inString = true;
    } else if (character === "[" || character === "{") {
      markArrayItem();
      if (containers.length >= LIMITS.nestingDepth) {
        throw new JsonStructureError(`input exceeds ${LIMITS.nestingDepth} level nesting depth limit`);
      }
      containers.push({
        type: character === "[" ? "array" : "object",
        expectsItem: character === "[",
        items: 0,
      });
    } else if (character === "]" || character === "}") {
      containers.pop();
    } else if (character === ",") {
      const container = containers[containers.length - 1];
      if (container && container.type === "array") container.expectsItem = true;
    } else if (!/\s/.test(character)) {
      markArrayItem();
    }
  }
}


// Supplemental product input rule: JSON.parse must not silently discard keys.
// Run only after the upstream depth/collection preflight and before parsing.
function rejectDuplicateKeys(text) {
  const containers = [];
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (character === "{") containers.push(new Set());
    else if (character === "[") containers.push(null);
    else if (character === "}" || character === "]") containers.pop();
    else if (character === '"') {
      const start = index;
      while (++index < text.length) {
        if (text[index] === "\\") index++;
        else if (text[index] === '"') break;
      }
      let next = index + 1;
      while (/^[ \t\n\r]$/.test(text[next] ?? "")) next++;
      if (text[next] === ":") {
        const keys = containers[containers.length - 1];
        const key = JSON.parse(text.slice(start, index + 1));
        if (keys?.has(key)) throw new Error("duplicate JSON object key");
        keys?.add(key);
      }
    }
  }
}

function diagnostic(message) {
  return String(message).slice(0, 2048).replace(
    /[\p{Cc}\p{Cf}\p{Mn}\p{Me}]/gu,
    (character) => `\\u{${character.codePointAt(0).toString(16)}}`,
  ).slice(0, 2048);
}

function validateBytes(document, bytes) {
  if (document !== "findings" && document !== "coverage-ledger") {
    throw new Error("unsupported document kind");
  }
  let phase = "input";
  try {
    if (bytes.length > LIMITS.inputBytes) throw new Error("input exceeds 5242880 byte limit");
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { throw new Error("input is not valid UTF-8"); }
    phase = "preflight";
    if (document === "findings") enforceJsonTextLimits(text);
    else ledger.preflightJsonText(text);
    rejectDuplicateKeys(text);
    phase = "parse";
    let value;
    try { value = JSON.parse(text); }
    catch { throw new Error("invalid JSON syntax"); }
    phase = "upstream";
    const errors = document === "findings"
      ? findings.validateDocument(value, schema) : ledger.validateDocument(value);
    return { valid: errors.length === 0, phase, errors: errors.map(diagnostic) };
  } catch (error) {
    // Parser/validator exceptions must not echo payloads from the input.
    const message = phase === "upstream" ? "upstream validator could not complete"
      : phase === "preflight" && error instanceof SyntaxError ? "invalid JSON syntax" : error.message;
    return { valid: false, phase, errors: [diagnostic(message)] };
  }
}

async function run() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > LIMITS.inputBytes) {
      process.stdout.write(JSON.stringify({ valid: false, phase: "input", errors: ["input exceeds 5242880 byte limit"] }));
      process.exitCode = 0;
      process.stdin.destroy();
      return;
    }
    chunks.push(chunk);
  }
  process.stdout.write(JSON.stringify(validateBytes(process.argv[2], Buffer.concat(chunks, length))));
}

module.exports = { validateBytes };
if (require.main === module) run().catch(() => {
  process.stderr.write("validator transport failed\n");
  process.exitCode = 1;
});
