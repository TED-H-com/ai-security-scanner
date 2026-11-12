import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const CLAUDE_SKILL = new URL("../../.claude/skills/ai-security-scanner/SKILL.md", import.meta.url);
const CODEX_SKILL = new URL("../../.codex/skills/ai-security-scanner/SKILL.md", import.meta.url);

test("Claude and Codex expose the same subordinate scanner operating contract", async () => {
  const [claude, codex] = await Promise.all([
    readFile(CLAUDE_SKILL, "utf8"),
    readFile(CODEX_SKILL, "utf8"),
  ]);

  assert.equal(
    claude,
    codex,
    "Update both required skill copies together; neither may drift into a competing product contract.",
  );
});
