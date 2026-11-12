import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { CANONICAL_SKILL, HOST_SKILLS, syncSkills } from "../../scripts/skill/sync-skill.mjs";

const CLAUDE_SKILL = new URL("../../.claude/skills/ai-security-scanner/SKILL.md", import.meta.url);
const CODEX_SKILL = new URL("../../.codex/skills/ai-security-scanner/SKILL.md", import.meta.url);

test("canonical scanner skill generates both host operating contracts and metadata", async () => {
  const result = await syncSkills({ repositoryRoot: fileURLToPath(new URL("../../", import.meta.url)) });
  assert.deepEqual(result.differences, [], "Run node scripts/skill/sync-skill.mjs --write after editing the canonical skill.");
  const [claude, codex] = await Promise.all([
    readFile(CLAUDE_SKILL, "utf8"),
    readFile(CODEX_SKILL, "utf8"),
  ]);

  assert.equal(
    claude,
    codex,
    "Both hosts must expose the same generated product contract.",
  );
});

test("canonical and generated skill instructions have resolvable local dependencies", async () => {
  for (const directory of [CANONICAL_SKILL, ...HOST_SKILLS]) {
    const url = new URL(`../../${directory}/SKILL.md`, import.meta.url);
    const content = await readFile(url, "utf8");
    for (const [, href] of content.matchAll(/\]\(([^\s)]+)\)/gu)) {
      if (/^(?:[a-z][a-z\d+.-]*:|\/|#)/iu.test(href)) continue;
      const dependency = new URL(href.split("#")[0], url);
      await assert.doesNotReject(access(dependency), `${directory}: missing ${href}`);
    }
  }
});
