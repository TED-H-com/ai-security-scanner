import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { CANONICAL_SKILL, HOST_SKILLS } from "../../scripts/skill/sync-skill.mjs";

const root = new URL("../../", import.meta.url);

test("Cloudflare host reference names implemented provider commands", async () => {
  const skill = await readFile(new URL(`${CANONICAL_SKILL}/SKILL.md`, root), "utf8");
  assert.match(skill, /\]\(references\/cloudflare-source-audit\.md\)/u);
  const reference = await readFile(new URL(`${CANONICAL_SKILL}/references/cloudflare-source-audit.md`, root), "utf8");
  const cli = await readFile(new URL("src-tauri/src/bin/cli.rs", root), "utf8");
  const commandEnum = cli.match(/enum CloudflareCommand \{([\s\S]*?)^\}/mu)?.[1];
  assert.ok(commandEnum, "CLI Cloudflare subcommand enum exists");
  const implemented = new Set([...commandEnum.matchAll(/^    ([A-Z][A-Za-z]+)\s*(?:\{|\()/gmu)]
    .map(([, variant]) => variant.replace(/([a-z])([A-Z])/gu, "$1-$2").toLowerCase()));
  const commands = [...reference.matchAll(/provider cloudflare ([a-z][a-z-]*)/gu)].map(([, name]) => name);
  assert.ok(commands.length > 0, "Reference includes concrete CLI commands");
  for (const command of commands) assert.ok(implemented.has(command), `Unknown Cloudflare command: ${command}`);
});

test("both hosts carry the reference with resolvable rebased links", async () => {
  for (const directory of [CANONICAL_SKILL, ...HOST_SKILLS]) {
    const url = new URL(`${directory}/references/cloudflare-source-audit.md`, root);
    const content = await readFile(url, "utf8");
    for (const [, href] of content.matchAll(/\]\(([^\s)]+)\)/gu)) {
      if (/^(?:[a-z][a-z\d+.-]*:|\/|#)/iu.test(href)) continue;
      await assert.doesNotReject(access(new URL(href.split("#")[0], url)), `${directory}: ${href}`);
    }
  }
});
