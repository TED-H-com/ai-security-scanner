#!/usr/bin/env node

import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CANONICAL_SKILL = "skills/ai-security-scanner";
export const HOST_SKILLS = Object.freeze([
  ".claude/skills/ai-security-scanner",
  ".codex/skills/ai-security-scanner",
]);

async function regularFiles(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, "en"))) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await regularFiles(resolve(directory, entry.name), name));
    else if (entry.isFile()) files.push(name);
    else throw new Error(`Skill sources and copies must use regular files: ${name}`);
  }
  return files;
}

async function rejectSymlinkParents(root, path) {
  const parts = relative(root, path).split(sep);
  let current = root;
  for (const part of parts) {
    current = resolve(current, part);
    try {
      if ((await lstat(current)).isSymbolicLink()) throw new Error(`Refusing a skill symlink: ${current}`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

// Resolve repository links from each generated location. Internal skill links
// still point within the copied skill, so each host gets regular portable files.
export function renderSkillMarkdown(source, sourceFile, destinationFile, sourceRoot, destinationRoot) {
  return source.replace(/(\]\()([^\s)]+)(\))/gu, (match, before, href, after) => {
    if (/^(?:[a-z][a-z\d+.-]*:|\/|#)/iu.test(href)) return match;
    const [pathname, fragment = ""] = href.split(/(?=#)/u);
    const resolved = resolve(dirname(sourceFile), pathname);
    const withinSkill = relative(sourceRoot, resolved);
    const target = withinSkill !== ".." && !withinSkill.startsWith(`..${sep}`)
      ? resolve(destinationRoot, withinSkill)
      : resolved;
    const rebased = relative(dirname(destinationFile), target).split(sep).join("/");
    return `${before}${rebased}${fragment}${after}`;
  });
}

export async function syncSkills({ repositoryRoot, check = true }) {
  const root = resolve(repositoryRoot);
  const sourceRoot = resolve(root, CANONICAL_SKILL);
  await rejectSymlinkParents(root, sourceRoot);
  const files = await regularFiles(sourceRoot);
  if (!files.includes("SKILL.md")) throw new Error("Canonical SKILL.md is missing.");
  const differences = [];
  const writes = [];
  for (const host of HOST_SKILLS) {
    const destinationRoot = resolve(root, host);
    await rejectSymlinkParents(root, destinationRoot);
    let existing = [];
    try { existing = await regularFiles(destinationRoot); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    const extras = existing.filter((name) => !files.includes(name));
    if (extras.length) throw new Error(`Unexpected host skill files; review before removing: ${extras.map((name) => `${host}/${name}`).join(", ")}`);
    for (const name of files) {
      const sourceFile = resolve(sourceRoot, name);
      const destinationFile = resolve(destinationRoot, name);
      await rejectSymlinkParents(root, destinationFile);
      let expected = await readFile(sourceFile);
      if (name.endsWith(".md")) expected = Buffer.from(renderSkillMarkdown(
        expected.toString("utf8"), sourceFile, destinationFile, sourceRoot, destinationRoot,
      ));
      let actual;
      try { actual = await readFile(destinationFile); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      if (!actual?.equals(expected)) {
        differences.push(`${host}/${name}`);
        writes.push({ destinationFile, expected });
      }
    }
  }
  if (!check) {
    for (const { destinationFile, expected } of writes) {
      await mkdir(dirname(destinationFile), { recursive: true });
      await writeFile(destinationFile, expected);
    }
  }
  return { checked_files: files.length * HOST_SKILLS.length, differences };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1 || !["--check", "--write"].includes(args[0])) {
      throw new Error("Usage: node scripts/skill/sync-skill.mjs --check|--write");
    }
    const check = args[0] === "--check";
    const result = await syncSkills({ repositoryRoot: fileURLToPath(new URL("../../", import.meta.url)), check });
    process.stdout.write(`${JSON.stringify({ mode: check ? "check" : "write", ...result })}\n`);
    if (check && result.differences.length) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
