#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const git = (directory, ...args) =>
  execFileSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

export function collectUpstreams(root) {
  const upstreamRoot = join(root, ".upstreams");
  const repositories = [];
  const candidates = [];

  for (const owner of readdirSync(upstreamRoot).sort()) {
    const ownerPath = join(upstreamRoot, owner);
    if (!statSync(ownerPath).isDirectory()) continue;
    // Some research checkouts (for example QEMU) live directly under .upstreams.
    // Never mistake their source directories for separate Git repositories.
    if (existsSync(join(ownerPath, ".git"))) {
      candidates.push(ownerPath);
      continue;
    }

    for (const repository of readdirSync(ownerPath).sort()) {
      const repositoryPath = join(ownerPath, repository);
      if (statSync(repositoryPath).isDirectory() && existsSync(join(repositoryPath, ".git"))) {
        candidates.push(repositoryPath);
      }
    }
  }

  for (const repositoryPath of candidates) {
    try {
      if (resolve(git(repositoryPath, "rev-parse", "--show-toplevel")) !== resolve(repositoryPath)) {
        throw new Error("checkout path is not its Git worktree root");
      }
      const remote = git(repositoryPath, "remote", "get-url", "origin")
        .replace(/\.git$/, "")
        .replace(/^git@github\.com:/, "https://github.com/");
      repositories.push({
        id: relative(upstreamRoot, repositoryPath),
        path: relative(root, repositoryPath),
        remote,
        branch: git(repositoryPath, "branch", "--show-current"),
        revision: git(repositoryPath, "rev-parse", "HEAD"),
        shallow: git(repositoryPath, "rev-parse", "--is-shallow-repository") === "true",
      });
    } catch (error) {
      throw new Error(`Could not inspect ${repositoryPath}: ${error.message}`);
    }
  }
  return repositories;
}

export function writeLock(root) {
  const outputPath = join(root, "engines", "upstreams.lock.json");
  const repositories = collectUpstreams(root);
  const lock = {
    schema_version: "1.0.0",
    generated_by: "scripts/lock-upstreams.mjs",
    note: "Research/source checkout lock only. Engine release manifests independently pin tested tags, images, rule databases, and adapters.",
    repositories,
  };

  writeFileSync(outputPath, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
  return { repositories, outputPath };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { repositories, outputPath } = writeLock(resolve(import.meta.dirname, ".."));
  console.log(`Locked ${repositories.length} upstream repositories in ${outputPath}`);
}
