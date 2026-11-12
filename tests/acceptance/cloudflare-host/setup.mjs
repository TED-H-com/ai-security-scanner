#!/usr/bin/env node
// Test tooling only: the synthetic owner authorizes only the copied fixture.
import { execFileSync } from "node:child_process";
import { chmod, copyFile, lstat, mkdir, readdir, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const fixture = fileURLToPath(new URL("fixture/", import.meta.url));

export async function prepareOutputDirectory(output) {
  if (!isAbsolute(output) || resolve(output) !== output) {
    throw new Error("--output must be a canonical absolute directory path");
  }
  // Its parent must exist: this helper never creates anything outside output.
  if (await realpath(dirname(output)) !== dirname(output)) {
    throw new Error("--output must use canonical parents; resolve links first");
  }
  let info;
  try { info = await lstat(output); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  if (info) {
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(output) !== output) {
      throw new Error("--output must be a real canonical directory");
    }
    if ((await readdir(output)).length) throw new Error("--output must not exist or must be empty");
  } else {
    await mkdir(output, { mode: 0o700 });
  }
  await chmod(output, 0o700);
  return output;
}

export async function setup({ cli, output, hostId = "unknown" }) {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(hostId)) {
    throw new Error("--host-id must be 1-128 ASCII letters, digits, underscores or hyphens");
  }
  const root = await prepareOutputDirectory(output);
  const cliPath = await realpath(resolve(cli));
  if (!(await lstat(cliPath)).isFile()) throw new Error("--cli must name a CLI executable file");
  const dataDirectory = join(root, "data");
  const runDirectory = join(root, "run");
  const sourceDirectory = join(root, "source");
  const processDirectory = join(root, "process");
  for (const directory of [dataDirectory, runDirectory, sourceDirectory, processDirectory]) {
    await mkdir(directory, { mode: 0o700 });
  }
  for (const entry of await readdir(fixture, { withFileTypes: true })) {
    if (!entry.isFile()) throw new Error(`Fixture member is not a regular file: ${entry.name}`);
    await copyFile(join(fixture, entry.name), join(sourceDirectory, entry.name));
  }
  const environment = {
    PATH: process.env.PATH ?? "",
    HOME: processDirectory,
    USERPROFILE: processDirectory,
    TMPDIR: processDirectory,
    TMP: processDirectory,
    TEMP: processDirectory,
    XDG_CACHE_HOME: processDirectory,
    XDG_CONFIG_HOME: processDirectory,
    XDG_DATA_HOME: processDirectory,
  };
  for (const name of ["SystemRoot", "WINDIR", "SYSTEMROOT"]) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  function command(...args) {
    let stdout;
    try {
      stdout = execFileSync(cliPath, ["--data-dir", dataDirectory, "--json", ...args], {
        cwd: root, env: environment, encoding: "utf8", timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      // Surface the CLI's own JSON outcome (for example a refused data-directory location).
      const detail = `${error.stdout ?? ""}${error.stderr ?? ""}`.trim().slice(0, 2000);
      throw new Error(`CLI ${args.slice(0, 3).join(" ")} failed${detail ? `: ${detail}` : ""}`);
    }
    return JSON.parse(stdout);
  }
  const created = command("case", "create", "--title", "Synthetic Cloudflare host acceptance");
  const caseId = created.id;
  if (typeof caseId !== "string" || !caseId) throw new Error("Case creation returned no case ID");
  const attached = command("source", "attach-workspace", "--case-id", caseId,
    "--label", "Synthetic voucher desk", "--path", sourceDirectory,
    "--profile", "repository-working-tree");
  const assetId = attached.asset_id;
  if (typeof assetId !== "string" || !assetId || typeof attached.snapshot_sha256 !== "string") {
    throw new Error("Workspace attachment returned no asset/snapshot binding");
  }
  const confirmer = "synthetic acceptance operator";
  command("scope", "approve", "--case-id", caseId, "--asset-id", assetId,
    "--permission", "local-artifact-read", "--confirmed-by", confirmer);
  const sourceViewRequestId = "synthetic-source-view";
  // The acknowledgement binds the declared host; `prepare` must declare the same ID.
  const prepared = command("provider", "cloudflare", "prepare-source-view",
    "--case-id", caseId, "--asset-id", assetId,
    "--expected-snapshot-sha256", attached.snapshot_sha256, "--scope-path", ".",
    "--request-id", sourceViewRequestId, "--acknowledge-model-processing",
    "--confirmed-by", confirmer, "--host-id", hostId);
  const status = command("provider", "cloudflare", "source-view-status",
    "--case-id", caseId, "--request-id", sourceViewRequestId);
  const receipt = status.result?.receipt;
  if (prepared.result?.status !== "ready" || receipt?.result?.status !== "ready"
      || receipt.case_id !== caseId || receipt.asset_id !== assetId
      || receipt.request_id !== sourceViewRequestId || receipt.digest !== prepared.receipt?.sha256) {
    throw new Error("Source-view status did not return the matching ready receipt");
  }
  const treePath = await realpath(prepared.result.view.path);
  const treeRelative = relative(dataDirectory, treePath);
  if (!treeRelative || treeRelative === ".." || treeRelative.startsWith(`..${sep}`)
      || isAbsolute(treeRelative) || basename(treePath) !== "tree") {
    throw new Error("Ready source tree is outside the throwaway data directory");
  }
  const context = {
    cli_path: cliPath,
    data_directory: dataDirectory,
    case_id: caseId,
    asset_id: assetId,
    source_view_request_id: sourceViewRequestId,
    declared_host_id: hostId,
    ready_receipt: receipt,
    tree_path: treePath,
    run_directory: runDirectory,
  };
  // Completion marker: no context file exists until every public CLI step passed.
  await writeFile(join(root, "host-context.json"), `${JSON.stringify(context, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  return context;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    const options = {};
    const names = { "--cli": "cli", "--output": "output", "--host-id": "hostId" };
    for (let i = 0; i < args.length; i += 2) {
      const name = names[args[i]];
      if (!name || !args[i + 1] || options[name]) {
        throw new Error("Usage: node setup.mjs --cli PATH --output DIR [--host-id ID]");
      }
      options[name] = args[i + 1];
    }
    if (!options.cli || !options.output) throw new Error("Both --cli and --output are required");
    await setup(options);
    process.stdout.write(`${join(options.output, "host-context.json")}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
