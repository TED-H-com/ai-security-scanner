import { copyFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { PROJECT_ROOT, readJson, writeJsonAtomic } from "./lib.mjs";

export async function incidentScanPackForRelease(version, commit) {
  const manifest = await readJson(path.join(PROJECT_ROOT, "docs/incident-pack.json"));
  if (manifest.app_version !== version) return null;
  const campaignBytes = await readFile(path.join(PROJECT_ROOT, manifest.campaign_path));
  return {
    ...manifest,
    source_commit: commit,
    campaign_sha256: createHash("sha256").update(campaignBytes).digest("hex"),
    campaign: JSON.parse(campaignBytes),
  };
}

export async function writeIncidentScanPack(output, version, commit) {
  const pack = await incidentScanPackForRelease(version, commit);
  if (!pack) return;
  await writeJsonAtomic(path.join(output, "incident-scan-pack.json"), pack);
  await copyFile(path.join(PROJECT_ROOT, `docs/release/v${version}.md`), path.join(output, "INCIDENT_SCAN_PACK.md"));
}
