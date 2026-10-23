import assert from "node:assert/strict";
import test from "node:test";
import { incidentFocusCopy, incidentFocusProfile, incidentIssueGuidance, selectIncidentFocusEngines, type IncidentIssueCoverage } from "../../src/incidentFocusProfile.ts";

test("incident selection only narrows existing applicable engine routes", () => {
  assert.deepEqual(selectIncidentFocusEngines(["semgrep", "trivy", "gitleaks", "trivy"]), ["trivy"]);
  assert.deepEqual(selectIncidentFocusEngines(["nuclei", "greenbone"]), []);
  assert.deepEqual(selectIncidentFocusEngines(["naabu", "strix", "openscap"]), []);
  assert.deepEqual(selectIncidentFocusEngines([]), []);
  assert.deepEqual(incidentFocusProfile.engine_ids, ["trivy"]);
});

test("campaign distinguishes published advisories from incident investigations and pending candidates", () => {
  assert.equal(incidentFocusProfile.issues.length, 17);
  const pending = incidentFocusProfile.issues.filter((issue) => issue.kind === "advisory_pending");
  assert.equal(pending.length, 6);
  for (const issue of pending) {
    assert.deepEqual(issue.advisory_ids, []);
    assert.deepEqual(issue.engine_ids, []);
    assert.equal(issue.mechanism_verified, issue.vendor === "Linux");
    assert.equal(issue.fixed_releases, undefined);
  }
  assert.equal(incidentFocusProfile.issues.find((issue) => issue.id === "zdi-can-32005")?.vendor, "ConnMan");
  for (const issue of incidentFocusProfile.issues) {
    assert.ok(issue.sources.length > 0);
    assert.ok(issue.sources.every((url) => new URL(url).protocol === "https:"));
  }
});

test("all supported locales explain incident coverage without a clean verdict", () => {
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    for (const value of Object.values(incidentFocusCopy[locale])) assert.ok(value.length > 0);
    assert.equal("clean" in incidentFocusCopy[locale], false);
  }
});

test("Traditional Chinese guidance covers every incident and reason without changing saved evidence", () => {
  for (const entry of incidentFocusProfile.issues) {
    const codes = entry.kind === "vulnerability"
      ? Object.keys(incidentFocusProfile.reason_zh_tw) : [entry.kind];
    for (const reason_code of codes) {
      const row: IncidentIssueCoverage = { issue_id: entry.id, title: entry.title,
        asset_id: null, status: "not_tested", finding_ids: [], reason_code,
        reason: "Saved English reason", next_action: entry.next_action, sources: entry.sources };
      const before = JSON.stringify(row);
      const translated = incidentIssueGuidance(row, "zh-TW");
      assert.match(translated.reason, /[\u3400-\u9fff]/u);
      assert.match(translated.nextAction, /[\u3400-\u9fff]/u);
      assert.deepEqual(incidentIssueGuidance(row, "en"), { reason: row.reason, nextAction: row.next_action });
      assert.equal(JSON.stringify(row), before);
    }
  }
  const unknown = { issue_id: "future-incident", reason_code: "future-reason",
    reason: "Retained context", next_action: "Retained action" } as IncidentIssueCoverage;
  assert.deepEqual(incidentIssueGuidance(unknown, "zh-TW"), {
    reason: unknown.reason, nextAction: unknown.next_action,
  });
});


test("new upstream evidence does not turn pending candidates into detector or release claims", () => {
  const php = incidentFocusProfile.issues.find((issue) => issue.id === "php2shell");
  assert.deepEqual(php?.verified_upstream_fixture?.matched_advisory_ids,
    ["CVE-2026-109618", "CVE-2026-109619"]);
  const ksmbd = incidentFocusProfile.issues.find((issue) => issue.id === "zdi-can-33774");
  assert.equal(ksmbd?.kind, "advisory_pending");
  assert.equal(ksmbd?.maintainer_patch_reference?.status,
    "maintainer_reported_fix_not_distribution_release");
  assert.deepEqual(ksmbd?.advisory_ids, []);
  assert.equal(incidentFocusProfile.upstream_review.nuclei_php_template,
    "intrusive_crash_probe_excluded");
});
