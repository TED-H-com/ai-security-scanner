import assert from "node:assert/strict";
import test from "node:test";

import type {
  BeginnerReportFinding,
  BeginnerReportProblemGroup,
  DiffState,
  FindingDiffReasonCode,
  Severity,
  VerificationDiff,
} from "../../src/types.ts";
import { compareProblems, type VerificationProblemReport } from "../../src/verificationProblems.ts";

const finding = (id: string, severity: Severity = "low"): BeginnerReportFinding => ({
  findingId: id,
  severity,
  targetAssetIds: ["asset-1"],
  priority: 10,
} as BeginnerReportFinding);

const group = (
  groupId: string,
  findingIds: string[],
  kind: BeginnerReportProblemGroup["kind"] = "iam_password_policy",
  representativeFindingId = findingIds[0] ?? "",
): BeginnerReportProblemGroup => ({
  groupId,
  ruleVersion: "aws-related-checks-1",
  kind,
  title: "IAM password policy needs attention",
  targetAssetId: "asset-1",
  representativeFindingId,
  findingIds,
  ...(kind === "iam_policy_permissions" ? { policyName: "Policy 1" } : {}),
});

const report = (
  findings: readonly BeginnerReportFinding[],
  groups: readonly BeginnerReportProblemGroup[],
): VerificationProblemReport => ({
  findings,
  problemGroups: groups,
});

const diff = (overrides: Partial<VerificationDiff> & Pick<VerificationDiff, "id" | "state">): VerificationDiff => ({
  title: overrides.id,
  assetName: "account",
  explanation: `${overrides.id} compared`,
  evidenceChanged: false,
  ...overrides,
});

const reason = (code: FindingDiffReasonCode, detail = code) => ({ code, detail });

const count = (problems: readonly { state: DiffState }[], state: DiffState) =>
  problems.filter((problem) => problem.state === state).length;

test("a resolved group stays one card beside ungrouped resolved and new problems", () => {
  const baseline = report(
    [finding("low", "low"), finding("high", "critical"), finding("solo", "medium")],
    [group("password", ["low", "high"], "iam_password_policy", "low")],
  );
  const problems = compareProblems([
    diff({
      id: "low",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "low",
      beforeSeverity: "low",
      title: "Minimum length",
    }),
    diff({
      id: "high",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "high",
      beforeSeverity: "critical",
      title: "Reuse",
    }),
    diff({
      id: "solo",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "solo",
      beforeSeverity: "medium",
    }),
    diff({
      id: "fresh",
      state: "new",
      comparisonStatus: "newly_observed",
      currentFindingId: "fresh",
      afterSeverity: "high",
    }),
  ], baseline);

  assert.equal(problems.length, 3);
  assert.equal(count(problems, "resolved"), 2);
  assert.equal(count(problems, "new"), 1);
  assert.equal(count(problems, "persistent"), 0);
  assert.equal(count(problems, "unverifiable"), 0);

  const grouped = problems[0];
  assert.equal(grouped?.id, "low");
  assert.equal(grouped?.state, "resolved");
  assert.equal(grouped?.moved, false);
  assert.deepEqual(grouped?.members.map((member) => member.id), ["low", "high"]);
  assert.equal(grouped?.group?.groupId, "password");
  assert.equal(grouped?.group?.kind, "iam_password_policy");
  assert.equal(grouped?.lead.id, "high");
  assert.equal(grouped?.displaysBaseline, true);
  assert.equal(grouped?.beforeSeverity, "critical");
  assert.equal(grouped?.afterSeverity, undefined);
  assert.equal(problems[1]?.id, "solo");
  assert.equal(problems[1]?.group, undefined);
  assert.equal(problems[2]?.state, "new");
  assert.equal(problems[2]?.afterSeverity, "high");
});

test("one resolved member and one still present stays one persistent problem", () => {
  const baseline = report(
    [finding("gone", "low"), finding("still", "high")],
    [group("password", ["gone", "still"])],
  );
  const problems = compareProblems([
    diff({
      id: "gone",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "gone",
      beforeSeverity: "low",
    }),
    diff({
      id: "still",
      state: "persistent",
      comparisonStatus: "still_present",
      baselineFindingId: "still",
      currentFindingId: "still",
      beforeSeverity: "high",
      afterSeverity: "medium",
    }),
  ], baseline);

  assert.equal(problems.length, 1);
  assert.equal(problems[0]?.state, "persistent");
  assert.equal(problems[0]?.moved, false);
  assert.deepEqual(problems[0]?.members.map((member) => member.id), ["gone", "still"]);
  assert.equal(problems[0]?.group, undefined);
  assert.equal(problems[0]?.displaysBaseline, false);
  // The card is still present, so it is named after the finding seen again, not the one fixed.
  assert.equal(problems[0]?.lead.id, "still");
  assert.equal(problems[0]?.beforeSeverity, "high");
  assert.equal(problems[0]?.afterSeverity, "medium");
});

test("a persistent problem is moved only when every observed member moved", () => {
  const baseline = report(
    [finding("left", "high"), finding("right", "medium")],
    [group("root", ["left", "right"], "root_account_usage")],
  );
  const current = report(
    [finding("left", "high"), finding("right", "medium")],
    [group("root", ["left", "right"], "root_account_usage")],
  );
  const pair = (leftMoved: boolean, rightMoved: boolean) => compareProblems([
    diff({
      id: "left",
      state: "persistent",
      comparisonStatus: "still_present",
      baselineFindingId: "left",
      currentFindingId: "left",
      changeReasons: leftMoved ? [reason("location_moved"), reason("severity_changed")] : [reason("severity_changed")],
    }),
    diff({
      id: "right",
      state: "persistent",
      comparisonStatus: "changed",
      baselineFindingId: "right",
      currentFindingId: "right",
      changeReasons: rightMoved ? [reason("location_moved", "location moved within the same file")] : [reason("evidence_changed")],
    }),
  ], baseline, current);

  const mixed = pair(true, false);
  assert.equal(mixed.length, 1);
  assert.equal(mixed[0]?.state, "persistent");
  assert.equal(mixed[0]?.moved, false);

  const moved = pair(true, true);
  assert.equal(moved.length, 1);
  assert.equal(moved[0]?.state, "persistent");
  assert.equal(moved[0]?.moved, true);
  assert.equal(moved[0]?.group?.kind, "root_account_usage");
});

test("one resolved member and one unverifiable member stays unverifiable", () => {
  const baseline = report(
    [finding("gone"), finding("unsure")],
    [group("password", ["gone", "unsure"])],
  );
  const problems = compareProblems([
    diff({ id: "gone", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "gone" }),
    diff({
      id: "unsure",
      state: "unverifiable",
      comparisonStatus: "unable_to_verify",
      baselineFindingId: "unsure",
    }),
  ], baseline);

  assert.equal(problems.length, 1);
  assert.equal(problems[0]?.state, "unverifiable");
  assert.equal(problems[0]?.moved, false);
});

test("native status priority keeps a still-present member ahead of an unverifiable one", () => {
  const baseline = report(
    [finding("still"), finding("unsure"), finding("fresh"), finding("gone")],
    [
      group("observed", ["still", "unsure"]),
      group("mixed-new", ["fresh", "gone"]),
    ],
  );
  const problems = compareProblems([
    diff({
      id: "still",
      state: "persistent",
      comparisonStatus: "still_present",
      baselineFindingId: "still",
      currentFindingId: "still",
    }),
    diff({
      id: "unsure",
      state: "unverifiable",
      comparisonStatus: "unable_to_verify",
      baselineFindingId: "unsure",
    }),
    diff({
      id: "fresh",
      state: "new",
      comparisonStatus: "newly_observed",
      baselineFindingId: "fresh",
      currentFindingId: "fresh",
    }),
    diff({
      id: "gone",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "gone",
    }),
  ], baseline);

  assert.equal(problems.length, 2);
  assert.equal(problems[0]?.state, "persistent");
  assert.equal(problems[1]?.state, "unverifiable");
});

test("no reports leave one problem per diff in diff order", () => {
  const diffs = [
    diff({ id: "1", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "a" }),
    diff({ id: "2", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "b" }),
    diff({ id: "3", state: "persistent", baselineFindingId: "c", currentFindingId: "c" }),
    diff({ id: "4", state: "new", currentFindingId: "d" }),
    diff({ id: "5", state: "unverifiable", comparisonStatus: "unable_to_verify", baselineFindingId: "e" }),
  ];
  const problems = compareProblems(diffs);

  assert.equal(problems.length, diffs.length);
  assert.deepEqual(problems.map((problem) => problem.id), diffs.map((item) => item.id));
  assert.deepEqual(problems.map((problem) => problem.state), diffs.map((item) => item.state));
  assert.deepEqual(problems.map((problem) => problem.members.length), [1, 1, 1, 1, 1]);
  assert.equal(count(problems, "resolved"), 2);
  assert.equal(count(problems, "persistent"), 1);
  assert.equal(count(problems, "new"), 1);
  assert.equal(count(problems, "unverifiable"), 1);

  const grouped = compareProblems(diffs.slice(0, 2), report(
    [finding("a"), finding("b")],
    [group("password", ["a", "b"])],
  ));
  assert.equal(grouped.length, 1);
  assert.equal(grouped[0]?.members.length, 2);
});

test("a baseline group stays one problem when the current report groups only one member", () => {
  const baseline = report(
    [finding("kept", "high"), finding("other", "medium")],
    [group("baseline-root", ["kept", "other"], "root_account_usage")],
  );
  const current = report(
    [finding("kept", "high"), finding("extra", "low"), finding("other", "medium")],
    [group("current-policy", ["kept", "extra"], "iam_policy_permissions", "extra")],
  );
  const problems = compareProblems([
    diff({
      id: "kept",
      state: "persistent",
      comparisonStatus: "still_present",
      baselineFindingId: "kept",
      currentFindingId: "kept",
      assetName: "kept-asset",
    }),
    diff({
      id: "other",
      state: "persistent",
      comparisonStatus: "still_present",
      baselineFindingId: "other",
      currentFindingId: "other",
      assetName: "other-asset",
    }),
  ], baseline, current);

  assert.equal(problems.length, 1);
  assert.equal(problems[0]?.state, "persistent");
  assert.deepEqual(problems[0]?.members.map((member) => member.id), ["kept", "other"]);
  assert.equal(problems[0]?.group?.groupId, "current-policy");
  assert.equal(problems[0]?.lead.id, "kept");
  assert.equal(problems[0]?.lead.assetName, "kept-asset");
});

test("problems are ordered by their first member diff", () => {
  const baseline = report(
    [finding("high", "critical"), finding("low", "low"), finding("solo", "medium")],
    [group("password", ["high", "low"], "iam_password_policy", "low")],
  );
  const problems = compareProblems([
    diff({ id: "new", state: "new", comparisonStatus: "newly_observed", currentFindingId: "new" }),
    diff({ id: "g-low", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "low" }),
    diff({ id: "solo", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "solo" }),
    diff({ id: "g-high", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "high", beforeSeverity: "critical" }),
  ], baseline);

  assert.deepEqual(problems.map((problem) => problem.id), ["new", "g-low", "solo"]);
  assert.deepEqual(problems[1]?.members.map((member) => member.id), ["g-low", "g-high"]);
  assert.equal(problems[1]?.lead.id, "g-high");
});

test("diffs that only meet through the other side stay one problem", () => {
  const baseline = report(
    [finding("c-low", "low"), finding("c-high", "critical"), finding("a-low", "low"), finding("a-high", "high")],
    [
      group("g-c", ["c-low", "c-high"], "iam_password_policy", "c-low"),
      group("g-a", ["a-low", "a-high"], "root_account_usage", "a-low"),
    ],
  );
  const current = report(
    [finding("a-high", "high"), finding("c-high", "critical")],
    [group("bridge", ["a-high", "c-high"], "iam_policy_permissions")],
  );
  const problems = compareProblems([
    diff({ id: "a-low", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "a-low" }),
    diff({ id: "c-low", state: "resolved", comparisonStatus: "resolved", baselineFindingId: "c-low" }),
    diff({
      id: "a-high",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "a-high",
      currentFindingId: "a-high",
    }),
    diff({
      id: "c-high",
      state: "resolved",
      comparisonStatus: "resolved",
      baselineFindingId: "c-high",
      currentFindingId: "c-high",
      beforeSeverity: "critical",
    }),
  ], baseline, current);

  assert.equal(problems.length, 1);
  assert.deepEqual(problems[0]?.members.map((member) => member.id), ["a-low", "c-low", "a-high", "c-high"]);
  assert.equal(problems[0]?.state, "resolved");
  assert.equal(problems[0]?.group?.groupId, "g-c");
  assert.equal(problems[0]?.lead.id, "c-high");
  assert.equal(problems[0]?.beforeSeverity, "critical");
});

test("an unverifiable problem with no current side displays from the baseline", () => {
  const baseline = report(
    [finding("first", "medium"), finding("second", "high")],
    [group("password", ["first", "second"], "iam_password_policy", "first")],
  );
  const problems = compareProblems([
    diff({ id: "first", state: "unverifiable", comparisonStatus: "unable_to_verify", baselineFindingId: "first", beforeSeverity: "medium" }),
    diff({ id: "second", state: "unverifiable", comparisonStatus: "unable_to_verify", baselineFindingId: "second", beforeSeverity: "high" }),
  ], baseline, report([], []));

  assert.equal(problems.length, 1);
  assert.equal(problems[0]?.state, "unverifiable");
  assert.equal(problems[0]?.displaysBaseline, true);
  assert.equal(problems[0]?.group?.groupId, "password");
  assert.equal(problems[0]?.lead.id, "second");
  assert.equal(problems[0]?.beforeSeverity, "high");
  assert.equal(problems[0]?.afterSeverity, undefined);
});
