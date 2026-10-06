import { projectProblemRows } from "./reportProblemPresentation.ts";
import type {
  BeginnerReportFinding,
  BeginnerReportProblemGroup,
  DiffState,
  FindingDiffStatus,
  Severity,
  VerificationDiff,
} from "./types.ts";

/** A report side the comparison can read. Only rendered problem cards count. */
export interface VerificationProblemReport {
  findings: readonly BeginnerReportFinding[];
  problemGroups?: readonly BeginnerReportProblemGroup[];
}

export interface VerificationProblem {
  /** Id of the earliest member diff. Problems stay in that order. */
  id: string;
  state: DiffState;
  moved: boolean;
  members: VerificationDiff[];
  lead: VerificationDiff;
  /** True when this problem displays from the before-fix report. */
  displaysBaseline: boolean;
  /** Group on the side this problem displays, when that side renders one. */
  group?: BeginnerReportProblemGroup;
  /** Highest baseline severity among members. */
  beforeSeverity?: Severity;
  /** Highest current severity among members. */
  afterSeverity?: Severity;
}

interface RenderedGroups {
  groupByFindingId: ReadonlyMap<string, BeginnerReportProblemGroup>;
  rowOrderByGroupId: ReadonlyMap<string, number>;
  representativeIdByGroupId: ReadonlyMap<string, string>;
}

// Same order `projectProblemRows` uses. A lower index is a higher severity.
const severityOrder: readonly Severity[] = ["critical", "high", "medium", "low", "unknown", "info"];

const sideFindingId = (diff: VerificationDiff, baseline: boolean): string | undefined => {
  const value = baseline ? diff.baselineFindingId : diff.currentFindingId;
  return value && value.length > 0 ? value : undefined;
};

/** Native status, or the mapped state when a stored diff did not keep one. */
const nativeStatus = (diff: VerificationDiff): FindingDiffStatus => {
  if (diff.comparisonStatus) return diff.comparisonStatus;
  switch (diff.state) {
    case "persistent": return "still_present";
    case "new": return "newly_observed";
    case "unverifiable": return "unable_to_verify";
    case "resolved": return "resolved";
  }
};

const problemState = (members: readonly VerificationDiff[]): DiffState => {
  const statuses = members.map(nativeStatus);
  if (statuses.some((status) => status === "still_present" || status === "changed")) return "persistent";
  if (statuses.some((status) => status === "unable_to_verify")) return "unverifiable";
  if (statuses.every((status) => status === "resolved")) return "resolved";
  if (statuses.every((status) => status === "newly_observed")) return "new";
  return "unverifiable";
};

const problemMoved = (state: DiffState, members: readonly VerificationDiff[]): boolean => {
  if (state !== "persistent") return false;
  const observed = members.filter((member) => {
    const status = nativeStatus(member);
    return status === "still_present" || status === "changed";
  });
  return observed.length > 0 && observed.every((member) =>
    member.changeReasons?.some((reason) => reason.code === "location_moved") === true);
};

const highestSeverity = (values: readonly (Severity | undefined)[]): Severity | undefined => {
  let best: Severity | undefined;
  let bestRank = Number.POSITIVE_INFINITY;
  for (const value of values) {
    if (!value) continue;
    const rank = severityOrder.indexOf(value);
    if (rank >= 0 && rank < bestRank) {
      best = value;
      bestRank = rank;
    }
  }
  return best;
};

const renderedGroups = (report: VerificationProblemReport | undefined): RenderedGroups | undefined => {
  if (!report) return undefined;
  const rows = projectProblemRows(report.findings, report.problemGroups ?? []);
  const groupByFindingId = new Map<string, BeginnerReportProblemGroup>();
  const rowOrderByGroupId = new Map<string, number>();
  const representativeIdByGroupId = new Map<string, string>();
  rows.forEach((row, index) => {
    if (!row.group) return;
    rowOrderByGroupId.set(row.group.groupId, index);
    representativeIdByGroupId.set(row.group.groupId, row.finding.findingId);
    for (const member of row.members) groupByFindingId.set(member.findingId, row.group);
  });
  return { groupByFindingId, rowOrderByGroupId, representativeIdByGroupId };
};

const nodeKey = (prefix: "B" | "C", findingId: string, side: RenderedGroups | undefined): string =>
  `${prefix}:${side?.groupByFindingId.get(findingId)?.groupId ?? findingId}`;

const diffNodes = (
  diff: VerificationDiff,
  index: number,
  baseline: RenderedGroups | undefined,
  current: RenderedGroups | undefined,
): string[] => {
  const nodes: string[] = [];
  const baselineId = sideFindingId(diff, true);
  const currentId = sideFindingId(diff, false);
  if (baselineId) nodes.push(nodeKey("B", baselineId, baseline));
  if (currentId) nodes.push(nodeKey("C", currentId, current));
  if (nodes.length === 0) nodes.push(`D:${index}`);
  return nodes;
};

const displayGroup = (
  members: readonly VerificationDiff[],
  baseline: boolean,
  side: RenderedGroups | undefined,
): { group?: BeginnerReportProblemGroup; representativeId?: string } => {
  if (!side) return {};
  let selected: { group: BeginnerReportProblemGroup; order: number; representativeId: string } | undefined;
  for (const member of members) {
    const findingId = sideFindingId(member, baseline);
    if (!findingId) continue;
    const group = side.groupByFindingId.get(findingId);
    if (!group) continue;
    const order = side.rowOrderByGroupId.get(group.groupId);
    const representativeId = side.representativeIdByGroupId.get(group.groupId);
    if (order === undefined || !representativeId) continue;
    if (!selected || order < selected.order) selected = { group, order, representativeId };
  }
  return selected ? { group: selected.group, representativeId: selected.representativeId } : {};
};

const leadDiff = (
  members: readonly VerificationDiff[],
  baseline: boolean,
  representativeId: string | undefined,
): VerificationDiff => {
  const first = members.find((member) => sideFindingId(member, baseline)) ?? members[0];
  if (!first) throw new Error("A compared problem has no diffs.");
  if (!representativeId) return first;
  return members.find((member) => sideFindingId(member, baseline) === representativeId) ?? first;
};

/**
 * Compare the same problem cards Results shows.
 * One card stays present while any member is observed again. It is no longer
 * observed only when every member was compared and none remains, and new only
 * when every member is new. Every other mix stays unverifiable.
 */
export function compareProblems(
  diffs: readonly VerificationDiff[],
  baselineReport?: VerificationProblemReport,
  currentReport?: VerificationProblemReport,
): VerificationProblem[] {
  const baseline = renderedGroups(baselineReport);
  const current = renderedGroups(currentReport);
  const parent = new Map<string, string>();
  const find = (node: string): string => {
    let root = node;
    while ((parent.get(root) ?? root) !== root) root = parent.get(root)!;
    let cursor = node;
    while (cursor !== root) {
      const next = parent.get(cursor) ?? cursor;
      parent.set(cursor, root);
      cursor = next;
    }
    return root;
  };
  const union = (left: string, right: string): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parent.set(leftRoot, rightRoot);
  };

  const nodeLists = diffs.map((diff, index) => diffNodes(diff, index, baseline, current));
  for (const nodes of nodeLists) {
    for (const node of nodes) {
      if (!parent.has(node)) parent.set(node, node);
    }
    const anchor = nodes[0];
    if (!anchor) continue;
    for (const node of nodes.slice(1)) union(anchor, node);
  }

  // A later diff can connect two components and change which node is the root,
  // so roots are read only after every diff has been unioned.
  const grouped = new Map<string, VerificationDiff[]>();
  const rootOrder: string[] = [];
  diffs.forEach((diff, index) => {
    const anchor = nodeLists[index]?.[0];
    if (!anchor) return;
    const root = find(anchor);
    const members = grouped.get(root);
    if (members) {
      members.push(diff);
      return;
    }
    grouped.set(root, [diff]);
    rootOrder.push(root);
  });

  return rootOrder.flatMap((root) => {
    const members = grouped.get(root);
    const first = members?.[0];
    if (!members || !first) return [];
    const state = problemState(members);
    const showsBaseline = state === "resolved" || members.every((member) => !sideFindingId(member, false));
    const displayed = displayGroup(members, showsBaseline, showsBaseline ? baseline : current);
    const beforeSeverity = highestSeverity(members.map((member) => member.beforeSeverity));
    const afterSeverity = highestSeverity(members.map((member) => member.afterSeverity));
    return [{
      id: first.id,
      state,
      moved: problemMoved(state, members),
      members,
      lead: leadDiff(members, showsBaseline, displayed.representativeId),
      displaysBaseline: showsBaseline,
      ...(displayed.group ? { group: displayed.group } : {}),
      ...(beforeSeverity ? { beforeSeverity } : {}),
      ...(afterSeverity ? { afterSeverity } : {}),
    }];
  });
}
