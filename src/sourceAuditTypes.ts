import type { SeverityWire } from "./types";

/** Exact serde DTOs. Keep native JSON and provider strings unchanged on the desktop. */
export interface ProviderSourceLocationWire {
  path: string;
  line: number;
  view_file_sha256: string;
}

export interface AgentAuditRecordWire {
  fingerprint: string;
  verdict: "confirmed" | "needs_validation" | "rejected";
  severity: SeverityWire | null;
  native_record: unknown;
  native_record_index: number;
  native_record_sha256: string;
  source_locations: Array<ProviderSourceLocationWire>;
  coverage_ids: Array<string>;
  reported_verifier_assignments: Array<string>;
}

export interface ProviderRecordRefWire {
  admission_id: string;
  native_record_index: number;
  native_record_sha256: string;
  native_fingerprint: string;
  source_locators: Array<ProviderSourceLocationWire>;
}

export interface SourceAuditMethodWire {
  provider: string;
  upstream_commit: string;
  validator_resources_sha256: string;
  profile: string;
  declared_invocation_limit: number | null;
  issued_invocations: number;
  remaining_invocations: number | null;
  counts_by_role: Record<string, number>;
  counts_by_state: Record<string, number>;
  provenance: string;
  verification_scope: string;
  validators_reexecuted: boolean;
}

export interface SourceAuditOutcomeWire {
  state: string;
  incomplete_reason: string | null;
  audit_performed: boolean;
}

export interface SourceAuditGapWire {
  coverage_id: string;
  status: string;
  label: string;
  continuation_paths: Array<string>;
  unresolved: Array<string>;
}

export interface SourceAuditValidationWire {
  native_record: unknown;
  native_record_index: number;
  native_record_sha256: string;
  source_locations: Array<ProviderSourceLocationWire>;
  coverage_ids: Array<string>;
  reported_verifier_assignments: Array<string>;
}

export interface SourceAuditTechnicalWire {
  confirmed: Array<AgentAuditRecordWire>;
  rejected: Array<AgentAuditRecordWire>;
  coverage_ledger: unknown;
  lineage: unknown;
  custody_digests: unknown;
  admission_sha256: string;
  originals: unknown;
}

export interface SourceAuditReportWire {
  task_id: string;
  asset_ids: Array<string>;
  admission_id: string;
  method: SourceAuditMethodWire;
  outcome: SourceAuditOutcomeWire;
  counts: Record<string, number>;
  coverage_by_status: Record<string, number>;
  to_validate: Array<SourceAuditValidationWire>;
  coverage_gaps: Array<SourceAuditGapWire>;
  unresolved_candidates: Array<string>;
  technical_detail: SourceAuditTechnicalWire;
  withheld_code_fields?: number;
  withheld_text_fields?: number;
}

/** The report projection keeps its wire shape, including all technical provenance. */
export const adaptSourceAudit = (audit: SourceAuditReportWire): SourceAuditReportWire => structuredClone(audit);
