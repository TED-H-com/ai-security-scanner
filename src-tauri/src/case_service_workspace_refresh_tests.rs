use crate::agentic_radar_input::{
    AgenticFramework, FRAMEWORK_IDENTIFIER_NAMESPACE, FRAMEWORK_METADATA_KEY,
};
use crate::mcp_armor_input::{
    MCP_CONFIGURATION_PATH_NAMESPACE, MCP_CONFIGURATION_SELECTED_METADATA_KEY,
    MCP_CONFIGURATION_SHA256_NAMESPACE,
};
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceInputProfile, WorkspaceSnapshot,
    WorkspaceSnapshotLimits, WorkspaceSnapshotReference, create_workspace_snapshot_with_profile,
    inspect_workspace_snapshot,
};
use std::path::Path;

fn write_tree(root: &Path, files: &[(&str, &str)]) {
    if files.is_empty() {
        fs::create_dir_all(root).unwrap();
    }
    for (relative_path, contents) in files {
        let path = root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
}

fn workspace_snapshot_from(
    fixture: &Fixture,
    case_id: &str,
    source_id: &str,
    folder_name: &str,
    files: &[(&str, &str)],
    profile: WorkspaceInputProfile,
) -> WorkspaceSnapshot {
    let selected = fixture.directory.path().join(folder_name);
    write_tree(&selected, files);
    fs::create_dir_all(fixture.directory.path().join("artifacts")).unwrap();
    create_workspace_snapshot_with_profile(
        fixture.directory.path().join("artifacts"),
        case_id,
        source_id,
        &selected,
        profile,
        WorkspaceSnapshotLimits::default(),
    )
    .unwrap()
}

fn repository_snapshot(
    fixture: &Fixture,
    case_id: &str,
    source_id: &str,
    folder_name: &str,
    files: &[(&str, &str)],
) -> WorkspaceSnapshot {
    workspace_snapshot_from(
        fixture,
        case_id,
        source_id,
        folder_name,
        files,
        WorkspaceInputProfile::RepositoryWorkingTree,
    )
}

fn reference_sha(case: &AssessmentCase, source_id: &str) -> String {
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == source_id)
        .unwrap();
    let reference: WorkspaceSnapshotReference =
        serde_json::from_value(source.metadata[WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY].clone())
            .unwrap();
    reference.sha256
}

fn gitleaks_manifest(fixture: &Fixture) -> EngineManifest {
    fixture
        .engines
        .get("gitleaks")
        .expect("gitleaks catalog manifest")
        .clone()
}

#[test]
fn refresh_keeps_the_asset_and_records_the_new_copy() {
    let fixture = Fixture::new();
    let created = fixture.create();
    let source_id = "workspace-source-refresh";
    let initial = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "refresh-before",
        &[
            ("keep-a.txt", "same-a"),
            ("keep-b.txt", "same-b"),
            ("nested/keep.txt", "same-nested"),
            ("changed.txt", "version-1"),
            ("removed.txt", "gone"),
        ],
    );
    let asset_id = initial.asset.id.clone();
    let old_reference = initial.reference.clone();
    let service = fixture.service();
    let attached = service
        .attach_workspace_snapshot(&created.id, "Payments service", initial)
        .unwrap();
    let attached_asset = attached
        .assets
        .iter()
        .find(|asset| asset.id == asset_id)
        .unwrap();
    let attached_saved_at = DateTime::parse_from_rfc3339(
        attached_asset.metadata["workspace_snapshot_saved_at"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        !attached_asset
            .metadata
            .contains_key("workspace_snapshot_previous_sha256")
    );
    assert!(
        !attached_asset
            .metadata
            .contains_key("workspace_snapshot_change")
    );
    let old_sha = attached_asset.metadata["workspace_snapshot_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let grants = service
        .approve_scope(
            &created.id,
            ScopeApprovalRequest {
                asset_id: asset_id.clone(),
                permissions: vec![ScanPermission::LocalArtifactRead],
                confirmed_by: "owner".into(),
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            },
        )
        .unwrap();
    service
        .select_agentic_framework(
            &created.id,
            &asset_id,
            &old_sha,
            Some(AgenticFramework::Langgraph),
        )
        .unwrap();
    let mut prepared = service.show_case(&created.id).unwrap();
    {
        let asset = prepared
            .assets
            .iter_mut()
            .find(|asset| asset.id == asset_id)
            .unwrap();
        asset.internet_exposed = Some(false);
        asset.contains_sensitive_data = Some(true);
    }
    let connected_at = prepared.data_sources[0].connected_at;
    let source_label = prepared.data_sources[0].label.clone();
    fixture
        .storage
        .save_case(&mut prepared, "test.prepare-refresh")
        .unwrap();
    let (target_source, target_profile) = service
        .workspace_refresh_target(&created.id, &asset_id)
        .unwrap();
    assert_eq!(target_source, source_id);
    assert_eq!(target_profile, WorkspaceInputProfile::RepositoryWorkingTree);
    let status_before = service.show_case(&created.id).unwrap().status;

    let refreshed_snapshot = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "refresh-after",
        &[
            ("keep-a.txt", "same-a"),
            ("keep-b.txt", "same-b"),
            ("nested/keep.txt", "same-nested"),
            ("changed.txt", "version-2"),
            ("added.txt", "added"),
        ],
    );
    let new_sha = refreshed_snapshot.reference.sha256.clone();
    let updated = service
        .refresh_workspace_snapshot(&created.id, &asset_id, refreshed_snapshot)
        .unwrap();

    assert_eq!(updated.status, status_before);
    assert_eq!(updated.assets.len(), 1);
    assert_eq!(updated.scope_grants.len(), grants.len());
    assert_eq!(updated.scope_grants[0].id, grants[0].id);
    assert_eq!(updated.scope_grants[0].asset_id, asset_id);
    assert_eq!(
        updated.scope_grants[0].permission,
        ScanPermission::LocalArtifactRead
    );
    let asset = &updated.assets[0];
    assert_eq!(asset.id, asset_id);
    assert_eq!(asset.name, "Payments service");
    assert_eq!(asset.kind, AssetKind::Repository);
    assert!(!asset.candidate);
    assert!(asset.owner_confirmed);
    assert_eq!(asset.internet_exposed, Some(false));
    assert_eq!(asset.contains_sensitive_data, Some(true));
    assert_eq!(asset.discovered_from, vec![source_id.to_owned()]);
    assert!(!asset.metadata.contains_key("local_input_profile"));
    assert_eq!(
        asset.metadata[FRAMEWORK_METADATA_KEY],
        serde_json::json!("langgraph")
    );
    assert_eq!(
        asset
            .identifiers
            .iter()
            .filter(|identifier| identifier.namespace == FRAMEWORK_IDENTIFIER_NAMESPACE)
            .map(|identifier| identifier.value.as_str())
            .collect::<Vec<_>>(),
        vec!["langgraph"]
    );
    let sha_identifiers = asset
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.namespace == "ai-security-scanner:workspace-snapshot-sha256"
        })
        .map(|identifier| identifier.value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sha_identifiers, vec![new_sha.as_str()]);
    assert_eq!(asset.metadata["workspace_snapshot_sha256"], new_sha);
    assert_eq!(
        asset.metadata["workspace_snapshot_previous_sha256"],
        old_sha
    );
    assert_ne!(old_sha, new_sha);
    let refreshed_saved_at = DateTime::parse_from_rfc3339(
        asset.metadata["workspace_snapshot_saved_at"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(refreshed_saved_at >= attached_saved_at);
    assert_eq!(
        asset.metadata["workspace_snapshot_change"],
        serde_json::json!({
            "added": 1,
            "changed": 1,
            "removed": 1,
            "unchanged": 3
        })
    );
    let source = &updated.data_sources[0];
    assert_eq!(source.label, source_label);
    assert_eq!(source.connected_at, connected_at);
    assert_eq!(source.status, SourceConnectionStatus::Connected);
    assert!(source.read_only);
    assert!(source.last_discovered_at.is_some());
    assert_eq!(reference_sha(&updated, source_id), new_sha);
    assert_eq!(
        local_input_compatibility(&updated, &gitleaks_manifest(&fixture), asset),
        LocalInputCompatibility::Compatible
    );
    inspect_workspace_snapshot(
        fixture.directory.path().join("artifacts"),
        &created.id,
        &old_reference,
    )
    .expect("the previous snapshot files stay in place");
}

#[test]
fn refresh_keeps_an_mcp_selection_that_still_exists_and_clears_one_that_does_not() {
    let fixture = Fixture::new();
    let created = fixture.create();
    let source_id = "workspace-source-mcp";
    let initial = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "mcp-before",
        &[
            ("mcp.json", "{\"mcpServers\":{\"one\":{}}}\n"),
            (".cursor/mcp.json", "{\"mcpServers\":{\"cursor\":{}}}\n"),
            (".vscode/mcp.json", "{\"mcpServers\":{\"vscode\":{}}}\n"),
        ],
    );
    let asset_id = initial.asset.id.clone();
    let manifest = initial.manifest.clone();
    let service = fixture.service();
    let attached = service
        .attach_workspace_snapshot(&created.id, "MCP repository", initial)
        .unwrap();
    let sha = attached.assets[0].metadata["workspace_snapshot_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    service
        .select_mcp_configuration(&created.id, &asset_id, &sha, &manifest, "mcp.json")
        .unwrap();
    let selected = service.show_case(&created.id).unwrap();
    let old_mcp_sha = selected.assets[0]
        .identifiers
        .iter()
        .find(|identifier| identifier.namespace == MCP_CONFIGURATION_SHA256_NAMESPACE)
        .unwrap()
        .value
        .clone();

    let kept = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "mcp-kept",
        &[
            (
                "mcp.json",
                "{\"mcpServers\":{\"one\":{\"changed\":true}}}\n",
            ),
            (".cursor/mcp.json", "{\"mcpServers\":{\"cursor\":{}}}\n"),
            (".vscode/mcp.json", "{\"mcpServers\":{\"vscode\":{}}}\n"),
        ],
    );
    let kept_mcp_sha = kept
        .manifest
        .files
        .iter()
        .find(|file| file.relative_path == "mcp.json")
        .unwrap()
        .sha256
        .clone();
    let kept_case = service
        .refresh_workspace_snapshot(&created.id, &asset_id, kept)
        .unwrap();
    let kept_asset = &kept_case.assets[0];
    assert_eq!(
        kept_asset.metadata[MCP_CONFIGURATION_SELECTED_METADATA_KEY],
        "mcp.json"
    );
    let kept_identifier = kept_asset
        .identifiers
        .iter()
        .find(|identifier| identifier.namespace == MCP_CONFIGURATION_SHA256_NAMESPACE)
        .unwrap();
    assert_eq!(kept_identifier.value, kept_mcp_sha);
    assert_ne!(kept_identifier.value, old_mcp_sha);
    assert!(kept_asset.identifiers.iter().any(|identifier| {
        identifier.namespace == MCP_CONFIGURATION_PATH_NAMESPACE && identifier.value == "mcp.json"
    }));

    let cleared = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "mcp-cleared",
        &[
            (".cursor/mcp.json", "{\"mcpServers\":{\"cursor\":{}}}\n"),
            (".vscode/mcp.json", "{\"mcpServers\":{\"vscode\":{}}}\n"),
        ],
    );
    let cleared_case = service
        .refresh_workspace_snapshot(&created.id, &asset_id, cleared)
        .unwrap();
    let cleared_asset = &cleared_case.assets[0];
    assert!(
        !cleared_asset
            .metadata
            .contains_key(MCP_CONFIGURATION_SELECTED_METADATA_KEY)
    );
    assert!(cleared_asset.identifiers.iter().all(|identifier| {
        identifier.namespace != MCP_CONFIGURATION_PATH_NAMESPACE
            && identifier.namespace != MCP_CONFIGURATION_SHA256_NAMESPACE
    }));
}

#[test]
fn refresh_omits_the_change_summary_when_the_previous_manifest_cannot_be_read() {
    let fixture = Fixture::new();
    let created = fixture.create();
    let source_id = "workspace-source-unreadable";
    let initial = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "unreadable-before",
        &[("keep.txt", "keep")],
    );
    let asset_id = initial.asset.id.clone();
    let first_reference = initial.reference.clone();
    let service = fixture.service();
    service
        .attach_workspace_snapshot(&created.id, "Repository", initial)
        .unwrap();
    let second = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "unreadable-second",
        &[("keep.txt", "changed")],
    );
    let second_reference = second.reference.clone();
    let second_sha = second.reference.sha256.clone();
    service
        .refresh_workspace_snapshot(&created.id, &asset_id, second)
        .unwrap();
    let mut stored = service.show_case(&created.id).unwrap();
    assert!(
        stored.assets[0]
            .metadata
            .contains_key("workspace_snapshot_change")
    );
    let source = &mut stored.data_sources[0];
    let mut reference: WorkspaceSnapshotReference =
        serde_json::from_value(source.metadata[WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY].clone())
            .unwrap();
    reference.sha256 = "f".repeat(64);
    source.metadata.insert(
        WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY.into(),
        serde_json::to_value(&reference).unwrap(),
    );
    fixture
        .storage
        .save_case(&mut stored, "test.corrupt-snapshot-reference")
        .unwrap();

    let third = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "unreadable-third",
        &[("keep.txt", "third")],
    );
    let third_sha = third.reference.sha256.clone();
    let updated = service
        .refresh_workspace_snapshot(&created.id, &asset_id, third)
        .unwrap();
    assert_eq!(
        updated.assets[0].metadata["workspace_snapshot_previous_sha256"],
        second_sha
    );
    assert_eq!(
        updated.assets[0].metadata["workspace_snapshot_sha256"],
        third_sha
    );
    assert!(
        !updated.assets[0]
            .metadata
            .contains_key("workspace_snapshot_change")
    );
    let artifact_root = fixture.directory.path().join("artifacts");
    inspect_workspace_snapshot(&artifact_root, &created.id, &first_reference)
        .expect("the first snapshot files stay in place");
    inspect_workspace_snapshot(&artifact_root, &created.id, &second_reference)
        .expect("the second snapshot files stay in place");
}

#[test]
fn refresh_refuses_an_active_or_paused_scan() {
    let fixture = Fixture::new();
    let created = fixture.create();
    let source_id = "workspace-source-active";
    let initial = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "active-before",
        &[("keep.txt", "keep")],
    );
    let asset_id = initial.asset.id.clone();
    let service = fixture.service();
    service
        .attach_workspace_snapshot(&created.id, "Repository", initial)
        .unwrap();
    service
        .approve_scope(
            &created.id,
            ScopeApprovalRequest {
                asset_id: asset_id.clone(),
                permissions: vec![ScanPermission::LocalArtifactRead],
                confirmed_by: "owner".into(),
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            },
        )
        .unwrap();
    let plan = service
        .plan_scan(
            &created.id,
            ScanPlanRequest {
                campaign_id: None,
                engine_ids: vec!["gitleaks".into()],
                engine_asset_routes: Vec::new(),
            },
        )
        .unwrap();
    assert!(
        plan.scan_run
            .engine_runs
            .iter()
            .any(|engine_run| engine_run.status == EngineRunStatus::Queued)
    );
    let next = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "active-next",
        &[("keep.txt", "next")],
    );
    let active = service
        .refresh_workspace_snapshot(&created.id, &asset_id, next)
        .unwrap_err();
    assert!(active.to_string().contains(
        "cannot refresh a workspace snapshot while a scan is active or paused; the recorded scan contract is immutable"
    ));

    let mut paused = service.show_case(&created.id).unwrap();
    for engine_run in &mut paused.scan_runs[0].engine_runs {
        if engine_run.status == EngineRunStatus::Queued {
            engine_run.status = EngineRunStatus::Paused;
        }
    }
    assert!(
        paused.scan_runs[0]
            .engine_runs
            .iter()
            .any(|engine_run| engine_run.status == EngineRunStatus::Paused)
    );
    fixture
        .storage
        .save_case(&mut paused, "test.pause-scan")
        .unwrap();
    let paused_snapshot = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "paused-next",
        &[("keep.txt", "paused")],
    );
    let paused_error = service
        .refresh_workspace_snapshot(&created.id, &asset_id, paused_snapshot)
        .unwrap_err();
    assert!(paused_error.to_string().contains(
        "cannot refresh a workspace snapshot while a scan is active or paused; the recorded scan contract is immutable"
    ));
}

#[test]
fn refresh_refuses_a_non_workspace_or_unknown_asset_and_a_mismatched_snapshot() {
    let fixture = Fixture::new();
    let created = fixture.create();
    let source_id = "workspace-source-guard";
    let initial = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "guard-before",
        &[("keep.txt", "keep")],
    );
    let asset_id = initial.asset.id.clone();
    let service = fixture.service();
    service
        .attach_workspace_snapshot(&created.id, "Repository", initial)
        .unwrap();

    let unknown = repository_snapshot(
        &fixture,
        &created.id,
        source_id,
        "guard-unknown",
        &[("keep.txt", "unknown")],
    );
    let unknown_error = service
        .refresh_workspace_snapshot(&created.id, "missing-asset", unknown)
        .unwrap_err();
    assert_eq!(
        invalid_request(&unknown_error),
        "asset not found: missing-asset"
    );

    let (declared, declared_id) = fixture.discovered_declared_asset(&created.id, AssetKind::Host);
    let declared_snapshot = repository_snapshot(
        &fixture,
        &declared.id,
        "declared-source",
        "guard-declared",
        &[("keep.txt", "declared")],
    );
    let declared_error = service
        .refresh_workspace_snapshot(&declared.id, &declared_id, declared_snapshot)
        .unwrap_err();
    assert_eq!(
        invalid_request(&declared_error),
        "workspace asset has no snapshot content hash"
    );

    let mut other_source = repository_snapshot(
        &fixture,
        &created.id,
        "workspace-source-other",
        "guard-other-source",
        &[("keep.txt", "other")],
    );
    other_source.asset.id = asset_id.clone();
    let other_source_error = service
        .refresh_workspace_snapshot(&created.id, &asset_id, other_source)
        .unwrap_err();
    assert_eq!(
        invalid_request(&other_source_error),
        "workspace refresh snapshot comes from a different source"
    );

    let other_profile = workspace_snapshot_from(
        &fixture,
        &created.id,
        source_id,
        "guard-iac",
        &[("main.tf", "resource \"example\" \"demo\" {}\n")],
        WorkspaceInputProfile::IacWorkingTree,
    );
    let other_profile_error = service
        .refresh_workspace_snapshot(&created.id, &asset_id, other_profile)
        .unwrap_err();
    assert_eq!(
        invalid_request(&other_profile_error),
        "workspace refresh snapshot uses a different input profile"
    );
}

#[test]
fn refresh_refuses_an_archived_or_demo_case() {
    let fixture = Fixture::new();
    let archived = fixture.create();
    fixture.service().archive_case(&archived.id).unwrap();
    let archived_snapshot = repository_snapshot(
        &fixture,
        &archived.id,
        "archived-source",
        "archived-folder",
        &[("keep.txt", "keep")],
    );
    let archived_error = fixture
        .service()
        .refresh_workspace_snapshot(&archived.id, "asset", archived_snapshot)
        .unwrap_err();
    assert_eq!(
        invalid_request(&archived_error),
        "archived cases cannot refresh a workspace snapshot; reopen by creating a new assessment case"
    );

    let mut demo = crate::demo::build_demo_case();
    fixture
        .storage
        .save_case(&mut demo, "test.demo-refresh")
        .unwrap();
    let demo_snapshot = repository_snapshot(
        &fixture,
        &demo.id,
        "demo-source",
        "demo-folder",
        &[("keep.txt", "keep")],
    );
    let demo_error = fixture
        .service()
        .refresh_workspace_snapshot(&demo.id, "asset", demo_snapshot)
        .unwrap_err();
    match demo_error {
        AppError::NotAuthorized(message) => assert_eq!(
            message,
            "synthetic demo cases are immutable and cannot refresh a workspace snapshot"
        ),
        other => panic!("expected NotAuthorized, got {other}"),
    }
}

fn invalid_request(error: &AppError) -> &str {
    match error {
        AppError::InvalidRequest(message) => message,
        other => panic!("expected InvalidRequest, got {other}"),
    }
}

#[test]
fn execution_scope_contract_hash_is_pinned_and_comparison_ignores_copy_hashes() {
    const EXECUTION_SCOPE_HASH: &str =
        "ac1f63612f48ba8a6391a07697166b7925bfe3e3b6acc1129b2af1299582d25f";
    let manifest = comparison_scope_manifest();
    let asset = comparison_scope_asset();
    let grant = comparison_scope_grant();
    let execution = comparable_scope_contract_sha256(
        &manifest,
        &[&asset],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Execution,
    )
    .unwrap();
    assert_eq!(
        execution, EXECUTION_SCOPE_HASH,
        "pin this constant to the current Execution document; do not change that document"
    );

    let mut left = asset.clone();
    left.identifiers.extend([
        AssetIdentifier {
            namespace: "ai-security-scanner:workspace-snapshot-sha256".into(),
            value: "a".repeat(64),
        },
        AssetIdentifier {
            namespace: MCP_CONFIGURATION_SHA256_NAMESPACE.into(),
            value: "b".repeat(64),
        },
        AssetIdentifier {
            namespace: MCP_CONFIGURATION_PATH_NAMESPACE.into(),
            value: "mcp.json".into(),
        },
        AssetIdentifier {
            namespace: FRAMEWORK_IDENTIFIER_NAMESPACE.into(),
            value: "langgraph".into(),
        },
    ]);
    let mut right = left.clone();
    for identifier in &mut right.identifiers {
        if identifier.namespace == "ai-security-scanner:workspace-snapshot-sha256" {
            identifier.value = "c".repeat(64);
        }
        if identifier.namespace == MCP_CONFIGURATION_SHA256_NAMESPACE {
            identifier.value = "d".repeat(64);
        }
    }
    let left_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&left],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    let right_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&right],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    assert_eq!(left_comparison, right_comparison);
    let left_execution = comparable_scope_contract_sha256(
        &manifest,
        &[&left],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Execution,
    )
    .unwrap();
    let right_execution = comparable_scope_contract_sha256(
        &manifest,
        &[&right],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Execution,
    )
    .unwrap();
    assert_ne!(left_execution, right_execution);

    let mut other_path = right.clone();
    for identifier in &mut other_path.identifiers {
        if identifier.namespace == MCP_CONFIGURATION_PATH_NAMESPACE {
            identifier.value = ".cursor/mcp.json".into();
        }
    }
    let path_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&other_path],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    assert_ne!(left_comparison, path_comparison);

    let mut other_framework = right.clone();
    for identifier in &mut other_framework.identifiers {
        if identifier.namespace == FRAMEWORK_IDENTIFIER_NAMESPACE {
            identifier.value = "crewai".into();
        }
    }
    let framework_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&other_framework],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    assert_ne!(left_comparison, framework_comparison);

    let mut other_kind = right.clone();
    other_kind.kind = AssetKind::Host;
    let kind_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&other_kind],
        std::slice::from_ref(&grant),
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    assert_ne!(left_comparison, kind_comparison);

    let mut other_grant = grant.clone();
    other_grant.permission = ScanPermission::InventoryRead;
    let permission_comparison = comparable_scope_contract_sha256(
        &manifest,
        &[&right],
        &[other_grant],
        ScopeContractPurpose::Comparison,
    )
    .unwrap();
    assert_ne!(left_comparison, permission_comparison);
}
