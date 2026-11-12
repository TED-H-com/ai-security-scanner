use crate::test_temp;

pub(super) use ai_security_scanner_lib::domain::{
    AssessmentCase, DataSource, OrganizationProfile, ScanPermission, ScopeGrant,
    SourceConnectionStatus,
};
pub(super) use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
pub(super) use ai_security_scanner_lib::storage::Storage;
pub(super) use ai_security_scanner_lib::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot,
};
pub(super) use chrono::Utc;
pub(super) use serde_json::{Value, json};
pub(super) use std::fs;
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::process::{Command, Output};

pub(super) struct Fixture {
    pub(super) _temp: test_temp::TempDir,
    pub(super) data: PathBuf,
    pub(super) case_id: String,
    pub(super) asset_id: String,
    pub(super) reference: WorkspaceSnapshotReference,
}
impl Fixture {
    pub(super) fn new(files: &[(&str, &[u8])], approve: bool) -> Self {
        let builder = tempfile::Builder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::PermissionsExt;
            let mut builder = builder;
            builder.permissions(fs::Permissions::from_mode(0o700));
            builder
        };
        let temp = builder.tempdir().map(test_temp::TempDir::from).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let data = root.join("data");
        let source = root.join("source");
        fs::create_dir_all(data.join("artifacts")).unwrap();
        fs::create_dir(&source).unwrap();
        for (path, bytes) in files {
            let path = source.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        let mut case = AssessmentCase::new(
            "Synthetic source view".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        let snapshot = create_workspace_snapshot(
            data.join("artifacts"),
            &case.id,
            "synthetic-source",
            &source,
            WorkspaceSnapshotLimits {
                max_files: 200_000,
                ..WorkspaceSnapshotLimits::default()
            },
        )
        .unwrap();
        let mut asset = snapshot.asset;
        let reference = snapshot.reference;
        asset.owner_confirmed = approve;
        asset.candidate = !approve;
        case.data_sources.push(DataSource {
            id: "synthetic-source".into(),
            kind: reference.input_profile.source_kind(),
            label: "Synthetic".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(Utc::now()),
            last_discovered_at: None,
            read_only: true,
            metadata: [(
                WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY.into(),
                json!(reference),
            )]
            .into(),
        });
        if approve {
            case.scope_grants.push(ScopeGrant {
                id: "local-grant".into(),
                asset_id: asset.id.clone(),
                permission: ScanPermission::LocalArtifactRead,
                confirmed_by: "test-owner".into(),
                confirmed_at: Utc::now(),
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            });
        }
        let asset_id = asset.id.clone();
        case.assets.push(asset);
        Storage::open(data.join("casework.db"))
            .unwrap()
            .save_case(&mut case, "fixture.created")
            .unwrap();
        Self {
            _temp: temp,
            data,
            case_id: case.id,
            asset_id,
            reference,
        }
    }
    pub(super) fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
        c.arg("--data-dir")
            .arg(&self.data)
            .arg("--json")
            .env("PATH", "");
        c
    }
    pub(super) fn prepare_command(&self, request: &str, scope: &str) -> Command {
        let mut c = self.command();
        c.args([
            "provider",
            "cloudflare",
            "prepare-source-view",
            "--case-id",
            &self.case_id,
            "--asset-id",
            &self.asset_id,
            "--expected-snapshot-sha256",
            &self.reference.sha256,
            "--request-id",
            request,
            "--scope-path",
            scope,
            "--acknowledge-model-processing",
            "--confirmed-by",
            "test-owner",
            "--host-id",
            "declared-test-host",
        ]);
        c
    }
    pub(super) fn prepare(&self, request: &str, scope: &str) -> Value {
        terminal(self.prepare_command(request, scope).output().unwrap(), 0)
    }
}
pub(super) fn terminal(output: Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["type"], "terminal");
    assert_eq!(value["exit_code"], code);
    value
}
pub(super) fn writable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
}

impl Fixture {
    pub(super) fn setup(approve: bool) -> (Self, Value) {
        let f = Self::new(&[("src/a.rs", b"fn main() {}\n")], approve);
        let view = f.prepare("view-request", ".");
        let host = f.data.parent().unwrap().join("host");
        fs::create_dir(&host).unwrap();
        let request = json!({
            "schema_version":"ai-security-scanner.cloudflare-audit-prepare-request/v1",
            "request_id":"audit-one", "case_id":f.case_id, "asset_id":f.asset_id,
            "source_view_request_id":"view-request", "expected_source_view_receipt_sha256":view["receipt"]["sha256"],
            "profile":"quick", "invocation_budget":null,
            "host":{"host_id":"declared-test-host","delegation":"available"}, "run_directory":host,
        });
        (f, request)
    }
    pub(super) fn audit_command(&self, request: &Value) -> Command {
        let path = self.data.parent().unwrap().join("request.json");
        fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
        let mut c = self.command();
        c.args(["provider", "cloudflare", "prepare", "--request"])
            .arg(path);
        c
    }
    pub(super) fn audit(&self, request: &Value, code: i32) -> Value {
        terminal(self.audit_command(request).output().unwrap(), code)
    }
    pub(super) fn audit_status(&self, id: &str, by_session: bool, code: i32) -> Value {
        terminal(
            self.command()
                .args([
                    "provider",
                    "cloudflare",
                    "status",
                    "--case-id",
                    &self.case_id,
                    if by_session {
                        "--session-id"
                    } else {
                        "--prepare-request-id"
                    },
                    id,
                ])
                .output()
                .unwrap(),
            code,
        )
    }
    pub(super) fn storage(&self) -> Storage {
        Storage::open(self.data.join("casework.db")).unwrap()
    }
    pub(super) fn events(&self) -> usize {
        self.storage()
            .list_case_events(&self.case_id)
            .unwrap()
            .iter()
            .filter(|e| e.event_type == "cloudflare_audit.preparation_terminal")
            .count()
    }
    pub(super) fn audit_root(&self) -> PathBuf {
        self.data
            .join("artifacts")
            .join(&self.case_id)
            .join("cloudflare-sessions")
    }
    pub(super) fn view_root(&self) -> PathBuf {
        let r = self
            .storage()
            .source_view_receipt(&self.case_id, "view-request")
            .unwrap()
            .unwrap();
        let v = serde_json::to_value(r.result).unwrap();
        self.data
            .join("artifacts")
            .join(v["relative_path"].as_str().unwrap())
    }
    pub(super) fn change_case(&self, change: impl FnOnce(&mut AssessmentCase)) {
        let s = self.storage();
        let mut c = s.get_case(&self.case_id).unwrap();
        change(&mut c);
        s.save_case(&mut c, "fixture.changed").unwrap();
    }
}
pub(super) fn receipt(value: &Value) -> &Value {
    &value["result"]["receipt"]
}
pub(super) fn facts(value: &Value) -> &Value {
    &receipt(value)["result"]["facts"]
}
impl Fixture {
    pub(super) fn checkpoint_command(&self, request: &Value) -> Command {
        let path = self.data.parent().unwrap().join("checkpoint.json");
        fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
        let mut c = self.command();
        c.args(["provider", "cloudflare", "checkpoint", "--request"])
            .arg(path);
        c
    }
    pub(super) fn checkpoint(&self, request: &Value, code: i32) -> Value {
        terminal(self.checkpoint_command(request).output().unwrap(), code)
    }
    pub(super) fn checkpoint_request(&self, prepared: &Value, action: Value) -> Value {
        json!({"schema_version":"ai-security-scanner.cloudflare-audit-checkpoint-request/v1",
            "request_id":"checkpoint-one","case_id":self.case_id,"session_id":prepared["session_id"],
            "expected_head_sha256":prepared["receipt"]["sha256"],"action":action})
    }
    pub(super) fn record_events(&self) -> usize {
        self.storage()
            .list_case_events(&self.case_id)
            .unwrap()
            .iter()
            .filter(|e| e.event_type == "cloudflare_audit.record_entry")
            .count()
    }
}

/// A synthetic terminal run, captured exclusively through real CLI commands.
pub(super) struct RunFixture {
    pub f: Fixture,
    pub prepared: Value,
    pub host: PathBuf,
    pub head: Value,
    pub findings: Value,
    pub ledger: Value,
    pub metadata: Value,
    pub hunter: Value,
    serial: usize,
}
impl RunFixture {
    pub fn new(profile: &str) -> Self {
        Self::without(profile, &[])
    }
    pub fn without(profile: &str, omitted: &[&str]) -> Self {
        Self::with_records(profile, omitted, |_, _, _| {})
    }
    pub fn with_records(
        profile: &str,
        omitted: &[&str],
        edit: impl FnOnce(&mut Value, &mut Value, &mut Value),
    ) -> Self {
        let (f, mut prep) = Fixture::setup(true);
        prep["profile"] = json!(profile);
        let prepared = f.audit(&prep, 0);
        let mut findings: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/cloudflare/bundle/findings.json"
        ))
        .unwrap();
        for record in findings.as_array_mut().unwrap() {
            for field in ["trace", "evidence"] {
                for location in record[field].as_array_mut().unwrap() {
                    location["file"] = json!("src/a.rs");
                    location["line"] = json!(1);
                }
            }
        }
        let mut ledger: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/cloudflare/bundle/coverage-ledger.json"
        ))
        .unwrap();
        ledger[0]["starting_paths"] = json!(["src/a.rs"]);
        ledger[0]["reviewed_paths"] = json!(["src/a.rs"]);
        ledger[0]["local_checks"][0]["reviewed_paths"] = json!(["src/a.rs"]);
        let mut metadata = json!({"run_id":facts(&prepared)["provider_run_id"],
            "source_ref":facts(&prepared)["source"]["source_ref"],"profile":profile,
            "execution_policy":"sandboxed-source-and-local-only", "repo":"Synthetic",
            "target":"Synthetic source", "budget":null, "scope_paths":["."], "run_status":"complete"});
        edit(&mut findings, &mut ledger, &mut metadata);
        let mut run = Self {
            host: PathBuf::from(prep["run_directory"].as_str().unwrap()),
            head: prepared["receipt"]["sha256"].clone(),
            f,
            prepared,
            findings,
            ledger,
            metadata,
            hunter: Value::Null,
            serial: 0,
        };
        for _ in 0..if omitted.contains(&"baseline") { 3 } else { 4 } {
            let a = run.issue(json!({"role":"reconnaissance_baseline"}));
            run.submit(&a, b"Synthetic source map");
        }
        run.hunter = run.issue(json!({"role":"hunter","wave":1}));
        run.ledger[0]["agent_id"] = run.hunter["agent_id"].clone();
        run.ledger[0]["local_checks"][0]["agent_id"] = run.hunter["agent_id"].clone();
        if omitted.contains(&"hunter") {
            run.action(json!({"type":"interrupt","assignment_id":run.hunter["assignment_id"],"reason":"abandoned"}));
        } else {
            run.submit(&run.hunter.clone(), b"{}");
        }
        for mut r in run.findings.as_array().unwrap().clone() {
            if omitted.contains(&"candidate") {
                continue;
            }
            let a = run.issue(json!({"role":"candidate_verifier","fingerprint":r["fingerprint"]}));
            if omitted.contains(&"same_fingerprint") {
                r["fingerprint"] = json!("different-returned-fingerprint");
            }
            run.submit(
                &a,
                &serde_json::to_vec(&json!({"decision":r["verdict"],"record":r})).unwrap(),
            );
        }
        run.documents(&["findings.json"]);
        if profile != "quick" && !omitted.contains(&"final") {
            for r in run
                .findings
                .as_array()
                .unwrap()
                .clone()
                .into_iter()
                .filter(|r| r["verdict"] != "rejected")
            {
                let a = run.issue(json!({"role":"final_verifier","fingerprint":r["fingerprint"]}));
                run.submit(
                    &a,
                    &serde_json::to_vec(
                        &json!({"decision":"verified","fingerprint":r["fingerprint"]}),
                    )
                    .unwrap(),
                );
            }
        }
        if profile != "quick" && !omitted.contains(&"clean") {
            let a = run.issue(json!({"role":"final_clean_critic"}));
            run.submit(&a, b"{}");
        }
        if !omitted.contains(&"critic") {
            let a = run.issue(json!({"role":"post_wave_critic","wave":1}));
            run.submit(&a, b"{}");
        }
        let names = [
            "run-metadata.json",
            "architecture.md",
            "coverage-ledger.json",
            "findings.json",
            "REPORT.md",
            "FINDINGS-DETAIL.md",
            "NEEDS-VALIDATION.md",
        ];
        run.documents(
            &names
                .into_iter()
                .filter(|n| !omitted.contains(n))
                .collect::<Vec<_>>(),
        );
        run
    }
    pub fn action(&mut self, action: Value) -> Value {
        self.serial += 1;
        let mut request = self.f.checkpoint_request(&self.prepared, action);
        request["request_id"] = json!(format!("fixture-{}", self.serial));
        request["expected_head_sha256"] = self.head.clone();
        let value = terminal(
            self.f
                .checkpoint_command(&request)
                .env("PATH", std::env::var_os("PATH").unwrap())
                .output()
                .unwrap(),
            0,
        );
        self.head = value["result"]["record_head"]["entry_sha256"].clone();
        value
    }
    pub fn issue(&mut self, spec: Value) -> Value {
        self.action(json!({"type":"issue","assignments":[spec]}))["result"]["entry"]["content"]["assignments"][0].clone()
    }
    pub fn submit(&mut self, a: &Value, bytes: &[u8]) {
        let path = format!(
            "agents/{}/artifacts/output.json",
            a["agent_id"].as_str().unwrap()
        );
        let file = self.host.join(&path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
        self.action(json!({"type":"submit_output","assignment_id":a["assignment_id"],"output":{"path":path}}));
    }
    pub fn documents(&mut self, names: &[&str]) {
        for name in names {
            let bytes = match *name {
                "findings.json" => serde_json::to_vec(&self.findings).unwrap(),
                "coverage-ledger.json" => serde_json::to_vec(&self.ledger).unwrap(),
                "run-metadata.json" => serde_json::to_vec(&self.metadata).unwrap(),
                _ => b"# Synthetic audit\n".to_vec(),
            };
            fs::write(self.host.join(name), bytes).unwrap();
        }
        self.action(json!({"type":"submit_documents","documents":names.iter().map(|n|json!({"name":n})).collect::<Vec<_>>()}));
    }
}

impl RunFixture {
    pub fn validate_command(&self) -> Command {
        let path = self.f.data.parent().unwrap().join("validate.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version":"ai-security-scanner.cloudflare-audit-validate-request/v1",
                "case_id":self.f.case_id,"session_id":self.prepared["session_id"],
                "expected_head_sha256":self.head
            }))
            .unwrap(),
        )
        .unwrap();
        let mut command = self.f.command();
        command
            .env("PATH", std::env::var_os("PATH").unwrap())
            .args(["provider", "cloudflare", "validate", "--request"])
            .arg(path);
        command
    }
    pub fn validate(&self, code: i32) -> Value {
        terminal(self.validate_command().output().unwrap(), code)
    }
    pub fn directory(&self) -> PathBuf {
        self.f
            .audit_root()
            .join(self.prepared["session_id"].as_str().unwrap())
    }
    pub fn assert_no_temporary(&self) {
        assert!(fs::read_dir(self.directory()).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".validate-")
        }));
    }
}
