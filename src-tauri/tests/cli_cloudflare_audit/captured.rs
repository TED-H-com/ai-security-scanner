use super::fixture::*;
use ai_security_scanner_lib::cloudflare_provider::audit::{captured, record::Entry};
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
struct Captured {
    f: Fixture,
    prepared: Value,
    host: PathBuf,
    head: Value,
    serial: usize,
}
impl Captured {
    fn new() -> Self {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let mut c = Self {
            head: prepared["receipt"]["sha256"].clone(),
            prepared,
            host: PathBuf::from(prep["run_directory"].as_str().unwrap()),
            f,
            serial: 0,
        };
        for bytes in [b"old report".as_slice(), b"current report"] {
            fs::write(c.host.join("REPORT.md"), bytes).unwrap();
            c.action(json!({"type":"submit_documents","documents":[{"name":"REPORT.md"}]}));
        }
        c
    }
    fn action(&mut self, action: Value) -> Value {
        self.serial += 1;
        let mut r = self.f.checkpoint_request(&self.prepared, action);
        r["request_id"] = json!(format!("capture-{}", self.serial));
        r["expected_head_sha256"] = self.head.clone();
        let v = self.f.checkpoint(&r, 0);
        self.head = v["result"]["record_head"]["entry_sha256"].clone();
        v
    }
    fn output(&mut self, discarded: bool) -> String {
        let role = if discarded {
            json!({"role":"candidate_verifier","fingerprint":"synthetic-candidate"})
        } else {
            json!({"role":"reconnaissance_baseline"})
        };
        let issued = self.action(json!({"type":"issue","assignments":[role]}));
        let a = &issued["result"]["entry"]["content"]["assignments"][0];
        let path = format!(
            "agents/{}/artifacts/output",
            a["agent_id"].as_str().unwrap()
        );
        fs::create_dir_all(self.host.join(&path).parent().unwrap()).unwrap();
        fs::write(
            self.host.join(&path),
            if discarded {
                b"bad output".as_slice()
            } else {
                b"accepted output"
            },
        )
        .unwrap();
        self.action(json!({"type":"submit_output","assignment_id":a["assignment_id"],"output":{"path":path}}));
        a["assignment_id"].as_str().unwrap().into()
    }
    fn destination(&self, name: &str) -> PathBuf {
        self.f.data.parent().unwrap().join(name)
    }
    fn command(&self, selector: &[&str], dest: &Path) -> Command {
        let mut command = self.f.command();
        command
            .args([
                "provider",
                "cloudflare",
                "retrieve-captured",
                "--case-id",
                &self.f.case_id,
                "--session-id",
                self.prepared["session_id"].as_str().unwrap(),
                "--destination",
            ])
            .arg(dest)
            .args(selector);
        command
    }
    fn objects(&self) -> PathBuf {
        self.f
            .audit_root()
            .join(self.prepared["session_id"].as_str().unwrap())
            .join("objects")
    }
}
pub(super) fn logical_database(f: &Fixture) -> Vec<String> {
    let db = rusqlite::Connection::open_with_flags(
        f.data.join("casework.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut dump = vec![];
    for table in tables {
        let mut statement = db
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |r| {
                (0..columns)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap();
        for row in rows {
            dump.push(format!("{table}: {:?}", row.unwrap()));
        }
    }
    dump.sort();
    dump
}
#[test]
fn exact_current_superseded_and_accepted_bytes_are_read_only_and_discoverable() {
    let mut c = Captured::new();
    let assignment = c.output(false);
    fs::write(c.objects().join(hash(b"orphan")), b"orphan").unwrap();
    let storage = Storage::open_read_only(c.f.data.join("casework.db")).unwrap();
    let snapshot = storage
        .cloudflare_captured_snapshot(&c.f.case_id, c.prepared["session_id"].as_str().unwrap())
        .unwrap();
    let entries = captured::enumerate(&snapshot.record).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(!entries.iter().any(|e| e.sha256 == hash(b"orphan")));
    let status = c.f.audit_status("audit-one", false, 0);
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["current"]["revision"],
        2
    );
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["current"]["sha256"],
        hash(b"current report")
    );
    assert_eq!(
        status["result"]["assignments"][0]["assignment_id"],
        assignment
    );
    assert_eq!(
        status["result"]["assignments"][0]["role"],
        "reconnaissance_baseline"
    );
    assert_eq!(
        status["result"]["assignments"][0]["output"]["sha256"],
        hash(b"accepted output")
    );
    fs::remove_dir_all(&c.host).unwrap();
    let before = logical_database(&c.f);
    let lease = DataDirectoryExclusiveLease::acquire(&c.f.data).unwrap();
    for (i, (selector, bytes)) in [
        (
            vec!["--document", "REPORT.md", "--revision", "1"],
            b"old report".as_slice(),
        ),
        (
            vec!["--document", "REPORT.md", "--revision", "2"],
            b"current report".as_slice(),
        ),
        (
            vec!["--assignment-id", &assignment],
            b"accepted output".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let dest = c.destination(&format!("recovered-{i}"));
        let v = terminal(
            c.command(&selector, &dest)
                .args([
                    "--expected-sha256",
                    &hash(bytes),
                    "--expected-head-sha256",
                    c.head.as_str().unwrap(),
                ])
                .output()
                .unwrap(),
            0,
        );
        assert_eq!(
            v["schema_version"],
            "ai-security-scanner.cloudflare-audit-command/v1"
        );
        assert_eq!(v["operation"], "provider.cloudflare.retrieve-captured");
        assert_eq!(v["command_outcome"], "completed");
        assert_eq!(v["case_id"], c.f.case_id);
        assert_eq!(v["session_id"], c.prepared["session_id"]);
        assert_eq!(v["run_id"], facts(&c.prepared)["provider_run_id"]);
        assert_eq!(v["task_id"], facts(&c.prepared)["provider_task_id"]);
        assert_ne!(v["run_id"], v["session_id"]);
        assert_eq!(v["observed_head_sha256"], c.head);
        assert_eq!(v["sha256"], hash(bytes));
        assert_eq!(v["byte_length"], bytes.len());
        assert_eq!(v["destination"], json!(dest));
        assert_eq!(v["retryable"], false);
        assert!(v["error_code"].is_null());
        assert_eq!(fs::read(&dest).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::metadata(&dest).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
    }
    drop(lease);
    assert_eq!(before, logical_database(&c.f));
    assert!(DataDirectoryExclusiveLease::acquire(&c.f.data).is_ok());
}
#[test]
fn selectors_discarded_outputs_and_caller_digest_mismatches_are_refused() {
    let mut c = Captured::new();
    let discarded = c.output(true);
    let before = logical_database(&c.f);
    for (i, args) in [
        vec!["--document", "unknown", "--revision", "1"],
        vec!["--document", "REPORT.md", "--revision", "99"],
        vec!["--document", "REPORT.md", "--revision", "0"],
        vec!["--document", "REPORT.md", "--revision", "bad"],
        vec!["--document", "REPORT.md"],
        vec!["--revision", "1"],
        vec![],
        vec!["--assignment-id", "missing"],
        vec!["--assignment-id", &discarded],
        vec![
            "--document",
            "REPORT.md",
            "--revision",
            "1",
            "--assignment-id",
            &discarded,
        ],
    ]
    .iter()
    .enumerate()
    {
        let dest = c.destination(&format!("refused-{i}"));
        let v = terminal(c.command(args, &dest).output().unwrap(), 2);
        assert_eq!(v["retryable"], false);
        assert!(!dest.exists());
    }
    let dest = c.destination("digest-mismatch");
    let v = terminal(
        c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
            .args(["--expected-sha256", &"0".repeat(64)])
            .output()
            .unwrap(),
        2,
    );
    assert_eq!(v["sha256"], hash(b"old report"));
    assert!(!dest.exists());
    assert_eq!(before, logical_database(&c.f));
}
#[test]
fn wrong_case_and_stale_head_are_distinguished() {
    let c = Captured::new();
    let mut other = AssessmentCase::new(
        "Other case".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "1-10".into(),
            data_classes: vec![],
            notes: None,
        },
    );
    c.f.storage()
        .save_case(&mut other, "fixture.other")
        .unwrap();
    let dest = c.destination("wrong-case");
    terminal(
        c.f.command()
            .args([
                "provider",
                "cloudflare",
                "retrieve-captured",
                "--case-id",
                &other.id,
                "--session-id",
                c.prepared["session_id"].as_str().unwrap(),
                "--document",
                "REPORT.md",
                "--revision",
                "1",
                "--destination",
            ])
            .arg(&dest)
            .output()
            .unwrap(),
        2,
    );
    let v = terminal(
        c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
            .args(["--expected-head-sha256", &"0".repeat(64)])
            .output()
            .unwrap(),
        3,
    );
    assert_eq!(v["observed_head_sha256"], c.head);
    assert_eq!(v["retryable"], true);
    assert!(!dest.exists());
}
#[test]
fn existing_linked_special_and_product_storage_destinations_are_refused() {
    let c = Captured::new();
    let selector = ["--document", "REPORT.md", "--revision", "1"];
    let existing = c.destination("existing");
    fs::write(&existing, b"preserve").unwrap();
    let directory = c.destination("directory");
    fs::create_dir(&directory).unwrap();
    let hardlink = c.destination("hardlink");
    fs::hard_link(&existing, &hardlink).unwrap();
    let paths = vec![
        existing.clone(),
        directory,
        hardlink,
        c.f.data.join("inside"),
    ];
    #[cfg(unix)]
    let paths = {
        let mut paths = paths;
        let symlink = c.destination("symlink");
        std::os::unix::fs::symlink(&existing, &symlink).unwrap();
        paths.push(symlink);
        let parent_link = c.destination("parent-link");
        std::os::unix::fs::symlink(&c.host, &parent_link).unwrap();
        paths.push(parent_link.join("file"));
        let fifo = c.destination("fifo");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        paths.push(fifo);
        paths
    };
    for path in paths {
        terminal(c.command(&selector, &path).output().unwrap(), 2);
    }
    assert_eq!(fs::read(existing).unwrap(), b"preserve");
    assert!(!c.f.data.join("inside").exists());
}

#[test]
fn missing_retrieve_parent_is_a_non_retryable_request_error() {
    let c = Captured::new();
    let destination = c.destination("missing").join("output");
    let result = terminal(
        c.command(
            &["--document", "REPORT.md", "--revision", "1"],
            &destination,
        )
        .output()
        .unwrap(),
        2,
    );
    assert_eq!(result["error_code"], "invalid_request");
    assert_eq!(result["retryable"], false);
    let message = result["error"].as_str().unwrap();
    assert!(message.contains("retrieve destination"), "{message}");
    assert!(!message.contains("case archive:"), "{message}");
    assert!(!destination.exists());
}
#[test]
fn committed_missing_corrupt_and_oversized_objects_fail_as_storage() {
    for kind in ["missing", "corrupt", "oversized", "descriptor"] {
        let c = Captured::new();
        let object = c.objects().join(hash(b"old report"));
        match kind {
            "missing" => fs::remove_file(object).unwrap(),
            "corrupt" => fs::write(object, b"bad report").unwrap(),
            "oversized" => fs::File::create(object)
                .unwrap()
                .set_len(9 * 1024 * 1024)
                .unwrap(),
            _ => fs::remove_file(c.objects().parent().unwrap().join("session.json")).unwrap(),
        }
        let dest = c.destination("failed");
        let v = terminal(
            c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
                .output()
                .unwrap(),
            4,
        );
        assert_eq!(v["error_code"], "storage_failed");
        assert!(!dest.exists());
    }
}
#[test]
fn stored_oversize_length_is_rejected_without_opening_an_object() {
    let c = Captured::new();
    let db = rusqlite::Connection::open(c.f.data.join("casework.db")).unwrap();
    let (id, payload): (i64, String) = db.query_row("SELECT sequence,payload_json FROM case_events WHERE event_type='cloudflare_audit.record_entry' ORDER BY sequence LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    let mut e: Entry = serde_json::from_str(&payload).unwrap();
    if let ai_security_scanner_lib::cloudflare_provider::audit::record::Content::SubmitDocuments {
        documents,
        ..
    } = &mut e.content
    {
        documents[0].byte_length = u64::MAX;
    }
    e.entry_sha256 = e.content_digest().unwrap();
    db.execute(
        "UPDATE case_events SET payload_json=?1 WHERE sequence=?2",
        rusqlite::params![serde_json::to_string(&e).unwrap(), id],
    )
    .unwrap();
    fs::remove_dir_all(c.objects()).unwrap();
    let dest = c.destination("oversize");
    terminal(
        c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
            .output()
            .unwrap(),
        4,
    );
    assert!(!dest.exists());
}
#[test]
fn snapshot_recheck_detects_a_concurrent_head_change() {
    let mut c = Captured::new();
    let storage = Storage::open_read_only_no_wait(c.f.data.join("casework.db")).unwrap();
    let snapshot = storage
        .cloudflare_captured_snapshot(&c.f.case_id, c.prepared["session_id"].as_str().unwrap())
        .unwrap();
    snapshot.recheck(&storage).unwrap();
    c.action(json!({"type":"submit_documents","documents":[{"name":"REPORT.md"}]}));
    let error = snapshot.recheck(&storage).unwrap_err();
    assert_eq!(
        ai_security_scanner_lib::error::foreground_error_class(&error).0,
        3
    );
}
#[test]
fn busy_database_returns_conflict_without_retry() {
    let c = Captured::new();
    let dest = c.destination("busy");
    let db = rusqlite::Connection::open(c.f.data.join("casework.db")).unwrap();
    db.execute_batch(
        "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE;",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let v = terminal(
        c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
            .output()
            .unwrap(),
        3,
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(v["error_code"], "data_directory_busy");
    assert!(!dest.exists());
    db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn abandoned_audit_retrieval_needs_no_current_authority() {
    let mut c = Captured::new();
    let issued =
        c.action(json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}));
    c.action(json!({"type":"interrupt","assignment_id":issued["result"]["entry"]["content"]["assignments"][0]["assignment_id"],"reason":"host abandoned work"}));
    c.f.change_case(|case| case.scope_grants.clear());
    fs::remove_dir_all(&c.host).unwrap();
    let before = logical_database(&c.f);
    let dest = c.destination("abandoned-copy");
    terminal(
        c.command(&["--document", "REPORT.md", "--revision", "1"], &dest)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(fs::read(dest).unwrap(), b"old report");
    assert_eq!(before, logical_database(&c.f));
}

#[test]
fn sealed_audit_retrieval_keeps_original_provider_identities() {
    let run = RunFixture::new("quick");
    let request = super::finalize::request(&run);
    super::finalize::finalize(&run, &request, 0);
    fs::remove_dir_all(&run.host).unwrap();
    let before = logical_database(&run.f);
    let dest = run.f.data.with_file_name("sealed-copy");
    let v = terminal(
        run.f
            .command()
            .args([
                "provider",
                "cloudflare",
                "retrieve-captured",
                "--case-id",
                &run.f.case_id,
                "--session-id",
                run.prepared["session_id"].as_str().unwrap(),
                "--document",
                "REPORT.md",
                "--revision",
                "1",
                "--destination",
            ])
            .arg(&dest)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(v["run_id"], facts(&run.prepared)["provider_run_id"]);
    assert_eq!(v["task_id"], facts(&run.prepared)["provider_task_id"]);
    assert_eq!(fs::read(dest).unwrap(), b"# Synthetic audit\n");
    let status = run.f.audit_status("audit-one", false, 0);
    let unselected = &status["result"]["assignments"][0];
    let manifest: Value = serde_json::from_slice(
        &fs::read(
            super::finalize::path(&run, &request).join("retained/bundle/provider-manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        !manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == unselected["output"]["path"])
    );
    let storage = Storage::open_read_only_no_wait(run.f.data.join("casework.db")).unwrap();
    let snapshot = storage
        .cloudflare_captured_snapshot(&run.f.case_id, run.prepared["session_id"].as_str().unwrap())
        .unwrap();
    assert!(
        captured::enumerate(&snapshot.record)
            .unwrap()
            .iter()
            .any(|e| e.available
                && e.selector
                    == captured::Selector::Assignment {
                        assignment_id: unselected["assignment_id"].as_str().unwrap().into()
                    })
    );
    let output = run.f.data.with_file_name("unselected-copy");
    terminal(
        run.f
            .command()
            .args([
                "provider",
                "cloudflare",
                "retrieve-captured",
                "--case-id",
                &run.f.case_id,
                "--session-id",
                run.prepared["session_id"].as_str().unwrap(),
                "--assignment-id",
                unselected["assignment_id"].as_str().unwrap(),
                "--destination",
            ])
            .arg(&output)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(fs::read(output).unwrap(), b"Synthetic source map");
    assert_eq!(before, logical_database(&run.f));
}

#[test]
fn explicit_existing_data_directory_is_required_without_initialization() {
    let root = crate::test_temp::tempdir().unwrap();
    writable(root.path());
    let data = root.path().join("absent-data");
    let dest = root.path().join("out");
    let args = [
        "--json",
        "provider",
        "cloudflare",
        "retrieve-captured",
        "--case-id",
        "case",
        "--session-id",
        "audit",
        "--document",
        "REPORT.md",
        "--revision",
        "1",
        "--destination",
    ];
    terminal(
        Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"))
            .args(args)
            .arg(&dest)
            .output()
            .unwrap(),
        2,
    );
    terminal(
        Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"))
            .arg("--data-dir")
            .arg(&data)
            .args(args)
            .arg(&dest)
            .output()
            .unwrap(),
        4,
    );
    assert!(!data.exists());
    assert!(!dest.exists());
}
