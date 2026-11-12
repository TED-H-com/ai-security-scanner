//! Unix subprocess coverage for foreground ownership. The executable named
//! docker below is a private fixture, never a container service or scanner.
#![cfg(all(feature = "cli", unix))]

#[allow(dead_code)]
#[path = "../src/test_temp.rs"]
mod test_temp;

use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::{ArtifactContext, ArtifactStore};
use ai_security_scanner_lib::case_service::{CaseService, ScanPlanRequest, ScopeApprovalRequest};
use ai_security_scanner_lib::container_runtime::{RuntimeCommandProvenance, RuntimeProvider};
use ai_security_scanner_lib::domain::{
    AssessmentCase, CaseStatus, EngineRunStatus, OrganizationProfile, ScanPermission, new_id,
};
use ai_security_scanner_lib::orchestrator::{ExecutionCheckpoint, ExecutionStage};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::storage::{ScanCommandReceipt, Storage};
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, create_workspace_snapshot_with_profile,
};
use chrono::Utc;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FAKE_DOCKER: &str = r#"#!/usr/bin/python3
import hashlib, json, os, pathlib, sys, time
root = pathlib.Path(__file__).parent
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\n')
mode = (root / 'mode').read_text().strip()
if mode == 'deny':
    print('fixture forbids every runtime operation', file=sys.stderr)
    sys.exit(91)
if args[0] == 'version':
    print('99.0.0-offline-fixture')
elif args[0] == 'info':
    security = ['name=seccomp,profile=builtin', 'name=rootless']
    print(json.dumps({'serverVersion':'99.0.0-offline-fixture','securityOptions':security}
                    if 'serverVersion' in args[-1] else security))
elif args[:2] == ['image', 'inspect']:
    print('[]')
elif args[0] == 'run':
    def option(name): return args[args.index(name) + 1]
    labels = dict(args[i + 1].split('=', 1) for i, value in enumerate(args) if value == '--label')
    mounts = [dict(piece.split('=',1) for piece in args[i + 1].split(',') if '=' in piece)
              for i, value in enumerate(args) if value == '--mount']
    output = pathlib.Path(next(m.get('src',m.get('source')) for m in mounts
                               if m.get('dst',m.get('target',m.get('destination'))) == '/output'))
    name = option('--name')
    identity = hashlib.sha256(name.encode()).hexdigest()
    image = next(value for value in args if '@sha256:' in value)
    state = {'Id':identity,'Name':name,'Config':{'Image':image,'Labels':labels}}
    state_file = root / (identity + '.json')
    state_file.write_text(json.dumps(state))
    pathlib.Path(option('--cidfile')).write_text(identity + '\n')
    (root / 'running.json').write_text(json.dumps({'pid':os.getpid(),'id':identity,'name':name}))
    if mode == 'block':
        deadline = time.monotonic() + 20
        while not (root / 'release').exists() and not (root / (identity + '.stopped')).exists():
            if time.monotonic() > deadline:
                print('fixture watchdog expired', file=sys.stderr)
                sys.exit(92)
            time.sleep(0.01)
    if labels['ai.security-scanner.engine'] == 'semgrep':
        print('synthetic scanner failure', file=sys.stderr)
        sys.exit(9)
    (output / 'gitleaks.json').write_bytes((root / 'gitleaks.json').read_bytes())
    print('offline fixture output captured')
elif args[:2] == ['container', 'inspect']:
    query = args[-1]
    states = [json.loads(path.read_text()) for path in root.glob('*.json') if len(path.stem) == 64]
    selected = [state for state in states if query in (state['Id'], state['Name'])]
    if len(selected) != 1:
        print('No such container', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(selected))
elif args[0] in ('stop', 'rm'):
    identity = args[-1]
    if len(identity) != 64:
        print('fixture refuses control by mutable name', file=sys.stderr)
        sys.exit(93)
    (root / (identity + '.stopped')).write_text('stopped')
    if args[0] == 'rm':
        (root / (identity + '.json')).unlink(missing_ok=True)
else:
    print('unexpected fixture runtime operation: ' + repr(args), file=sys.stderr)
    sys.exit(94)
"#;

struct Fixture {
    _root: test_temp::TempDir,
    data: PathBuf,
    binary_directory: PathBuf,
    case_id: String,
    asset_id: String,
}

impl Fixture {
    fn new(approved: bool, runtime_mode: &str) -> Self {
        let root = test_temp::tempdir().unwrap();
        let data = root.path().join("data");
        let artifacts = data.join("artifacts");
        let binary_directory = root.path().join("fake-runtime");
        fs::create_dir_all(&artifacts).unwrap();
        fs::create_dir(&binary_directory).unwrap();
        fs::write(binary_directory.join("docker"), FAKE_DOCKER).unwrap();
        fs::set_permissions(
            binary_directory.join("docker"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(binary_directory.join("mode"), runtime_mode).unwrap();
        let storage = Storage::open(data.join("casework.db")).unwrap();
        let mut case = AssessmentCase::new(
            "Foreground subprocess fixture".into(),
            OrganizationProfile {
                organization_name: "Synthetic fixture only".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        storage.save_case(&mut case, "fixture.created").unwrap();
        let engines = EngineRegistry::load_builtin().unwrap();
        let adapters = builtin_adapter_registry().unwrap();
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            &artifacts,
            data.join("signing.key"),
        );
        let source = root.path().join("selected-repository");
        fs::create_dir_all(source.join("config")).unwrap();
        fs::write(
            source.join("config/example.env"),
            b"# inert synthetic fixture\n",
        )
        .unwrap();
        let snapshot = create_workspace_snapshot_with_profile(
            &artifacts,
            &case.id,
            &new_id(),
            &source,
            WorkspaceInputProfile::RepositoryWorkingTree,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        let asset_id = snapshot.asset.id.clone();
        service
            .attach_workspace_snapshot(&case.id, "Inert local repository", snapshot)
            .unwrap();
        if approved {
            service
                .approve_scope(
                    &case.id,
                    ScopeApprovalRequest {
                        asset_id: asset_id.clone(),
                        permissions: vec![ScanPermission::LocalArtifactRead],
                        confirmed_by: "Fixture owner".into(),
                        expires_at: None,
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    },
                )
                .unwrap();
        }
        let mut raw: Value =
            serde_json::from_slice(include_bytes!("fixtures/adapters/gitleaks.json")).unwrap();
        raw[0]["asset_id"] = json!(asset_id);
        fs::write(
            binary_directory.join("gitleaks.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        Self {
            _root: root,
            data,
            binary_directory,
            case_id: case.id,
            asset_id,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
        command.arg("--data-dir").arg(&self.data);
        command.env("PATH", &self.binary_directory);
        command.env_remove("AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE");
        command.env_remove("AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY");
        command
    }

    fn run_command(&self, json_output: bool, engines: &str) -> Command {
        let mut command = self.command();
        if json_output {
            command.arg("--json");
        }
        command.args([
            "scan",
            "run",
            "--case-id",
            &self.case_id,
            "--wait",
            "--engine",
            engines,
        ]);
        command
    }

    fn case(&self) -> AssessmentCase {
        Storage::open_read_only(self.data.join("casework.db"))
            .unwrap()
            .get_case(&self.case_id)
            .unwrap()
    }

    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.binary_directory.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn receipt(&self, run_id: &str) -> ScanCommandReceipt {
        let storage = Storage::open_read_only(self.data.join("casework.db")).unwrap();
        let receipts = storage
            .scan_command_receipts(&self.case_id, Some(run_id))
            .unwrap();
        assert_eq!(
            receipts.len(),
            1,
            "each invocation saves exactly one terminal acknowledgement"
        );
        receipts.into_iter().next().unwrap()
    }

    fn assert_saved_terminal(&self, terminal: &Value) -> ScanCommandReceipt {
        assert_eq!(
            terminal["schema_version"],
            "ai-security-scanner.scan-command/v1"
        );
        assert_eq!(terminal["type"], "terminal");
        assert_eq!(terminal["case_id"], self.case_id);
        let receipt = self.receipt(terminal["run_id"].as_str().unwrap());
        assert_eq!(terminal["receipt"], serde_json::to_value(&receipt).unwrap());
        assert_eq!(terminal["case_revision"], receipt.case_revision);
        let output = self
            .command()
            .args([
                "--json",
                "scan",
                "status",
                "--case-id",
                &self.case_id,
                "--run-id",
                &receipt.run_id,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["command_receipts"], json!([receipt]));
        let case = self.case();
        let run = case
            .scan_runs
            .iter()
            .find(|run| run.id == receipt.run_id)
            .unwrap();
        assert_eq!(
            status["run_report_snapshots"],
            json!(case.run_report_snapshots)
        );
        if ai_security_scanner_lib::report_snapshot::terminal_snapshot_ready(run) {
            let record =
                ai_security_scanner_lib::report_snapshot::current_run_snapshot(&case, &run.id)
                    .unwrap()
                    .expect("terminal run retained its original report before acknowledgement");
            assert_eq!(terminal["result"]["report_snapshot"], json!(record));
            let path = self
                .data
                .join("artifacts")
                .join(&record.snapshot.relative_path);
            let snapshot =
                ai_security_scanner_lib::report_snapshot::ReportSnapshot::load(&path).unwrap();
            let inspection = snapshot.verify().unwrap();
            assert_eq!(inspection.run_id, run.id);
            assert_eq!(inspection.attachment_count, 0);
            assert_eq!(inspection.locale, "en");
            assert_eq!(inspection.redaction, "standard");
        } else {
            assert!(
                case.run_report_snapshots.is_empty(),
                "unfinished recovery must stay in Progress"
            );
        }
        let _lease = DataDirectoryExclusiveLease::acquire(&self.data)
            .expect("foreground released writer ownership");
        receipt
    }

    fn captured_run(&self) -> (String, PathBuf) {
        let storage = Storage::open(self.data.join("casework.db")).unwrap();
        let engines = EngineRegistry::load_builtin().unwrap();
        let adapters = builtin_adapter_registry().unwrap();
        let artifacts = self.data.join("artifacts");
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            &artifacts,
            self.data.join("signing.key"),
        );
        let plan = service
            .plan_scan(
                &self.case_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                    ..ScanPlanRequest::default()
                },
            )
            .unwrap();
        let execution = &plan.executable[0];
        let context = ArtifactContext {
            case_id: self.case_id.clone(),
            scan_run_id: plan.scan_run.id.clone(),
            engine_run_id: execution.engine_run_id.clone(),
        };
        let store = ArtifactStore::open(&artifacts).unwrap();
        let directories = store.prepare_run(&context, execution.attempt).unwrap();
        let output = directories.output.join("gitleaks.json");
        fs::copy(self.binary_directory.join("gitleaks.json"), &output).unwrap();
        let artifact = store
            .describe_file(&context, &output, "application/json", true)
            .unwrap();
        let mut case = storage.get_case(&self.case_id).unwrap();
        let run = case
            .scan_runs
            .iter_mut()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        let task = run
            .engine_runs
            .iter_mut()
            .find(|task| task.id == execution.engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(task.resume_token.as_deref().unwrap()).unwrap();
        checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
        checkpoint.artifact_ids = vec![artifact.id.clone()];
        checkpoint.cleanup_completed = true;
        checkpoint.runtime_provider = Some(RuntimeProvider::Docker);
        checkpoint.runtime_command_provenance = Some(RuntimeCommandProvenance::Compatibility);
        task.status = EngineRunStatus::PartiallyCompleted;
        task.phase = "captured_awaiting_adapter".into();
        task.progress_percent = 85;
        task.raw_artifact_ids = vec![artifact.id.clone()];
        task.resume_token = Some(checkpoint.resume_token().unwrap());
        run.completed_at = Some(Utc::now());
        case.status = CaseStatus::NeedsAttention;
        case.raw_artifacts.push(artifact);
        storage.save_case(&mut case, "fixture.captured").unwrap();
        (plan.scan_run.id, output)
    }
}

struct Running {
    child: Option<Child>,
    unread_stdout: Option<ChildStdout>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

fn read_pipe(mut reader: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

fn make_fixture_directories_removable(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    if metadata.is_dir() {
        // Production snapshots are intentionally read-only. Restore write
        // permission only on this test's private copy so it can be removed.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(path).unwrap() {
            make_fixture_directories_removable(&entry.unwrap().path());
        }
    }
}

impl Running {
    fn spawn(mut command: Command, read_stdout: bool) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pipe = child.stdout.take().unwrap();
        let (stdout, unread_stdout) = if read_stdout {
            (Some(read_pipe(pipe)), None)
        } else {
            (None, Some(pipe))
        };
        let stderr = Some(read_pipe(child.stderr.take().unwrap()));
        Self {
            child: Some(child),
            unread_stdout,
            stdout,
            stderr,
        }
    }

    fn await_runtime(&mut self, fixture: &Fixture) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(bytes) = fs::read(fixture.binary_directory.join("running.json"))
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                return value;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "CLI exited before reaching the controlled runtime; calls: {:?}",
                fixture.calls()
            );
            assert!(
                Instant::now() < deadline,
                "runtime never started; calls: {:?}",
                fixture.calls()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "foreground did not exit within its test deadline"
            );
            thread::sleep(Duration::from_millis(10));
        };
        self.child.take();
        drop(self.unread_stdout.take());
        Output {
            status,
            stdout: self
                .stdout
                .take()
                .map(|reader| reader.join().unwrap())
                .unwrap_or_default(),
            stderr: self.stderr.take().unwrap().join().unwrap(),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn terminal(output: &Output, exit_code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let documents = String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("stdout contains JSON records only"))
        .collect::<Vec<_>>();
    let terminals = documents
        .iter()
        .filter(|document| document["type"] == "terminal")
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 1, "one final acknowledgement per command");
    assert_eq!(terminals[0]["exit_code"], exit_code);
    terminals[0].clone()
}

#[test]
fn unapproved_repository_finishes_without_runtime_contact_or_invented_authority() {
    let fixture = Fixture::new(false, "deny");
    let output = Running::spawn(fixture.run_command(true, "gitleaks"), true).wait();
    let result = terminal(&output, 0);
    fixture.assert_saved_terminal(&result);
    let case = fixture.case();
    assert_eq!(case.scan_runs.len(), 1);
    assert!(case.scan_runs[0].completed_at.is_some());
    assert!(case.scan_runs[0].engine_runs.is_empty());
    let request_outcome = serde_json::to_value(&case.scan_runs[0].request_outcome).unwrap();
    assert_eq!(request_outcome["status"], "no_checks_completed");
    assert_eq!(request_outcome["code"], "no_effective_scope_grants");
    assert_eq!(result["result"]["request_outcome"], request_outcome);
    assert!(case.scope_grants.is_empty());
    assert!(case.findings.is_empty());
    assert_eq!(result["result"]["finding_count"], 0);
    assert!(fixture.calls().is_empty());
}

#[test]
fn live_owner_blocks_normal_writes_while_status_preserves_saved_truth() {
    let fixture = Fixture::new(true, "deny");
    let owner = DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
    let before = fixture.case();
    let storage = Storage::open_read_only(fixture.data.join("casework.db")).unwrap();
    let events = storage.list_case_events(&fixture.case_id).unwrap();
    assert!(
        fixture.case().run_report_snapshots.is_empty(),
        "live scan must not save an interim report"
    );
    let id = fixture.case_id.as_str();
    let commands = vec![
        vec!["case", "create", "--title", "must-not-create"],
        vec!["case", "select", id],
        vec!["case", "archive", id],
        vec!["case", "delete", id, "--confirm-case-id", id],
        vec![
            "source",
            "upsert",
            "--case-id",
            id,
            "--kind",
            "user-declared",
            "--label",
            "must-not-create",
        ],
        vec![
            "scope",
            "approve",
            "--case-id",
            id,
            "--asset-id",
            &fixture.asset_id,
            "--permission",
            "local-artifact-read",
            "--confirmed-by",
            "Fixture owner",
        ],
        vec![
            "finding",
            "update",
            "--case-id",
            id,
            "--finding-id",
            "missing-finding",
            "--status",
            "confirmed",
            "--decided-by",
            "Fixture owner",
            "--reason",
            "must-not-write",
        ],
        vec!["scan", "plan", "--case-id", id, "--engine", "gitleaks"],
        vec![
            "scan",
            "rescan-plan",
            "--case-id",
            id,
            "--baseline-run-id",
            "missing-run",
            "--engine",
            "gitleaks",
        ],
        vec!["scan", "cancel", "--case-id", id, "--run-id", "missing-run"],
        vec![
            "scan",
            "run",
            "--case-id",
            id,
            "--wait",
            "--engine",
            "gitleaks",
        ],
        vec![
            "scan",
            "recover",
            "--case-id",
            id,
            "--run-id",
            "missing-run",
            "--wait",
        ],
    ];
    for args in commands {
        let expected_exit = if args[0] == "scan" && matches!(args[1], "run" | "recover") {
            3
        } else {
            // The established non-foreground CLI retains its generic error
            // exit code; the typed foreground busy contract uses exit 3.
            1
        };
        let output = fixture
            .command()
            .args(["--json"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "writer {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::to_value(fixture.case()).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(fixture.case().storage_revision(), before.storage_revision());
        assert_eq!(storage.list_case_events(id).unwrap(), events);
    }
    let output = fixture
        .command()
        .args(["--json", "scan", "status", "--case-id", id])
        .output()
        .unwrap();
    assert!(output.status.success());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["case_id"], id);
    assert_eq!(status["command_receipts"], json!([]));
    assert!(fixture.calls().is_empty());
    drop(owner);
}

#[test]
fn foreground_persists_real_adapter_finding_and_failed_sibling_before_returning() {
    let fixture = Fixture::new(true, "complete");
    let output = Running::spawn(fixture.run_command(true, "gitleaks,semgrep"), true).wait();
    let result = terminal(&output, 0);
    fixture.assert_saved_terminal(&result);
    let case = fixture.case();
    let run = case.scan_runs.last().unwrap();
    assert!(run.completed_at.is_some());
    assert_eq!(
        run.engine_runs
            .iter()
            .find(|task| task.engine_id == "gitleaks")
            .unwrap()
            .status,
        EngineRunStatus::Completed
    );
    assert_eq!(
        run.engine_runs
            .iter()
            .find(|task| task.engine_id == "semgrep")
            .unwrap()
            .status,
        EngineRunStatus::Failed
    );
    assert!(
        !case.findings.is_empty(),
        "actual Gitleaks adapter must parse the saved fixture"
    );
    assert_eq!(result["result"]["finding_count"], case.findings.len());
    assert!(!case.raw_artifacts.is_empty());
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|call| call[0] == "run")
            .count(),
        2
    );
    assert!(!fixture.calls().iter().any(|call| call[0] == "pull"));
}

fn assert_cancelled_owner(fixture: &Fixture, runtime: &Value, result: &Value) {
    fixture.assert_saved_terminal(result);
    assert_eq!(result["command_outcome"], "interrupted");
    let case = fixture.case();
    assert!(case.scan_runs[0].completed_at.is_some());
    assert_eq!(
        case.scan_runs[0].engine_runs[0].status,
        EngineRunStatus::Cancelled
    );
    let calls = fixture.calls();
    assert!(
        calls.iter().any(
            |call| call[0] == "stop" && call.as_array().unwrap().last() == Some(&runtime["id"])
        )
    );
    assert!(
        calls
            .iter()
            .any(|call| call[0] == "rm" && call.as_array().unwrap().last() == Some(&runtime["id"]))
    );
    let checkpoint = ExecutionCheckpoint::from_resume_token(
        case.scan_runs[0].engine_runs[0]
            .resume_token
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(checkpoint.cleanup_completed);
    assert_eq!(
        unsafe { libc::kill(runtime["pid"].as_i64().unwrap() as libc::pid_t, 0) },
        -1,
        "the controlled runtime process must be reaped before CLI exit"
    );
}

#[test]
fn sigint_and_sigterm_wait_for_exact_cancellation_cleanup_and_saved_receipt() {
    for (signal, expected_exit) in [(libc::SIGINT, 130), (libc::SIGTERM, 143)] {
        let fixture = Fixture::new(true, "block");
        let mut process = Running::spawn(fixture.run_command(false, "gitleaks"), true);
        let runtime = process.await_runtime(&fixture);
        let pid = process.child.as_ref().unwrap().id();
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, signal) }, 0);
        let output = process.wait();
        let result = terminal(&output, expected_exit);
        assert_cancelled_owner(&fixture, &runtime, &result);
    }
}

#[test]
fn parent_pipe_cancels_on_request_or_eof_after_preserving_cleanup_and_receipt() {
    for (control, expected_exit) in [("cancel\n", 130), ("terminate\n", 143), ("", 130)] {
        let fixture = Fixture::new(true, "block");
        let mut command = fixture.run_command(false, "gitleaks");
        command
            .arg("--bootstrap-control-stdin")
            .stdin(Stdio::piped());
        let mut process = Running::spawn(command, true);
        let runtime = process.await_runtime(&fixture);
        let mut pipe = process.child.as_mut().unwrap().stdin.take().unwrap();
        pipe.write_all(control.as_bytes()).unwrap();
        drop(pipe);
        let result = terminal(&process.wait(), expected_exit);
        assert_cancelled_owner(&fixture, &runtime, &result);
    }
}

#[test]
fn malformed_parent_control_saves_failure_and_still_cleans_owned_resources() {
    for control in ["execute shell\n", "xxxxxxxxxxxxxxxxx"] {
        let fixture = Fixture::new(true, "block");
        let mut command = fixture.run_command(true, "gitleaks");
        command
            .arg("--bootstrap-control-stdin")
            .stdin(Stdio::piped());
        let mut process = Running::spawn(command, true);
        let runtime = process.await_runtime(&fixture);
        let mut pipe = process.child.as_mut().unwrap().stdin.take().unwrap();
        pipe.write_all(control.as_bytes()).unwrap();
        // Keep the pipe open: malformed and overlong messages must not wait for EOF.
        let result = terminal(&process.wait(), 4);
        fixture.assert_saved_terminal(&result);
        assert_eq!(result["command_outcome"], "failed");
        assert_eq!(result["error_code"], "cancellation_control_failed");
        assert_eq!(
            fixture.case().scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Cancelled
        );
        assert!(
            fixture
                .calls()
                .iter()
                .any(|call| call[0] == "rm"
                    && call.as_array().unwrap().last() == Some(&runtime["id"]))
        );
    }
}

#[test]
fn open_parent_control_does_not_delay_normal_completion() {
    let fixture = Fixture::new(true, "complete");
    let mut command = fixture.run_command(true, "gitleaks");
    command
        .arg("--bootstrap-control-stdin")
        .stdin(Stdio::piped());
    let mut process = Running::spawn(command, true);
    let _pipe = process.child.as_mut().unwrap().stdin.take().unwrap();
    let result = terminal(&process.wait(), 0);
    fixture.assert_saved_terminal(&result);
    assert_eq!(result["command_outcome"], "completed");
    assert_eq!(fixture.case().findings.len(), 1);
}

#[test]
fn bootstrap_process_cancellation_and_parent_death_settle_the_actual_cli_owner() {
    let node = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file())
        .expect("bootstrap integration requires Node.js");
    let bootstrap =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/skill/bootstrap-core.mjs");
    for (signal, code) in [
        (libc::SIGINT, 130),
        (libc::SIGTERM, 143),
        (libc::SIGKILL, 130),
    ] {
        let fixture = Fixture::new(true, "block");
        let cli = fixture.run_command(false, "gitleaks");
        let mut command = Command::new(&node);
        command.args(["--input-type=module", "-e", r#"
            import { pathToFileURL } from 'node:url';
            const [module, executable, ...argv] = process.argv.slice(1);
            const { invokeCoreCommand, preparedCommandArguments } = await import(pathToFileURL(module));
            const { args, parentControl } = preparedCommandArguments(argv);
            process.exitCode = await invokeCoreCommand(executable, args, { parentControl });
        "#]);
        command
            .arg(&bootstrap)
            .arg(cli.get_program())
            .args(cli.get_args());
        for (key, value) in cli.get_envs() {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        let mut process = Running::spawn(command, true);
        let runtime = process.await_runtime(&fixture);
        let pid = process.child.as_ref().unwrap().id();
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, signal) }, 0);
        let output = process.wait();
        let result = if signal == libc::SIGKILL {
            // The killed parent cannot acknowledge an exit code. Its child's
            // inherited output pipe closes only after cleanup and persistence.
            let documents = String::from_utf8(output.stdout).unwrap();
            let terminals = documents
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|value| value["type"] == "terminal")
                .collect::<Vec<_>>();
            assert_eq!(terminals.len(), 1);
            assert_eq!(terminals[0]["exit_code"], code);
            terminals.into_iter().next().unwrap()
        } else {
            terminal(&output, code)
        };
        assert_cancelled_owner(&fixture, &runtime, &result);
    }
}

#[test]
fn broken_stdout_still_saves_terminal_outcome_and_releases_execution_ownership() {
    for json_only in [false, true] {
        let fixture = Fixture::new(true, "block");
        let mut process = Running::spawn(fixture.run_command(json_only, "gitleaks"), false);
        let runtime = process.await_runtime(&fixture);
        drop(process.unread_stdout.take());
        fs::write(fixture.binary_directory.join("release"), b"release").unwrap();
        let output = process.wait();
        assert_eq!(
            output.status.code(),
            Some(4),
            "json_only={json_only}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let case = fixture.case();
        let run = case.scan_runs.last().unwrap();
        assert!(run.completed_at.is_some());
        assert!(run.engine_runs.iter().all(|task| !matches!(
            task.status,
            EngineRunStatus::Queued
                | EngineRunStatus::Preparing
                | EngineRunStatus::Running
                | EngineRunStatus::Paused
        )));
        let receipt = fixture.receipt(&run.id);
        assert_eq!(receipt.case_revision, case.storage_revision());
        if json_only {
            // No progress records touch stdout in --json mode. The first
            // failed write is the final acknowledgement, AFTER its immutable
            // receipt and completed findings have already been committed.
            assert_eq!(receipt.payload["exit_code"], 0);
            assert_eq!(receipt.payload["command_outcome"], "completed");
            assert!(receipt.payload["error_code"].is_null());
            assert_eq!(run.engine_runs[0].status, EngineRunStatus::Completed);
            assert!(!case.findings.is_empty());
            assert_eq!(
                receipt.payload["result"]["finding_count"],
                case.findings.len()
            );
        } else {
            // NDJSON detects the broken pipe during execution, so its saved
            // command result records the failed output channel.
            assert_eq!(receipt.payload["exit_code"], 4);
            assert_eq!(receipt.payload["command_outcome"], "failed");
            assert_eq!(receipt.payload["error_code"], "output_failed");
        }
        let calls = fixture.calls();
        assert!(
            calls
                .iter()
                .any(|call| call[0] == "rm"
                    && call.as_array().unwrap().last() == Some(&runtime["id"]))
        );
        let checkpoint = ExecutionCheckpoint::from_resume_token(
            run.engine_runs[0].resume_token.as_deref().unwrap(),
        )
        .unwrap();
        assert!(checkpoint.cleanup_completed);
        assert_eq!(
            unsafe { libc::kill(runtime["pid"].as_i64().unwrap() as libc::pid_t, 0) },
            -1,
            "final delivery failure must not leave a runtime process alive"
        );
        let status_output = fixture
            .command()
            .args([
                "--json",
                "scan",
                "status",
                "--case-id",
                &fixture.case_id,
                "--run-id",
                &run.id,
            ])
            .output()
            .unwrap();
        assert!(status_output.status.success());
        let status: Value = serde_json::from_slice(&status_output.stdout).unwrap();
        assert_eq!(status["command_receipts"], json!([receipt]));
        let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data)
            .expect("delivery failure must not retain execution ownership");
    }
}

#[test]
fn open_unread_stdout_cannot_keep_scan_ownership_or_a_runtime_alive() {
    let fixture = Fixture::new(true, "block");
    // Unknown engine identifiers produce bounded, terminal NotExecuted tasks.
    // Their event payload fills the stdout pipe without any extra executions.
    // Each identifier stays below the planner's 200-character input bound, and
    // the single --engine argument stays below Linux's per-argument byte bound.
    let engines = std::iter::once("gitleaks".to_owned())
        .chain((0..255).map(|index| format!("fixture-missing-{index:03}-{}", "x".repeat(160))))
        .collect::<Vec<_>>()
        .join(",");
    let started = Instant::now();
    let process = Running::spawn(fixture.run_command(false, &engines), false);
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let pipe = process.unread_stdout.as_ref().unwrap().as_raw_fd();
        // A child already writing may make shrinking return EBUSY. Its existing
        // capacity must still be below the intentionally oversized event.
        unsafe { libc::fcntl(pipe, libc::F_SETPIPE_SZ, 4096) };
        let capacity = unsafe { libc::fcntl(pipe, libc::F_GETPIPE_SZ) };
        assert!(capacity > 0 && capacity <= 65_536);
    }
    // Keep the read end open until AFTER process exit. Closing it would test
    // EPIPE instead of the permanently blocked write this test exercises.
    let output = process.wait();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the CLI must not depend on the fake runtime's 20-second watchdog"
    );
    let case = fixture.case();
    assert_eq!(case.scan_runs.len(), 1);
    let run = &case.scan_runs[0];
    assert!(run.completed_at.is_some());
    assert_eq!(run.engine_runs.len(), 256);
    assert!(run.engine_runs.iter().all(|task| !matches!(
        task.status,
        EngineRunStatus::Queued
            | EngineRunStatus::Preparing
            | EngineRunStatus::Running
            | EngineRunStatus::Paused
    )));
    let receipt = fixture.receipt(&run.id);
    assert_eq!(receipt.case_revision, case.storage_revision());
    assert_eq!(receipt.payload["exit_code"], 4);
    assert_eq!(receipt.payload["command_outcome"], "failed");
    assert_eq!(receipt.payload["error_code"], "output_failed");
    let calls = fixture.calls();
    assert!(!calls.iter().any(|call| call[0] == "pull"));
    assert!(calls.iter().filter(|call| call[0] == "run").count() <= 1);
    // Output can fail during preflight, before the controlled runtime starts.
    // When it does start, require exact cleanup and process reaping as well.
    if let Ok(bytes) = fs::read(fixture.binary_directory.join("running.json")) {
        let runtime: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(calls.iter().any(
            |call| call[0] == "stop" && call.as_array().unwrap().last() == Some(&runtime["id"])
        ));
        assert!(
            calls
                .iter()
                .any(|call| call[0] == "rm"
                    && call.as_array().unwrap().last() == Some(&runtime["id"]))
        );
        assert_eq!(
            unsafe { libc::kill(runtime["pid"].as_i64().unwrap() as libc::pid_t, 0) },
            -1,
            "blocked stdout must not leave the controlled runtime process alive"
        );
    }
    let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data)
        .expect("blocked stdout must not retain writer ownership");
}

#[test]
fn captured_recovery_parses_retained_evidence_without_runtime_or_source_access() {
    for interrupted_while_running in [false, true] {
        let fixture = Fixture::new(true, "deny");
        let (run_id, raw_path) = fixture.captured_run();
        if interrupted_while_running {
            // Model a process loss after capture/cleanup but before the parser
            // worker saved its terminal status. Its checkpoint is already a
            // safe host-only handoff even though the task still says Running.
            let storage = Storage::open(fixture.data.join("casework.db")).unwrap();
            let mut case = storage.get_case(&fixture.case_id).unwrap();
            let run = &mut case.scan_runs[0];
            run.completed_at = None;
            let task = &mut run.engine_runs[0];
            task.status = EngineRunStatus::Running;
            task.started_at = Some(Utc::now());
            task.finished_at = None;
            case.status = CaseStatus::Scanning;
            storage
                .save_case(&mut case, "fixture.interrupted_capture")
                .unwrap();
        }
        let before = fixture.case();
        let original_task = &before.scan_runs[0].engine_runs[0];
        let original_checkpoint =
            ExecutionCheckpoint::from_resume_token(original_task.resume_token.as_deref().unwrap())
                .unwrap();
        let raw_bytes = fs::read(&raw_path).unwrap();
        // Remove the original workspace and its preserved source tree. Both
        // terminal partial and interrupted Running tasks must use only evidence.
        fs::remove_dir_all(fixture._root.path().join("selected-repository")).unwrap();
        let snapshots = fixture
            .data
            .join("artifacts")
            .join(&fixture.case_id)
            .join("workspace-snapshots");
        make_fixture_directories_removable(&snapshots);
        fs::remove_dir_all(snapshots).unwrap();
        let mut command = fixture.command();
        command.args([
            "--json",
            "scan",
            "recover",
            "--case-id",
            &fixture.case_id,
            "--run-id",
            &run_id,
            "--wait",
        ]);
        let output = Running::spawn(command, true).wait();
        let result = terminal(&output, 0);
        fixture.assert_saved_terminal(&result);
        let case = fixture.case();
        assert_eq!(case.scan_runs.len(), 1);
        assert_eq!(case.scan_runs[0].id, run_id);
        let task = &case.scan_runs[0].engine_runs[0];
        assert_eq!(task.id, original_task.id);
        assert_eq!(task.status, EngineRunStatus::Completed);
        let recovered_checkpoint =
            ExecutionCheckpoint::from_resume_token(task.resume_token.as_deref().unwrap()).unwrap();
        assert_eq!(recovered_checkpoint.attempt, original_checkpoint.attempt);
        assert_eq!(
            recovered_checkpoint.artifact_ids,
            original_checkpoint.artifact_ids
        );
        assert!(!case.findings.is_empty());
        assert_eq!(fs::read(raw_path).unwrap(), raw_bytes);
        assert!(
            fixture.calls().is_empty(),
            "captured recovery must not even detect a runtime (interrupted Running={interrupted_while_running})"
        );
    }
}

#[test]
fn altered_captured_evidence_is_not_adapted_or_replaced_by_a_fresh_scan() {
    let fixture = Fixture::new(true, "deny");
    let (run_id, raw_path) = fixture.captured_run();
    fs::write(&raw_path, b"[]").unwrap();
    let mut command = fixture.command();
    command.args([
        "--json",
        "scan",
        "recover",
        "--case-id",
        &fixture.case_id,
        "--run-id",
        &run_id,
        "--wait",
    ]);
    let output = Running::spawn(command, true).wait();
    let result = terminal(&output, 4);
    fixture.assert_saved_terminal(&result);
    assert_eq!(result["command_outcome"], "recovery_required");
    assert_eq!(result["retryable"], false);
    assert_eq!(result["result"]["recovery"]["required"], true);
    assert_eq!(
        result["result"]["recovery"]["available_without_target_contact"],
        false
    );
    assert!(result["result"]["recovery"]["next_command"].is_null());
    let case = fixture.case();
    assert_eq!(case.scan_runs.len(), 1);
    assert_eq!(case.scan_runs[0].id, run_id);
    assert_eq!(
        case.scan_runs[0].engine_runs[0].status,
        EngineRunStatus::Failed
    );
    assert_eq!(
        case.scan_runs[0].engine_runs[0].error_code.as_deref(),
        Some("captured_evidence_unavailable")
    );
    assert!(case.scan_runs[0].completed_at.is_some());
    assert!(case.findings.is_empty());
    assert_eq!(fs::read(&raw_path).unwrap(), b"[]");
    assert!(fixture.calls().is_empty());
}

#[test]
fn unknown_case_and_missing_wait_are_refused_without_starting_any_runtime() {
    let fixture = Fixture::new(true, "deny");
    let before = fixture.case();
    for args in [
        vec!["scan", "run", "--case-id", "missing-case", "--wait"],
        vec!["scan", "run", "--case-id", &fixture.case_id],
    ] {
        let output = fixture
            .command()
            .args(["--json"])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fixture.case().storage_revision(), before.storage_revision());
        assert_eq!(
            serde_json::to_value(fixture.case()).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
    assert!(fixture.calls().is_empty());
}

#[test]
fn terminal_snapshot_failure_preserves_results_and_recovers_without_runtime_contact() {
    let fixture = Fixture::new(true, "complete");
    let blocked = fixture
        .data
        .join("artifacts")
        .join(&fixture.case_id)
        .join("report-snapshots");
    fs::create_dir_all(blocked.parent().unwrap()).unwrap();
    fs::write(&blocked, b"existing file").unwrap();
    let output = Running::spawn(fixture.run_command(true, "gitleaks"), true).wait();
    let failed = terminal(&output, 4);
    assert_eq!(failed["error_code"], "terminal_report_snapshot_failed");
    let case = fixture.case();
    let run_id = &case.scan_runs[0].id;
    assert_eq!(
        case.scan_runs[0].engine_runs[0].status,
        EngineRunStatus::Completed
    );
    assert!(!case.findings.is_empty());
    assert!(case.run_report_snapshots.is_empty());
    assert!(failed["result"]["report_snapshot_retry_command"].is_array());
    let original_task = json!(case.scan_runs[0]);
    let calls = fixture.calls();
    let mut retry_blocked = fixture.command();
    retry_blocked.args([
        "--json",
        "scan",
        "recover",
        "--case-id",
        &fixture.case_id,
        "--run-id",
        run_id,
        "--wait",
    ]);
    let failed_retry = terminal(&Running::spawn(retry_blocked, true).wait(), 4);
    assert_eq!(
        failed_retry["error_code"],
        "terminal_report_snapshot_failed"
    );
    assert_eq!(failed_retry["retryable"], true);
    assert_eq!(fixture.case().scan_runs.len(), 1);
    assert_eq!(fixture.calls(), calls);
    fs::remove_file(&blocked).unwrap();
    fs::write(fixture.binary_directory.join("mode"), "deny").unwrap();
    let mut saved = None;
    for _ in 0..2 {
        let mut command = fixture.command();
        command.args([
            "--json",
            "scan",
            "recover",
            "--case-id",
            &fixture.case_id,
            "--run-id",
            run_id,
            "--wait",
        ]);
        let output = Running::spawn(command, true).wait();
        let result = terminal(&output, 0);
        let restored = fixture.case();
        assert_eq!(json!(restored.scan_runs[0]), original_task);
        assert_eq!(restored.run_report_snapshots.len(), 1);
        let record = json!(restored.run_report_snapshots[0]);
        assert_eq!(result["result"]["report_snapshot"], record);
        if let Some(previous) = &saved {
            assert_eq!(&record, previous);
        }
        saved = Some(record);
        assert_eq!(
            fixture.calls(),
            calls,
            "report retry must not even detect a runtime"
        );
    }
}
