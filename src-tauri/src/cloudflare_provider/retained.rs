//! Portable, private preservation of reported bundles. No case admission or
//! workflow trust is granted, and offline reads never execute a validator.
use super::bundle::{
    AuditBinding, BundleFile, BundleManifest, check_manifest, file_index_digest, validate_bundle,
    verified_read,
};
use super::{MAX_SEALED_FILE_BYTES, bundle_io::BundleRoot, strict_json};
use crate::case_archive_io::{
    guard_archive_parent, make_private, private_tempdir_in, publish_directory_no_replace,
    validate_path,
};
use crate::error::{AppError, AppResult};
use crate::provider_report::ProviderProvenance;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MIB: u64 = 1024 * 1024;
const ENVELOPE: &str = "retention.json";
const SCHEMA: &str = "ai-security-scanner.cloudflare-retained/v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retention {
    schema_version: String,
    core_source_sha256: String,
    bundle_sha256: String,
    source_view_sha256: String,
    binding: AuditBinding,
    provenance: ProviderProvenance,
    bundle_files: Vec<BundleFile>,
    source_files: Vec<BundleFile>,
    documents: Vec<BundleFile>,
    payload_index_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RetainedInspection {
    pub schema_version: &'static str,
    pub retention_sha256: String,
    pub bundle_sha256: String,
    pub source_view_sha256: String,
    pub binding: AuditBinding,
    pub file_count: usize,
    pub byte_length: u64,
    pub provenance: ProviderProvenance,
    pub integrity_verified: bool,
    pub expected_identity_verified: bool,
    pub validation_reperformed: bool,
    pub producer_core_matches: bool,
    pub audit_performed: bool,
    pub admission_ready: bool,
    pub documents: Vec<BundleFile>,
}

#[derive(Debug, Serialize)]
pub struct RetainedPublication {
    pub path: PathBuf,
    pub inspection: RetainedInspection,
}

#[derive(Debug, Serialize)]
pub struct RetainedRetrieval {
    pub path: PathBuf,
    pub member: String,
    pub sha256: String,
    pub byte_length: u64,
    pub retention_sha256: String,
}

fn invalid(reason: &str) -> AppError {
    AppError::InvalidRequest(format!("retained Cloudflare bundle: {reason}"))
}
pub(crate) fn retrieve_error(error: AppError) -> AppError {
    match error {
        AppError::InvalidRequest(message) if message.starts_with("case archive: ") => {
            AppError::InvalidRequest(message.replacen("case archive: ", "retrieve: ", 1))
        }
        AppError::UnsafeArchiveParent => {
            invalid("retrieve destination has an untrusted writable ancestor")
        }
        other => other,
    }
}
fn retrieve_destination_error(error: AppError) -> AppError {
    match error {
        AppError::InvalidRequest(message) if message.starts_with("case archive: ") => {
            AppError::InvalidRequest(message.replacen(
                "case archive: ",
                "retrieve destination: ",
                1,
            ))
        }
        other => retrieve_error(other),
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn require_hash(actual: &str, expected: &str) -> AppResult<()> {
    if !hash_valid(expected) || actual != expected {
        return Err(invalid("expected digest does not match the selected data"));
    }
    Ok(())
}
fn entry(path: &str, bytes: &[u8]) -> BundleFile {
    BundleFile {
        path: path.into(),
        sha256: digest(bytes),
        byte_length: bytes.len() as u64,
    }
}

/// Private files are created exclusively inside an owned private tree. No
/// destination parent is created or has its existing permissions repaired.
fn write_private(root: &Path, relative: &str, bytes: &[u8]) -> AppResult<()> {
    validate_path(relative)?;
    let destination = root.join(relative);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| invalid("missing parent"))?,
    )?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&destination)?;
    make_private(&destination, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn destination(path: &Path) -> AppResult<(crate::case_archive_io::ArchiveParentGuard, PathBuf)> {
    let absolute = std::path::absolute(path)?;
    let name = absolute
        .file_name()
        .ok_or_else(|| invalid("destination needs a name"))?;
    validate_path(
        name.to_str()
            .ok_or_else(|| invalid("destination name must be UTF-8"))?,
    )?;
    let guard = guard_archive_parent(
        absolute
            .parent()
            .ok_or_else(|| invalid("destination needs a parent"))?,
    )?;
    let destination = guard.path().join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(invalid("destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok((guard, destination))
}

#[cfg(unix)]
pub(crate) fn sync_directories(root: &Path) -> AppResult<()> {
    for child in fs::read_dir(root)? {
        let child = child?;
        if child.file_type()?.is_dir() {
            sync_directories(&child.path())?;
        }
    }
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}

pub async fn retain_bundle(
    bundle_path: &Path,
    view_path: &Path,
    expected_bundle_sha256: &str,
    output: &Path,
) -> AppResult<RetainedPublication> {
    if !hash_valid(expected_bundle_sha256) {
        return Err(invalid("expected bundle digest must be lowercase SHA-256"));
    }
    let (parent, output) = destination(output)?;
    let staging = private_tempdir_in(parent.path(), ".scanner-cloudflare-retain-")?;
    let mut bundle = BundleRoot::open(bundle_path)?;
    let manifest_bytes = bundle.read("provider-manifest.json", 4 * MIB)?;
    let manifest: BundleManifest = serde_json::from_value(strict_json::parse(&manifest_bytes)?)
        .map_err(|_| invalid("invalid provider manifest"))?;
    check_manifest(&manifest)?;
    let mut index = manifest.files.clone();
    index.push(entry("provider-manifest.json", &manifest_bytes));
    require_hash(&file_index_digest(&index)?, expected_bundle_sha256)?;
    let mut bundle_files = Vec::new();
    write_private(
        staging.path(),
        "bundle/provider-manifest.json",
        &manifest_bytes,
    )?;
    bundle_files.push(entry("bundle/provider-manifest.json", &manifest_bytes));
    for file in &manifest.files {
        let bytes = verified_read(&mut bundle, file)?;
        let relative = format!("bundle/{}", file.path);
        write_private(staging.path(), &relative, &bytes)?;
        bundle_files.push(entry(&relative, &bytes));
    }
    let mut view = BundleRoot::open(view_path)?;
    let mut source_files = Vec::new();
    for file in &manifest.source.files {
        let bytes = verified_read(&mut view, file)?;
        let relative = format!("source-view/{}", file.path);
        write_private(staging.path(), &relative, &bytes)?;
        source_files.push(entry(&relative, &bytes));
    }
    bundle.verify_unchanged()?;
    view.verify_unchanged()?;
    // Validate only the captured private bytes, never a later read of the input.
    let validation = validate_bundle(
        &staging.path().join("bundle"),
        &staging.path().join("source-view"),
    )
    .await?;
    require_hash(&validation.bundle_sha256, expected_bundle_sha256)?;
    if !validation.valid {
        return Err(invalid(
            "captured bundle did not pass validation; nothing was published",
        ));
    }
    let projection = validation
        .projection
        .as_ref()
        .ok_or_else(|| invalid("validation has no report projection"))?;
    let projection_bytes = serde_json::to_vec(projection)?;
    let validation_bytes = serde_json::to_vec(&validation)?;
    if projection_bytes.len() as u64 > 64 * MIB || validation_bytes.len() as u64 > 64 * MIB {
        return Err(invalid("saved documents exceed their size limit"));
    }
    write_private(staging.path(), "projection.json", &projection_bytes)?;
    write_private(staging.path(), "validation.json", &validation_bytes)?;
    let documents = vec![
        entry("projection.json", &projection_bytes),
        entry("validation.json", &validation_bytes),
    ];
    let all = bundle_files
        .iter()
        .chain(&source_files)
        .chain(&documents)
        .cloned()
        .collect::<Vec<_>>();
    let retention = Retention {
        schema_version: SCHEMA.into(),
        core_source_sha256: env!("AI_SECURITY_SCANNER_REPORT_CORE_SHA256").into(),
        bundle_sha256: validation.bundle_sha256,
        source_view_sha256: validation.source_view_sha256,
        binding: validation.binding,
        provenance: ProviderProvenance::ReportedOnly,
        bundle_files,
        source_files,
        documents,
        payload_index_sha256: file_index_digest(&all)?,
    };
    let retention_bytes = serde_json::to_vec(&retention)?;
    if retention_bytes.len() as u64 > MAX_SEALED_FILE_BYTES {
        return Err(invalid("retention index exceeds 8 MiB"));
    }
    write_private(staging.path(), ENVELOPE, &retention_bytes)?;
    let inspection = inspect_retained(staging.path(), Some(&digest(&retention_bytes)))?;
    #[cfg(unix)]
    sync_directories(staging.path())?;
    publish_directory_no_replace(staging.path(), &output)?;
    #[cfg(unix)]
    std::fs::File::open(parent.path())?.sync_all()?;
    Ok(RetainedPublication {
        path: output,
        inspection,
    })
}

pub(crate) struct Loaded {
    pub(crate) root: BundleRoot,
    index: Retention,
    pub(crate) inspection: RetainedInspection,
    pub(crate) manifest: BundleManifest,
    pub(crate) projection: Value,
    pub(crate) members: Vec<BundleFile>,
}

pub(crate) fn load_retained(input: &Path, expected: Option<&str>) -> AppResult<Loaded> {
    load_archive_payload(input, expected, false)
}

/// Archive-only context: source bodies remain authenticated inventory, without claiming
/// their absent bytes were checked. Standalone inspection always reads the full payload.
pub(crate) fn load_archive_payload(
    input: &Path,
    expected: Option<&str>,
    omit_source_bodies: bool,
) -> AppResult<Loaded> {
    let mut root = BundleRoot::open(input)?;
    let bytes = root.read(ENVELOPE, MAX_SEALED_FILE_BYTES)?;
    let retention_hash = digest(&bytes);
    if let Some(expected) = expected {
        require_hash(&retention_hash, expected)?;
    }
    let index: Retention = serde_json::from_value(strict_json::parse(&bytes)?)
        .map_err(|_| invalid("invalid retention index"))?;
    if index.schema_version != SCHEMA
        || index.provenance != ProviderProvenance::ReportedOnly
        || !hash_valid(&index.core_source_sha256)
        || !hash_valid(&index.bundle_sha256)
        || !hash_valid(&index.source_view_sha256)
        || index.bundle_files.len() > 4097
        || index.source_files.len() > 10_000
        || index.documents.len() != 2
    {
        return Err(invalid("unsupported retention contract or bounds"));
    }
    if index
        .bundle_files
        .iter()
        .any(|file| !file.path.starts_with("bundle/") || file.byte_length > 8 * MIB)
        || index
            .source_files
            .iter()
            .any(|file| !file.path.starts_with("source-view/") || file.byte_length > 8 * MIB)
        || index
            .documents
            .iter()
            .any(|file| !matches!(file.path.as_str(), "projection.json" | "validation.json"))
    {
        return Err(invalid("retained inventory has an invalid member class"));
    }
    let all = index
        .bundle_files
        .iter()
        .chain(&index.source_files)
        .chain(&index.documents)
        .cloned()
        .collect::<Vec<_>>();
    let mut names = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for file in &all {
        validate_path(&file.path)?;
        if !names.insert(&file.path) || file.byte_length > 64 * MIB {
            return Err(invalid("duplicate or oversized retained entry"));
        }
        total = total
            .checked_add(file.byte_length)
            .ok_or_else(|| invalid("size overflow"))?;
    }
    if total > 328 * MIB
        || !names.contains(&"projection.json".to_owned())
        || !names.contains(&"validation.json".to_owned())
    {
        return Err(invalid("invalid retained inventory"));
    }
    require_hash(&file_index_digest(&all)?, &index.payload_index_sha256)?;
    let mut manifest_bytes = None;
    let mut projection = None;
    let mut validation = None;
    for file in &all {
        if omit_source_bodies && file.path.starts_with("source-view/") {
            continue;
        }
        let bytes = verified_read(&mut root, file)?;
        match file.path.as_str() {
            "bundle/provider-manifest.json" => {
                if bytes.len() as u64 > 4 * MIB {
                    return Err(invalid("oversized provider manifest"));
                }
                manifest_bytes = Some(bytes);
            }
            "projection.json" => projection = Some(strict_json::parse(&bytes)?),
            "validation.json" => validation = Some(strict_json::parse(&bytes)?),
            _ => {}
        }
    }
    let manifest_bytes = manifest_bytes.ok_or_else(|| invalid("missing provider manifest"))?;
    let manifest: BundleManifest = serde_json::from_value(strict_json::parse(&manifest_bytes)?)
        .map_err(|_| invalid("invalid stored provider manifest"))?;
    check_manifest(&manifest)?;
    let mut native = manifest.files.clone();
    native.push(entry("provider-manifest.json", &manifest_bytes));
    require_hash(&file_index_digest(&native)?, &index.bundle_sha256)?;
    require_hash(&manifest.source.view_sha256, &index.source_view_sha256)?;
    if manifest.binding != index.binding {
        return Err(invalid("stored case/run binding mismatch"));
    }
    check_inventory(&index.bundle_files, &native, "bundle/")?;
    check_inventory(&index.source_files, &manifest.source.files, "source-view/")?;
    if index
        .documents
        .iter()
        .any(|file| !matches!(file.path.as_str(), "projection.json" | "validation.json"))
    {
        return Err(invalid("unknown retained document"));
    }
    let projection = projection.ok_or_else(|| invalid("missing projection"))?;
    let validation = validation.ok_or_else(|| invalid("missing validation"))?;
    check_saved_validation(&projection, &validation, &index, &manifest_bytes)?;
    root.verify_unchanged()?;
    let inspection = RetainedInspection {
        schema_version: "ai-security-scanner.cloudflare-retained-inspection/v1",
        retention_sha256: retention_hash,
        bundle_sha256: index.bundle_sha256.clone(),
        source_view_sha256: index.source_view_sha256.clone(),
        binding: index.binding.clone(),
        file_count: all.len() + 1,
        byte_length: total + bytes.len() as u64,
        provenance: ProviderProvenance::ReportedOnly,
        integrity_verified: true,
        expected_identity_verified: expected.is_some(),
        validation_reperformed: false,
        producer_core_matches: index.core_source_sha256
            == env!("AI_SECURITY_SCANNER_REPORT_CORE_SHA256"),
        audit_performed: false,
        admission_ready: false,
        documents: index.documents.clone(),
    };
    let mut members = all;
    members.push(entry(ENVELOPE, &bytes));
    Ok(Loaded {
        manifest,
        projection,
        members,
        root,
        index,
        inspection,
    })
}

fn check_inventory(actual: &[BundleFile], expected: &[BundleFile], prefix: &str) -> AppResult<()> {
    if actual.len() != expected.len() {
        return Err(invalid("stored inventory differs from provider manifest"));
    }
    let expected = expected
        .iter()
        .map(|file| (format!("{prefix}{}", file.path), file))
        .collect::<std::collections::BTreeMap<_, _>>();
    for file in actual {
        let old = expected
            .get(&file.path)
            .ok_or_else(|| invalid("unindexed retained member"))?;
        if file.sha256 != old.sha256 || file.byte_length != old.byte_length {
            return Err(invalid("retained member differs from provider manifest"));
        }
    }
    Ok(())
}

fn check_saved_validation(
    projection: &Value,
    validation: &Value,
    index: &Retention,
    manifest: &[u8],
) -> AppResult<()> {
    if projection["schema_version"] != "ai-security-scanner.provider-report/v1"
        || projection["provider_id"] != "cloudflare-security-audit"
        || projection["provenance"] != "reported_only"
        || validation["schema_version"] != "ai-security-scanner.cloudflare-bundle-validation/v1"
        || validation["validation_scope"] != "reported_bundle"
        || validation["valid"] != true
        || validation["provenance"] != "reported_only"
        || validation["projection"] != *projection
        || validation["bundle_sha256"] != index.bundle_sha256
        || validation["manifest_sha256"] != digest(manifest)
        || validation["source_view_sha256"] != index.source_view_sha256
        || validation["binding"] != serde_json::to_value(&index.binding)?
        || validation["reference_errors"]
            .as_array()
            .is_none_or(|errors| !errors.is_empty())
        || [
            "audit_performed",
            "admission_ready",
            "canonical_snapshot_binding_verified",
            "source_authorization_verified",
        ]
        .iter()
        .any(|field| validation[field] != false)
    {
        return Err(invalid(
            "stored validation/projection contract is inconsistent",
        ));
    }
    let validations = validation["upstream_validations"]
        .as_array()
        .ok_or_else(|| invalid("missing saved upstream validation"))?;
    if validations.len() < 2
        || validations.len() > 3
        || validations.iter().any(|item| {
            item["validation"]["valid"] != true
                || item["validation"]["phase"] != "upstream"
                || item["audit_performed"] != false
                || item["admission_ready"] != false
        })
    {
        return Err(invalid("invalid saved upstream validation"));
    }
    Ok(())
}

pub fn inspect_retained(input: &Path, expected: Option<&str>) -> AppResult<RetainedInspection> {
    Ok(load_retained(input, expected)?.inspection)
}

pub fn retrieve_retained(
    input: &Path,
    expected_retention_sha256: &str,
    member: &str,
    output: &Path,
) -> AppResult<RetainedRetrieval> {
    retrieve_retained_inner(input, expected_retention_sha256, member, output)
        .map_err(retrieve_error)
}

fn retrieve_retained_inner(
    input: &Path,
    expected_retention_sha256: &str,
    member: &str,
    output: &Path,
) -> AppResult<RetainedRetrieval> {
    let mut loaded = load_retained(input, Some(expected_retention_sha256))?;
    let file = loaded
        .index
        .bundle_files
        .iter()
        .chain(&loaded.index.source_files)
        .chain(&loaded.index.documents)
        .find(|file| file.path == member)
        .ok_or_else(|| invalid("requested member is not indexed"))?
        .clone();
    let bytes = verified_read(&mut loaded.root, &file)?;
    loaded.root.verify_unchanged()?;
    let output = RetrievalDestination::prepare(output, &[])?.publish(&bytes, || Ok(()))?;
    Ok(RetainedRetrieval {
        path: output,
        member: member.into(),
        sha256: file.sha256,
        byte_length: file.byte_length,
        retention_sha256: loaded.inspection.retention_sha256,
    })
}

/// Pins the destination namespace throughout recovery, including the object read.
pub(crate) struct RetrievalDestination {
    parent: crate::case_archive_io::ArchiveParentGuard,
    output: PathBuf,
}
impl RetrievalDestination {
    pub(crate) fn prepare(output: &Path, forbidden_roots: &[PathBuf]) -> AppResult<Self> {
        let absolute = std::path::absolute(output)?;
        let parent = absolute
            .parent()
            .ok_or_else(|| invalid("retrieve destination needs a parent"))?;
        match fs::symlink_metadata(parent) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(invalid("retrieve destination parent does not exist"));
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let (parent, output) = destination(&absolute).map_err(retrieve_destination_error)?;
        for root in forbidden_roots {
            let root = match crate::internal_paths::canonicalize(root) {
                Ok(root) => root,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            if output.starts_with(root) {
                return Err(invalid("destination is inside product storage"));
            }
        }
        if !forbidden_roots.is_empty()
            && parent
                .path()
                .ancestors()
                .any(|p| fs::symlink_metadata(p.join("casework.db")).is_ok())
        {
            return Err(invalid("destination is inside a case workspace"));
        }
        Ok(Self { parent, output })
    }
    /// Recheck the captured boundary after staging and immediately before publication.
    pub(crate) fn publish(
        self,
        bytes: &[u8],
        recheck: impl FnOnce() -> AppResult<()>,
    ) -> AppResult<PathBuf> {
        (|| {
            let parent = &self.parent;
            let output = &self.output;
            parent.verify_unchanged()?;
            let staging = private_tempdir_in(parent.path(), ".scanner-cloudflare-retrieve-")?;
            write_private(staging.path(), "document", bytes)?;
            parent.verify_unchanged()?;
            recheck()?;
            parent.verify_unchanged()?;
            parent.publish_private_file(
                &staging.path().join("document"),
                output.file_name().unwrap(),
            )?;
            Ok(self.output)
        })()
        .map_err(retrieve_destination_error)
    }
}

#[cfg(test)]
mod captured_publication_tests {
    use super::*;

    #[test]
    fn captured_publication_rechecks_before_exposing_bytes() {
        let root = tempfile::tempdir().unwrap();
        make_private(root.path(), true).unwrap();
        let output = root.path().join("out");
        let result = RetrievalDestination::prepare(&output, &[])
            .unwrap()
            .publish(b"private", || {
                Err(AppError::Conflict("changed captured head".into()))
            });
        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert!(!output.exists());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn retrieve_publication_conflict_uses_retrieve_wording() {
        let root = tempfile::tempdir().unwrap();
        make_private(root.path(), true).unwrap();
        let output = root.path().join("out");
        let result = RetrievalDestination::prepare(&output, &[])
            .unwrap()
            .publish(b"private", || {
                fs::write(&output, b"existing")?;
                Ok(())
            });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("retrieve destination"), "{error}");
        assert!(!error.contains("case archive:"), "{error}");
        assert_eq!(fs::read(output).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn captured_publication_rejects_parent_replacement() {
        let root = tempfile::tempdir().unwrap();
        make_private(root.path(), true).unwrap();
        let parent = root.path().join("parent");
        let moved = root.path().join("moved");
        fs::create_dir(&parent).unwrap();
        make_private(&parent, true).unwrap();
        let result = RetrievalDestination::prepare(&parent.join("out"), &[])
            .unwrap()
            .publish(b"private", || {
                crate::case_archive_io::rename_entry_no_replace(&parent, &moved)?;
                fs::create_dir(&parent)?;
                Ok(())
            });
        assert!(result.is_err());
        assert!(!parent.join("out").exists());
        assert!(!moved.join("out").exists());
    }
}
