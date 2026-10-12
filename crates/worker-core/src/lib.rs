//! Provenance-checked, bounded WinAFL launch arguments.
//! The worker-core verifier *does not spawn* a native process. Windows Job
//! Object ownership and real native acceptance are separate B1.5 gates.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use worker_protocol::{CampaignLimits, RunId, RunRequest, WorkerError};

const PINNED_SOURCE: &str = "16c59fde8b824ab54c56f23aef910a6fdd874ad0";
const DEFAULT_TIMEOUT_MS: &str = "20000";
const PERSISTENT_ITERATIONS: &str = "1000";

#[derive(Clone, Debug)]
pub struct WorkerPolicy {
    pub max_limits: CampaignLimits,
    /// Administrator-provisioned trusted digest; never a client-supplied trust anchor.
    pub pinned_target_lock_sha256: String,
    pub target_lock_path: PathBuf,
    pub a4_manifest_path: PathBuf,
    pub harness_path: PathBuf,
    pub allowed_binary_root: PathBuf,
    pub allowed_tool_root: PathBuf,
    pub allowed_input_root: PathBuf,
    pub output_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerifiedRunSpec {
    pub run_id: RunId,
    pub executable: PathBuf,
    pub argv: Vec<OsString>,
    pub working_dir: PathBuf,
    pub limits: CampaignLimits,
    pub evidence_dir: PathBuf,
}

#[derive(Deserialize)]
struct Tool {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
struct Tools {
    drrun: Tool,
    afl_fuzz: Tool,
    winafl_client: Tool,
}

#[derive(Deserialize)]
struct Lock {
    source_commit: String,
    tools: Tools,
}

#[derive(Deserialize)]
struct ConfirmedA4 {
    target_commit: String,
    cycles: u32,
    confirmed_map_nonzero_bytes: u64,
    toolchain_lock_sha256: String,
    harness_sha256: String,
    pdf_filter_sha256: String,
    mupdf_sha256: String,
    confirmed_modules: Vec<String>,
}

fn verify_path(path: &Path, root: &Path) -> Result<PathBuf, WorkerError> {
    if !path.is_absolute() || !root.is_absolute() {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let text = path.to_string_lossy();
    if text.starts_with(r"\\") || text.starts_with(r"//") {
        return Err(WorkerError::UnverifiedToolchain);
    }
    for part in path.ancestors() {
        let meta = fs::symlink_metadata(part).map_err(|_| WorkerError::UnverifiedToolchain)?;
        if meta.file_type().is_symlink() {
            return Err(WorkerError::UnverifiedToolchain);
        }
        #[cfg(windows)]
        if reparse_point(&meta) {
            return Err(WorkerError::UnverifiedToolchain);
        }
    }
    for part in root.ancestors() {
        let meta = fs::symlink_metadata(part).map_err(|_| WorkerError::UnverifiedToolchain)?;
        if meta.file_type().is_symlink() {
            return Err(WorkerError::UnverifiedToolchain);
        }
        #[cfg(windows)]
        if reparse_point(&meta) {
            return Err(WorkerError::UnverifiedToolchain);
        }
    }
    let canonical = fs::canonicalize(path).map_err(|_| WorkerError::UnverifiedToolchain)?;
    let allowed = fs::canonicalize(root).map_err(|_| WorkerError::UnverifiedToolchain)?;
    if !canonical.starts_with(allowed) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    Ok(canonical)
}

#[cfg(windows)]
fn reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (meta.file_attributes() & 0x400) != 0
}

fn sha256_file(path: &Path) -> Result<String, WorkerError> {
    if !fs::metadata(path)
        .map_err(|_| WorkerError::UnverifiedToolchain)?
        .is_file()
    {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let mut stream = File::open(path).map_err(|_| WorkerError::UnverifiedToolchain)?;
    let mut hash = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|_| WorkerError::UnverifiedToolchain)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn file_matches(path: &Path, expected: &str) -> Result<(), WorkerError> {
    if expected.len() != 64 || !expected.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    if sha256_file(path)?.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(WorkerError::UnverifiedToolchain)
    }
}

fn verified_binary(path: &Path, root: &Path, hash: &str) -> Result<PathBuf, WorkerError> {
    let canon = verify_path(path, root)?;
    file_matches(&canon, hash)?;
    Ok(canon)
}

fn check_limits(limits: CampaignLimits, ceilings: CampaignLimits) -> Result<(), WorkerError> {
    if limits.max_duration_s > ceilings.max_duration_s
        || limits.max_memory_bytes > ceilings.max_memory_bytes
        || limits.max_disk_bytes > ceilings.max_disk_bytes
        || limits.max_cpu_percent > ceilings.max_cpu_percent
    {
        return Err(WorkerError::LimitExceeded);
    }
    Ok(())
}

/// Return a validated, structured process command but do not spawn or
/// treat test fixtures as proof that WinAFL was actually instrumented.
pub fn verify_and_build_launch(
    request: &RunRequest,
    policy: &WorkerPolicy,
) -> Result<VerifiedRunSpec, WorkerError> {
    request.validate()?;
    if !request.target_lock_sha256.eq_ignore_ascii_case(&policy.pinned_target_lock_sha256) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    check_limits(request.limits, policy.max_limits)?;
    let lock_path = verify_path(
        &policy.target_lock_path,
        policy
            .target_lock_path
            .parent()
            .ok_or(WorkerError::UnverifiedToolchain)?,
    )?;
    let a4_path = verify_path(
        &policy.a4_manifest_path,
        policy
            .a4_manifest_path
            .parent()
            .ok_or(WorkerError::UnverifiedToolchain)?,
    )?;
    file_matches(&lock_path, &policy.pinned_target_lock_sha256)?;

    let lock: Lock = serde_json::from_reader(
        File::open(&lock_path).map_err(|_| WorkerError::UnverifiedToolchain)?,
    )
    .map_err(|_| WorkerError::UnverifiedToolchain)?;
    let a4: ConfirmedA4 =
        serde_json::from_reader(File::open(a4_path).map_err(|_| WorkerError::UnverifiedToolchain)?)
            .map_err(|_| WorkerError::UnverifiedToolchain)?;
    if lock.source_commit != PINNED_SOURCE
        || a4.target_commit != PINNED_SOURCE
        || a4.cycles < 10
        || a4.confirmed_map_nonzero_bytes == 0
        || !a4
            .toolchain_lock_sha256
            .eq_ignore_ascii_case(&policy.pinned_target_lock_sha256)
    {
        return Err(WorkerError::UnverifiedToolchain);
    }

    let harness = verified_binary(
        &policy.harness_path,
        &policy.allowed_binary_root,
        &a4.harness_sha256,
    )?;
    // Use the provisioned path here: Windows canonicalize() may add a \\?\\ prefix,
    // which must never be mistaken for an untrusted user-supplied device path.
    let sibling = policy
        .harness_path
        .parent()
        .ok_or(WorkerError::UnverifiedToolchain)?;
    verified_binary(
        &sibling.join("PdfFilter.dll"),
        &policy.allowed_binary_root,
        &a4.pdf_filter_sha256,
    )?;
    verified_binary(
        &sibling.join("libmupdf.dll"),
        &policy.allowed_binary_root,
        &a4.mupdf_sha256,
    )?;
    let executable = verified_binary(
        &lock.tools.afl_fuzz.path,
        &policy.allowed_tool_root,
        &lock.tools.afl_fuzz.sha256,
    )?;
    let drrun = verified_binary(
        &lock.tools.drrun.path,
        &policy.allowed_tool_root,
        &lock.tools.drrun.sha256,
    )?;
    let client = verified_binary(
        &lock.tools.winafl_client.path,
        &policy.allowed_tool_root,
        &lock.tools.winafl_client.sha256,
    )?;
    let drrun_dir = drrun.parent().ok_or(WorkerError::UnverifiedToolchain)?;

    let mut observed = HashSet::new();
    if a4.confirmed_modules.is_empty() || a4.confirmed_modules.len() > 8 {
        return Err(WorkerError::UnverifiedToolchain);
    }
    for module in &a4.confirmed_modules {
        if module.len() > 128
            || !module.to_ascii_lowercase().ends_with(".dll")
            || !module
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
            || !observed.insert(module.to_ascii_lowercase())
        {
            return Err(WorkerError::UnverifiedToolchain);
        }
    }
    let input = verify_path(
        &policy.allowed_input_root.join(&request.input_bundle_id),
        &policy.allowed_input_root,
    )?;
    if !input.is_dir() {
        return Err(WorkerError::InvalidConfig);
    }
    // The actual fuzzer and Windows Job Object supervisor is responsible for
    // proving seed validity and applying CPU/memory/disk/time limits.
    let root = verify_path(&policy.output_root, &policy.output_root)?;
    let run_id = RunId(Uuid::new_v4());
    let evidence_dir = root.join(run_id.0.to_string());
    if evidence_dir.exists() {
        return Err(WorkerError::InvalidConfig);
    }
    let mut argv = vec![
        OsString::from("-i"),
        input.into_os_string(),
        OsString::from("-o"),
        evidence_dir.as_os_str().to_os_string(),
        OsString::from("-D"),
        drrun_dir.as_os_str().to_os_string(),
        OsString::from("-w"),
        client.into_os_string(),
        OsString::from("-t"),
        OsString::from(DEFAULT_TIMEOUT_MS),
        OsString::from("--"),
        OsString::from("-covtype"),
        OsString::from("edge"),
    ];
    for module in a4.confirmed_modules {
        argv.push(OsString::from("-coverage_module"));
        argv.push(OsString::from(module));
    }
    argv.extend([
        OsString::from("-target_module"),
        harness
            .file_name()
            .ok_or(WorkerError::UnverifiedToolchain)?
            .to_os_string(),
        OsString::from("-target_method"),
        OsString::from("fuzz_one_file"),
        OsString::from("-fuzz_iterations"),
        OsString::from(PERSISTENT_ITERATIONS),
        OsString::from("-nargs"),
        OsString::from("1"),
        OsString::from("--"),
        harness.into_os_string(),
        OsString::from("@@"),
    ]);
    Ok(VerifiedRunSpec {
        run_id,
        executable,
        argv,
        working_dir: root,
        limits: request.limits,
        evidence_dir,
    })
}
