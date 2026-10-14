//! Provenance-checked, bounded WinAFL launch arguments.
//! The worker-core verifier *does not spawn* a native process. Windows Job
//! Object ownership and quota enforcement are separate B1.5 gates.

mod corpus;

use corpus::CorpusSnapshot;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
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
    /// Trusted digest of real A4 evidence, provisioned out of band with the lock.
    pub pinned_a4_manifest_sha256: String,
    pub target_lock_path: PathBuf,
    pub a4_manifest_path: PathBuf,
    pub harness_path: PathBuf,
    pub allowed_binary_root: PathBuf,
    pub allowed_tool_root: PathBuf,
    pub allowed_input_root: PathBuf,
    pub output_root: PathBuf,
}

#[derive(Debug)]
/// A read-only launch plan, not permission to bypass the Windows supervisor.
/// The runner must own this value until all native descendants have stopped.
pub struct VerifiedRunSpec {
    run_id: RunId,
    executable: PathBuf,
    argv: Vec<OsString>,
    working_dir: PathBuf,
    limits: CampaignLimits,
    evidence_dir: PathBuf,
    // Windows sharing locks must outlive the supervised process, not just verification.
    _guards: Vec<File>,
    _corpus: CorpusSnapshot,
}

impl VerifiedRunSpec {
    pub fn run_id(&self) -> RunId {
        self.run_id
    }
    pub fn limits(&self) -> CampaignLimits {
        self.limits
    }
    pub fn evidence_dir(&self) -> &Path {
        &self.evidence_dir
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }
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
    schema_version: u32,
    target_id: String,
    source_tag: String,
    architecture: String,
    harness_entry: String,
    nargs: u32,
    acquisition: Acquisition,
    source_commit: String,
    tools: Tools,
    runtime_files: Vec<Tool>,
}

#[derive(Deserialize)]
struct Acquisition {
    winafl_source_commit: String,
    dynamorio_release: String,
}

#[derive(Deserialize)]
struct ConfirmedA4 {
    target_commit: String,
    target_module: String,
    target_method: String,
    cycles: u32,
    confirmed_map_nonzero_bytes: u64,
    toolchain_lock_sha256: String,
    harness_sha256: String,
    pdf_filter_sha256: String,
    mupdf_sha256: String,
    confirmed_modules: Vec<String>,
}

// WinAFL 1.17 builds a legacy downstream Windows command line; after
// canonical verification we must not pass the Win32 extended-length \\?\\
// namespace through that unquoted interface. Retained handles still
// refer to the same fully verified objects.
fn native_argv_path(path: &Path) -> Result<PathBuf, WorkerError> {
    #[cfg(windows)]
    {
        let raw = path.to_str().ok_or(WorkerError::UnverifiedToolchain)?;
        let dos = match raw.strip_prefix(r"\\?\") {
            Some(stripped) => stripped,
            None => raw,
        };
        let b = dos.as_bytes();
        if b.len() < 3
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || b[2] != b'\\'
            || dos.len() >= 240
            || dos.starts_with(r"\\")
        {
            return Err(WorkerError::UnverifiedToolchain);
        }
        Ok(PathBuf::from(dos))
    }
    #[cfg(not(windows))]
    {
        Ok(path.to_path_buf())
    }
}

fn safe_absolute(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || text.starts_with(r"\\")
        || text.starts_with("//")
        || text.split(['/', '\\']).any(|p| p == ".." || p == ".")
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        {
            return false;
        }
        if text.chars().skip(2).any(|c| c == ':') {
            return false;
        }
        if text
            .split(['/', '\\'])
            .any(|p| p.ends_with('.') || p.ends_with(' '))
        {
            return false;
        }
    }
    true
}

fn open_guard(path: &Path, directory: bool) -> Result<File, WorkerError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny deletion of ancestors; deny both write and delete on verified files.
        options.share_mode(if directory { 3 } else { 1 });
        options.custom_flags(0x02000000 | 0x00200000); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    let meta = file
        .metadata()
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(WorkerError::UnverifiedToolchain);
        }
    }
    if meta.is_dir() != directory || (!directory && !meta.is_file()) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    Ok(file)
}

fn verify_path(path: &Path, root: &Path, guards: &mut Vec<File>) -> Result<PathBuf, WorkerError> {
    if !safe_absolute(path) || !safe_absolute(root) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    for candidate in [root, path] {
        let ancestors: Vec<_> = candidate.ancestors().collect();
        for part in ancestors.into_iter().rev() {
            let meta = fs::symlink_metadata(part).map_err(|_| WorkerError::UnverifiedToolchain)?;
            if meta.file_type().is_symlink() {
                return Err(WorkerError::UnverifiedToolchain);
            }
            guards.push(open_guard(part, meta.is_dir())?);
        }
    }
    let canonical = fs::canonicalize(path).map_err(|_| WorkerError::UnverifiedToolchain)?;
    let allowed = fs::canonicalize(root).map_err(|_| WorkerError::UnverifiedToolchain)?;
    if !canonical.starts_with(allowed) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    Ok(canonical)
}

fn file_matches(file: &mut File, expected: &str) -> Result<(), WorkerError> {
    if expected.len() != 64 || !expected.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err(WorkerError::UnverifiedToolchain);
    }
    file.rewind()
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    let mut hash = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| WorkerError::UnverifiedToolchain)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    file.rewind()
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    if format!("{:x}", hash.finalize()).eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(WorkerError::UnverifiedToolchain)
    }
}

fn read_manifest<T: serde::de::DeserializeOwned>(
    path: &Path,
    expected: &str,
    guards: &mut Vec<File>,
) -> Result<T, WorkerError> {
    let mut file = open_guard(path, false)?;
    // Bound allocation and parse precisely the bytes authenticated by the trusted digest.
    let mut bytes = Vec::new();
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    if bytes.len() > 1024 * 1024
        || expected.len() != 64
        || !format!("{:x}", Sha256::digest(&bytes)).eq_ignore_ascii_case(expected)
    {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let result = serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    guards.push(file);
    Ok(result)
}

fn verified_binary(
    path: &Path,
    root: &Path,
    hash: &str,
    guards: &mut Vec<File>,
) -> Result<PathBuf, WorkerError> {
    let canon = verify_path(path, root, guards)?;
    let mut file = open_guard(&canon, false)?;
    file_matches(&mut file, hash)?;
    let mut header = [0; 64];
    file.read_exact(&mut header)
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    let offset = u32::from_le_bytes(header[60..64].try_into().unwrap()) as u64;
    if &header[..2] != b"MZ" || offset < 64 {
        return Err(WorkerError::UnverifiedToolchain);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    let mut pe = [0; 6];
    file.read_exact(&mut pe)
        .map_err(|_| WorkerError::UnverifiedToolchain)?;
    if pe != [b'P', b'E', 0, 0, 0x64, 0x86] {
        return Err(WorkerError::UnverifiedToolchain);
    }
    guards.push(file);
    Ok(canon)
}

fn check_limits(limits: CampaignLimits, ceilings: CampaignLimits) -> Result<(), WorkerError> {
    ceilings.validate()?;
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
    let mut guards = Vec::new();
    if !request
        .target_lock_sha256
        .eq_ignore_ascii_case(&policy.pinned_target_lock_sha256)
    {
        return Err(WorkerError::UnverifiedToolchain);
    }
    check_limits(request.limits, policy.max_limits)?;
    let lock_path = verify_path(
        &policy.target_lock_path,
        policy
            .target_lock_path
            .parent()
            .ok_or(WorkerError::UnverifiedToolchain)?,
        &mut guards,
    )?;
    let a4_path = verify_path(
        &policy.a4_manifest_path,
        policy
            .a4_manifest_path
            .parent()
            .ok_or(WorkerError::UnverifiedToolchain)?,
        &mut guards,
    )?;
    let lock: Lock = read_manifest(&lock_path, &policy.pinned_target_lock_sha256, &mut guards)?;
    let a4: ConfirmedA4 = read_manifest(&a4_path, &policy.pinned_a4_manifest_sha256, &mut guards)?;
    if lock.schema_version != 1
        || lock.target_id != "sumatrapdf-3.6.1rel"
        || lock.source_tag != "3.6.1rel"
        || lock.architecture != "x64"
        || lock.harness_entry != "fuzz_one_file"
        || lock.nargs != 1
        || lock.acquisition.winafl_source_commit != "fd85f38548b14352f4b70ad414f364ea6dc1a769"
        || lock.acquisition.dynamorio_release != "cronbuild-11.91.20735"
        || a4.target_module != "sumatrafuzz-harness.exe"
        || a4.target_method != "fuzz_one_file"
        || policy.harness_path.file_name().and_then(|n| n.to_str())
            != Some("sumatrafuzz-harness.exe")
        || lock.source_commit != PINNED_SOURCE
        || a4.target_commit != PINNED_SOURCE
        || a4.cycles != 10
        || a4.confirmed_map_nonzero_bytes == 0
        || a4.confirmed_map_nonzero_bytes > 65536
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
        &mut guards,
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
        &mut guards,
    )?;
    verified_binary(
        &sibling.join("libmupdf.dll"),
        &policy.allowed_binary_root,
        &a4.mupdf_sha256,
        &mut guards,
    )?;
    if lock.tools.drrun.path.file_name().and_then(|n| n.to_str()) != Some("drrun.exe")
        || [&lock.tools.drrun.path, &lock.tools.winafl_client.path]
            .iter()
            .any(|p| {
                p.to_string_lossy()
                    .chars()
                    .any(|c| c.is_whitespace() || c == '"')
            })
    {
        // Pinned WinAFL constructs an unquoted downstream DynamoRIO command line.
        return Err(WorkerError::UnverifiedToolchain);
    }
    if lock.runtime_files.is_empty() || lock.runtime_files.len() > 512 {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let mut runtime_paths = HashSet::new();
    let mut has_drconfig = false;
    for entry in &lock.runtime_files {
        let path = verified_binary(
            &entry.path,
            &policy.allowed_tool_root,
            &entry.sha256,
            &mut guards,
        )?;
        if !runtime_paths.insert(path.to_string_lossy().to_lowercase()) {
            return Err(WorkerError::UnverifiedToolchain);
        }
        if entry.path == lock.tools.drrun.path.with_file_name("drconfig.exe") {
            has_drconfig = true;
        }
    }
    if !has_drconfig {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let executable = verified_binary(
        &lock.tools.afl_fuzz.path,
        &policy.allowed_tool_root,
        &lock.tools.afl_fuzz.sha256,
        &mut guards,
    )?;
    let drrun = verified_binary(
        &lock.tools.drrun.path,
        &policy.allowed_tool_root,
        &lock.tools.drrun.sha256,
        &mut guards,
    )?;
    let client = verified_binary(
        &lock.tools.winafl_client.path,
        &policy.allowed_tool_root,
        &lock.tools.winafl_client.sha256,
        &mut guards,
    )?;
    let drrun_dir = drrun.parent().ok_or(WorkerError::UnverifiedToolchain)?;

    let mut observed = HashSet::new();
    if a4.confirmed_modules.len() != 2 {
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
    if !observed.contains("pdffilter.dll") || !observed.contains("libmupdf.dll") {
        return Err(WorkerError::UnverifiedToolchain);
    }
    let input = verify_path(
        &policy.allowed_input_root.join(&request.input_bundle_id),
        &policy.allowed_input_root,
        &mut guards,
    )?;
    if !input.is_dir() {
        return Err(WorkerError::InvalidConfig);
    }
    let root = verify_path(&policy.output_root, &policy.output_root, &mut guards)?;
    if !root.is_dir() {
        return Err(WorkerError::InvalidConfig);
    }
    let run_id = RunId(Uuid::new_v4());
    let evidence_dir = root.join(run_id.0.to_string());
    let evidence_arg = native_argv_path(&evidence_dir)?;
    if evidence_dir.exists() {
        return Err(WorkerError::InvalidConfig);
    }
    let mut corpus = CorpusSnapshot::create(root.join(format!("{}.seeds", run_id.0)))?;
    let provisioned_input = policy.allowed_input_root.join(&request.input_bundle_id);
    let mut count = 0_u32;
    let mut seed_bytes = 0_u64;
    for entry in fs::read_dir(&provisioned_input).map_err(|_| WorkerError::InvalidConfig)? {
        count += 1;
        if count > 10000 {
            return Err(WorkerError::LimitExceeded);
        }
        let path = entry.map_err(|_| WorkerError::UnverifiedToolchain)?.path();
        let verified = verify_path(&path, &policy.allowed_input_root, &mut guards)?;
        let file = open_guard(&verified, false)?;
        seed_bytes = seed_bytes
            .checked_add(
                file.metadata()
                    .map_err(|_| WorkerError::UnverifiedToolchain)?
                    .len(),
            )
            .ok_or(WorkerError::LimitExceeded)?;
        if seed_bytes > request.limits.max_disk_bytes.get() {
            return Err(WorkerError::LimitExceeded);
        }
        let copied = corpus.copy_seed(&verified)?;
        guards.push(file);
        corpus.files.push(open_guard(&copied, false)?);
    }
    if count == 0 {
        return Err(WorkerError::InvalidConfig);
    }
    corpus.seal()?;
    let input = fs::canonicalize(&corpus.path).map_err(|_| WorkerError::UnverifiedToolchain)?;
    let input_arg = native_argv_path(&input)?;
    // Keep writable evidence out of WinAFL's unqualified taskkill executable search.
    let working_dir = native_argv_path(
        executable
            .parent()
            .ok_or(WorkerError::UnverifiedToolchain)?,
    )?;
    let executable_arg = native_argv_path(&executable)?;
    let drrun_arg = native_argv_path(drrun_dir)?;
    let client_arg = native_argv_path(&client)?;
    let harness_arg = native_argv_path(&harness)?;
    let mut argv = vec![
        OsString::from("-i"),
        input_arg.into_os_string(),
        OsString::from("-o"),
        evidence_arg.into_os_string(),
        OsString::from("-D"),
        drrun_arg.into_os_string(),
        OsString::from("-w"),
        client_arg.into_os_string(),
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
        harness_arg.into_os_string(),
        OsString::from("@@"),
    ]);
    Ok(VerifiedRunSpec {
        run_id,
        executable: executable_arg,
        argv,
        working_dir,
        limits: request.limits,
        evidence_dir,
        _guards: guards,
        _corpus: corpus,
    })
}
