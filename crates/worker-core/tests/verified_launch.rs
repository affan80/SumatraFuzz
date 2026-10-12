use sha2::{Digest, Sha256};
use std::{fs, num::{NonZeroU64, NonZeroU8}, path::{Path, PathBuf}};
use tempfile::TempDir;
use uuid::Uuid;
use worker_core::{verify_and_build_launch, WorkerPolicy};
use worker_protocol::{CampaignLimits, ControllerId, RunRequest, WorkerError};

const PIN: &str = "16c59fde8b824ab54c56f23aef910a6fdd874ad0";
fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn write(path: &Path, bytes: &[u8]) -> String {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    hash(bytes)
}
struct Fixture {
    _temp: TempDir,
    policy: WorkerPolicy,
    request: RunRequest,
    bundle: PathBuf,
}
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let binaries = dir.join("binaries");
    let tools = dir.join("tools");
    let input = dir.join("input");
    let output = dir.join("output");
    let harness = binaries.join("sumatrafuzz-harness.exe");
    let h = write(&harness, b"test harness"); // synthetic verification fixture, never native proof
    let filter = write(&binaries.join("PdfFilter.dll"), b"test filter");
    let mupdf = write(&binaries.join("libmupdf.dll"), b"test mupdf");
    let dr = tools.join("drrun.exe");
    let afl = tools.join("afl-fuzz.exe");
    let client = tools.join("winafl.dll");
    let drh = write(&dr, b"debug runner");
    let aflh = write(&afl, b"fuzzer");
    let clienth = write(&client, b"client");
    write(&input.join("approved-bundle").join("a.pdf"), b"%PDF-1.4\n");
    fs::create_dir_all(&output).unwrap();
    let lock_path = dir.join("target-lock.json");
    let lock = serde_json::json!({
        "source_commit": PIN,
        "tools": {
            "drrun": {"path": dr, "sha256": drh},
            "afl_fuzz": {"path": afl, "sha256": aflh},
            "winafl_client": {"path": client, "sha256": clienth}
        }
    });
    let digest = write(&lock_path, serde_json::to_string(&lock).unwrap().as_bytes());
    let a4_path = dir.join("a4-confirmed.json");
    fs::write(&a4_path, serde_json::to_vec(&serde_json::json!({
        "target_commit": PIN, "cycles": 10, "confirmed_map_nonzero_bytes": 1,
        "toolchain_lock_sha256": digest, "harness_sha256": h, "pdf_filter_sha256": filter,
        "mupdf_sha256": mupdf, "confirmed_modules": ["PdfFilter.dll", "libmupdf.dll"]
    })).unwrap()).unwrap();
    let limits = CampaignLimits {
        max_duration_s: NonZeroU64::new(60).unwrap(),
        max_memory_bytes: NonZeroU64::new(256 * 1024 * 1024).unwrap(),
        max_disk_bytes: NonZeroU64::new(512 * 1024 * 1024).unwrap(),
        max_cpu_percent: NonZeroU8::new(75).unwrap(),
    };
    Fixture {
        _temp: tmp,
        policy: WorkerPolicy {
            max_limits: limits, target_lock_path: lock_path, a4_manifest_path: a4_path,
            harness_path: harness, allowed_binary_root: binaries,
            allowed_tool_root: tools, allowed_input_root: input, output_root: output,
        },
        request: RunRequest {
            request_id: Uuid::from_u128(42), controller_id: ControllerId(Uuid::from_u128(7)),
            input_bundle_id: "approved-bundle".to_string(), target_lock_sha256: digest,
            limits, label: "test-case".to_string(),
        },
        bundle: dir.join("input").join("approved-bundle"),
    }
}
#[test]
fn verified_launch_builds_explicit_argv_without_shell() {
    let fixture = fixture();
    let spec = verify_and_build_launch(&fixture.request, &fixture.policy).unwrap();
    let args: Vec<String> = spec.argv.iter().map(|v| v.to_string_lossy().to_string()).collect();
    assert_eq!(spec.executable.file_name().unwrap(), "afl-fuzz.exe");
    assert!(args.windows(2).any(|x| x == ["-target_method", "fuzz_one_file"]));
    assert!(args.windows(2).any(|x| x == ["-i", fixture.bundle.to_str().unwrap()]));
    assert_eq!(args.last().map(String::as_str), Some("@@"));
    assert!(spec.evidence_dir.starts_with(&fixture.policy.output_root));
}
#[test]
fn changed_target_lock_is_denied_before_spawn() {
    let mut f = fixture();
    f.request.target_lock_sha256 = "f".repeat(64);
    assert!(matches!(verify_and_build_launch(&f.request, &f.policy), Err(WorkerError::UnverifiedToolchain)));
}
#[test]
fn resource_limits_and_unknown_bundle_are_denied() {
    let mut f = fixture();
    f.request.limits.max_cpu_percent = NonZeroU8::new(99).unwrap();
    assert!(matches!(verify_and_build_launch(&f.request, &f.policy), Err(WorkerError::LimitExceeded)));
    f.request.limits = f.policy.max_limits;
    f.request.input_bundle_id = "not-admitted".to_owned();
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}
#[test]
fn mutated_native_binary_is_denied() {
    let f = fixture();
    fs::write(f.policy.harness_path.clone(), b"tampered harness").unwrap();
    assert!(matches!(verify_and_build_launch(&f.request, &f.policy), Err(WorkerError::UnverifiedToolchain)));
}
