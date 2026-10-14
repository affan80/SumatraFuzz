use sha2::{Digest, Sha256};
use std::{
    fs,
    num::{NonZeroU64, NonZeroU8},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use uuid::Uuid;
use worker_core::{verify_and_build_launch, WorkerPolicy};
use worker_protocol::{CampaignLimits, ControllerId, RunRequest, WorkerError};

const PIN: &str = "16c59fde8b824ab54c56f23aef910a6fdd874ad0";
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
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
fn pe(label: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x100];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes.extend_from_slice(label);
    bytes
}
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let dir = fs::canonicalize(tmp.path()).unwrap();
    #[cfg(windows)]
    let dir = tmp.path().to_path_buf();
    let binaries = dir.join("binaries");
    let tools = dir.join("tools");
    let input = dir.join("input");
    let output = dir.join("output");
    let harness = binaries.join("sumatrafuzz-harness.exe");
    let h = write(&harness, &pe(b"test harness")); // synthetic verification fixture, never native proof
    let filter = write(&binaries.join("PdfFilter.dll"), &pe(b"test filter"));
    let mupdf = write(&binaries.join("libmupdf.dll"), &pe(b"test mupdf"));
    let dr = tools.join("drrun.exe");
    let afl = tools.join("afl-fuzz.exe");
    let client = tools.join("winafl.dll");
    let drh = write(&dr, &pe(b"debug runner"));
    let aflh = write(&afl, &pe(b"fuzzer"));
    let clienth = write(&client, &pe(b"client"));
    let drconfig = tools.join("drconfig.exe");
    let drconfigh = write(&drconfig, &pe(b"DR registration helper"));
    write(&input.join("approved-bundle").join("a.pdf"), b"%PDF-1.4\n");
    fs::create_dir_all(&output).unwrap();
    let lock_path = dir.join("target-lock.json");
    let lock = serde_json::json!({
        "schema_version": 1, "target_id": "sumatrapdf-3.6.1rel",
        "source_tag": "3.6.1rel", "architecture": "x64", "harness_entry": "fuzz_one_file", "nargs": 1,
        "source_commit": PIN,
        "acquisition": {"winafl_source_commit": "fd85f38548b14352f4b70ad414f364ea6dc1a769",
          "dynamorio_release": "cronbuild-11.91.20735"},
        "runtime_files": [{"path": drconfig, "sha256": drconfigh}],
        "tools": {
            "drrun": {"path": dr, "sha256": drh},
            "afl_fuzz": {"path": afl, "sha256": aflh},
            "winafl_client": {"path": client, "sha256": clienth}
        }
    });
    let digest = write(&lock_path, serde_json::to_string(&lock).unwrap().as_bytes());
    let a4_path = dir.join("a4-confirmed.json");
    fs::write(
        &a4_path,
        serde_json::to_vec(&serde_json::json!({
            "target_commit": PIN, "target_module": "sumatrafuzz-harness.exe", "target_method": "fuzz_one_file", "cycles": 10, "confirmed_map_nonzero_bytes": 1,
            "toolchain_lock_sha256": digest, "harness_sha256": h, "pdf_filter_sha256": filter,
            "mupdf_sha256": mupdf, "confirmed_modules": ["PdfFilter.dll", "libmupdf.dll"]
        }))
        .unwrap(),
    )
    .unwrap();
    let a4_digest = hash(&fs::read(&a4_path).unwrap());
    let limits = CampaignLimits {
        max_duration_s: NonZeroU64::new(60).unwrap(),
        max_memory_bytes: NonZeroU64::new(256 * 1024 * 1024).unwrap(),
        max_disk_bytes: NonZeroU64::new(512 * 1024 * 1024).unwrap(),
        max_cpu_percent: NonZeroU8::new(75).unwrap(),
    };
    Fixture {
        _temp: tmp,
        policy: WorkerPolicy {
            max_limits: limits,
            pinned_target_lock_sha256: digest.clone(),
            pinned_a4_manifest_sha256: a4_digest,
            target_lock_path: lock_path,
            a4_manifest_path: a4_path,
            harness_path: harness,
            allowed_binary_root: binaries,
            allowed_tool_root: tools,
            allowed_input_root: input,
            output_root: output,
        },
        request: RunRequest {
            request_id: Uuid::from_u128(42),
            controller_id: ControllerId(Uuid::from_u128(7)),
            input_bundle_id: "approved-bundle".to_string(),
            target_lock_sha256: digest,
            limits,
            label: "test-case".to_string(),
        },
        bundle: dir.join("input").join("approved-bundle"),
    }
}
#[test]
fn verified_launch_builds_explicit_argv_without_shell() {
    let fixture = fixture();
    let spec = verify_and_build_launch(&fixture.request, &fixture.policy).unwrap();
    let args: Vec<String> = spec
        .argv()
        .iter()
        .map(|v| v.to_string_lossy().to_string())
        .collect();
    assert_eq!(spec.executable().file_name().unwrap(), "afl-fuzz.exe");
    assert!(args
        .windows(2)
        .any(|x| x == ["-target_method", "fuzz_one_file"]));
    // Windows canonical paths can have an extended-length prefix.
    let actual_input = args.windows(2).find(|x| x[0] == "-i").unwrap();
    assert_eq!(
        PathBuf::from(&actual_input[1]),
        fs::canonicalize(&fixture.bundle).unwrap()
    );
    assert_eq!(args.last().map(String::as_str), Some("@@"));
    assert!(spec
        .evidence_dir()
        .starts_with(fs::canonicalize(&fixture.policy.output_root).unwrap()));
}
#[test]
fn changed_target_lock_is_denied_before_spawn() {
    let mut f = fixture();
    f.request.target_lock_sha256 = "f".repeat(64);
    assert!(matches!(
        verify_and_build_launch(&f.request, &f.policy),
        Err(WorkerError::UnverifiedToolchain)
    ));
}
#[test]
fn resource_limits_and_unknown_bundle_are_denied() {
    let mut f = fixture();
    f.request.limits.max_cpu_percent = NonZeroU8::new(99).unwrap();
    assert!(matches!(
        verify_and_build_launch(&f.request, &f.policy),
        Err(WorkerError::LimitExceeded)
    ));
    f.request.limits = f.policy.max_limits;
    f.request.input_bundle_id = "not-admitted".to_owned();
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}
#[test]
fn mutated_native_binary_is_denied() {
    let f = fixture();
    fs::write(f.policy.harness_path.clone(), b"tampered harness").unwrap();
    assert!(matches!(
        verify_and_build_launch(&f.request, &f.policy),
        Err(WorkerError::UnverifiedToolchain)
    ));
}

#[test]
fn forged_matching_client_manifest_cannot_replace_worker_trust_anchor() {
    let mut f = fixture();
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.policy.target_lock_path).unwrap()).unwrap();
    // A hostile client can supply a fresh hash but cannot change the
    // administrator-provisioned worker trust anchor.
    lock["untrusted_note"] = serde_json::json!("attacker-repacked");
    let rewritten = serde_json::to_vec(&lock).unwrap();
    let changed_hash = write(&f.policy.target_lock_path, &rewritten);
    let mut a4: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.policy.a4_manifest_path).unwrap()).unwrap();
    a4["toolchain_lock_sha256"] = serde_json::json!(changed_hash);
    fs::write(&f.policy.a4_manifest_path, serde_json::to_vec(&a4).unwrap()).unwrap();
    f.request.target_lock_sha256 = changed_hash;
    assert!(matches!(
        verify_and_build_launch(&f.request, &f.policy),
        Err(WorkerError::UnverifiedToolchain)
    ));
}

#[test]
fn forged_a4_and_harness_hash_cannot_replace_worker_trust_anchor() {
    let f = fixture();
    // The toolchain lock is unchanged. An attacker with write access to the
    // unhashed A4 manifest must not authorize a substituted target executable.
    let mut forged: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.policy.a4_manifest_path).unwrap()).unwrap();
    let modified = b"substituted executable";
    fs::write(&f.policy.harness_path, modified).unwrap();
    forged["harness_sha256"] = serde_json::json!(hash(modified));
    fs::write(
        &f.policy.a4_manifest_path,
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_and_build_launch(&f.request, &f.policy),
        Err(WorkerError::UnverifiedToolchain)
    ));
}

fn rewrite(
    f: &mut Fixture,
    lock_change: impl FnOnce(&mut serde_json::Value),
    a4_change: impl FnOnce(&mut serde_json::Value),
) {
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.policy.target_lock_path).unwrap()).unwrap();
    lock_change(&mut lock);
    f.policy.pinned_target_lock_sha256 = write(
        &f.policy.target_lock_path,
        &serde_json::to_vec(&lock).unwrap(),
    );
    f.request.target_lock_sha256 = f.policy.pinned_target_lock_sha256.clone();
    let mut a4: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.policy.a4_manifest_path).unwrap()).unwrap();
    a4["toolchain_lock_sha256"] = serde_json::json!(f.policy.pinned_target_lock_sha256);
    a4_change(&mut a4);
    f.policy.pinned_a4_manifest_sha256 = write(
        &f.policy.a4_manifest_path,
        &serde_json::to_vec(&a4).unwrap(),
    );
}

#[test]
fn rejects_pinned_but_invalid_native_contract() {
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("source_tag", serde_json::json!("untrusted")),
        ("source_commit", serde_json::json!("0".repeat(40))),
        ("architecture", serde_json::json!("x86")),
        ("harness_entry", serde_json::json!("other")),
        ("nargs", serde_json::json!(2)),
        ("target_id", serde_json::json!("other")),
    ] {
        let mut f = fixture();
        rewrite(&mut f, |v| v[key] = value, |_| {});
        assert!(
            verify_and_build_launch(&f.request, &f.policy).is_err(),
            "accepted {key}"
        );
    }
    for (key, value) in [
        ("cycles", serde_json::json!(11)),
        ("confirmed_map_nonzero_bytes", serde_json::json!(65537)),
        ("target_method", serde_json::json!("other")),
        ("target_module", serde_json::json!("other.exe")),
        ("confirmed_modules", serde_json::json!(["unrelated.dll"])),
        (
            "confirmed_modules",
            serde_json::json!(["PdfFilter.dll", "pdffilter.dll"]),
        ),
    ] {
        let mut f = fixture();
        rewrite(&mut f, |_| {}, |v| v[key] = value);
        assert!(
            verify_and_build_launch(&f.request, &f.policy).is_err(),
            "accepted A4 {key}"
        );
    }
}

#[test]
fn rejects_correctly_hashed_non_x64_binary() {
    for machine in [0x014c_u16, 0xaa64] {
        let mut f = fixture();
        let mut bytes = pe(b"wrong architecture");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        let digest = write(&f.policy.harness_path, &bytes);
        rewrite(
            &mut f,
            |_| {},
            |v| v["harness_sha256"] = serde_json::json!(digest),
        );
        assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    }
}

#[test]
fn rejects_lexical_traversal_even_when_it_resolves_inside_root() {
    let mut f = fixture();
    fs::create_dir(f.policy.allowed_binary_root.join("nested")).unwrap();
    f.policy.harness_path = f
        .policy
        .allowed_binary_root
        .join("nested/../sumatrafuzz-harness.exe");
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}

#[test]
fn rejects_a_file_as_output_root() {
    let mut f = fixture();
    f.policy.output_root = f.policy.harness_path.clone();
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}

#[test]
fn each_missing_or_changed_native_component_is_denied() {
    for component in [
        "sumatrafuzz-harness.exe",
        "PdfFilter.dll",
        "libmupdf.dll",
        "afl-fuzz.exe",
        "drrun.exe",
        "winafl.dll",
    ] {
        for missing in [false, true] {
            let f = fixture();
            let root = if component == "sumatrafuzz-harness.exe"
                || component == "PdfFilter.dll"
                || component == "libmupdf.dll"
            {
                &f.policy.allowed_binary_root
            } else {
                &f.policy.allowed_tool_root
            };
            let path = root.join(component);
            if missing {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, b"tampered").unwrap();
            }
            assert!(
                verify_and_build_launch(&f.request, &f.policy).is_err(),
                "accepted {component}"
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn verified_files_and_ancestors_remain_locked_until_spec_is_dropped() {
    let f = fixture();
    let spec = verify_and_build_launch(&f.request, &f.policy).unwrap();
    assert!(fs::write(&f.policy.harness_path, b"changed after verification").is_err());
    assert!(fs::remove_file(&f.policy.a4_manifest_path).is_err());
    let moved = f.policy.allowed_binary_root.with_extension("moved");
    assert!(fs::rename(&f.policy.allowed_binary_root, &moved).is_err());
    drop(spec);
    fs::write(&f.policy.harness_path, b"released").unwrap();
    fs::rename(&f.policy.allowed_binary_root, moved).unwrap();
}

#[test]
fn malformed_manifests_and_unbounded_policy_fail_closed() {
    for bytes in [
        b"not JSON".as_slice(),
        b"{}",
        b"{\"source_commit\":\"x\",\"source_commit\":\"y\"}",
    ] {
        let mut f = fixture();
        f.policy.pinned_target_lock_sha256 = write(&f.policy.target_lock_path, bytes);
        f.request.target_lock_sha256 = f.policy.pinned_target_lock_sha256.clone();
        assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
        let mut f = fixture();
        f.policy.pinned_a4_manifest_sha256 = write(&f.policy.a4_manifest_path, bytes);
        assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    }
    let mut f = fixture();
    f.policy.max_limits.max_cpu_percent = NonZeroU8::new(101).unwrap();
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    for field in 0..4 {
        let mut f = fixture();
        match field {
            0 => f.request.limits.max_duration_s = NonZeroU64::new(u64::MAX).unwrap(),
            1 => f.request.limits.max_memory_bytes = NonZeroU64::new(u64::MAX).unwrap(),
            2 => f.request.limits.max_disk_bytes = NonZeroU64::new(u64::MAX).unwrap(),
            _ => f.request.limits.max_cpu_percent = NonZeroU8::new(100).unwrap(),
        }
        assert!(matches!(
            verify_and_build_launch(&f.request, &f.policy),
            Err(WorkerError::LimitExceeded)
        ));
    }
}

#[test]
fn labels_cannot_add_arguments_and_bundle_paths_are_denied() {
    let mut f = fixture();
    f.request.label = "& cmd.exe /c arbitrary -- -target_method other".into();
    let spec = verify_and_build_launch(&f.request, &f.policy).unwrap();
    assert!(!spec
        .argv()
        .iter()
        .any(|arg| arg.to_string_lossy().contains("arbitrary")));
    drop(spec);
    for bundle in [
        "../escape",
        "..\\escape",
        "C:\\escape",
        "//server/share",
        "a/b",
    ] {
        f.request.input_bundle_id = bundle.into();
        assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    }
}

#[test]
fn redirected_corpus_is_denied() {
    let f = fixture();
    let moved = f.bundle.with_extension("moved");
    fs::rename(&f.bundle, &moved).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&moved, &f.bundle).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&f.bundle)
        .arg(&moved)
        .status()
        .unwrap()
        .success());
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    #[cfg(windows)]
    fs::remove_dir(&f.bundle).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_namespace_aliases_are_denied_before_open() {
    for path in [
        r"\\server\share\target.exe",
        r"\\?\C:\target.exe",
        r"\\.\C:\target.exe",
        r"C:\target.exe:stream",
        r"C:\folder.\target.exe",
        r"C:\folder \target.exe",
        r"C:relative.exe",
    ] {
        let mut f = fixture();
        f.policy.harness_path = path.into();
        assert!(
            verify_and_build_launch(&f.request, &f.policy).is_err(),
            "accepted {path}"
        );
    }
}

#[test]
fn redirected_seed_inside_admitted_bundle_is_denied() {
    let f = fixture();
    let seed = f.bundle.join("redirect.pdf");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&f.policy.harness_path, &seed).unwrap();
    #[cfg(windows)]
    {
        // A directory junction requires no symlink privilege, even for a standard user.
        assert!(std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&seed)
            .arg(&f.policy.allowed_binary_root)
            .status()
            .unwrap()
            .success());
    }
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
    #[cfg(windows)]
    fs::remove_dir(seed).unwrap();
}

#[test]
fn verified_drrun_cannot_authorize_a_different_runtime_executable() {
    let mut f = fixture();
    let copy = f.policy.allowed_tool_root.join("approved-copy.exe");
    fs::copy(f.policy.allowed_tool_root.join("drrun.exe"), &copy).unwrap();
    rewrite(
        &mut f,
        |v| v["tools"]["drrun"]["path"] = serde_json::json!(copy),
        |_| {},
    );
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}

#[test]
fn runtime_helpers_and_dependencies_must_match_provisioned_inventory() {
    let f = fixture();
    fs::write(
        f.policy.allowed_tool_root.join("drconfig.exe"),
        b"substituted helper",
    )
    .unwrap();
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}

#[test]
fn unsafe_downstream_dynamorio_paths_are_rejected() {
    let mut f = fixture();
    let dir = f.policy.allowed_tool_root.join("unsafe space");
    fs::create_dir(&dir).unwrap();
    let path = dir.join("winafl.dll");
    fs::copy(f.policy.allowed_tool_root.join("winafl.dll"), &path).unwrap();
    rewrite(
        &mut f,
        |v| v["tools"]["winafl_client"]["path"] = serde_json::json!(path),
        |_| {},
    );
    assert!(verify_and_build_launch(&f.request, &f.policy).is_err());
}

#[test]
fn native_working_directory_cannot_search_writable_evidence_for_helpers() {
    let f = fixture();
    let spec = verify_and_build_launch(&f.request, &f.policy).unwrap();
    assert_eq!(
        spec.working_dir(),
        fs::canonicalize(&f.policy.allowed_tool_root).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn empty_output_root_cannot_be_replaced_while_verified() {
    let f = fixture();
    let spec = verify_and_build_launch(&f.request, &f.policy).unwrap();
    let moved = f.policy.output_root.with_extension("moved");
    assert!(fs::rename(&f.policy.output_root, &moved).is_err());
    drop(spec);
    fs::rename(&f.policy.output_root, moved).unwrap();
}

#[cfg(windows)]
#[test]
fn admitted_corpus_namespace_cannot_gain_a_queue_after_verification() {
    let f = fixture();
    let spec = verify_and_build_launch(&f.request, &f.policy).unwrap();
    let args = spec.argv();
    let input = PathBuf::from(&args[1]);
    assert!(fs::create_dir(input.join("queue")).is_err());
    assert!(fs::write(input.join("new.pdf"), b"unverified").is_err());
    assert!(std::fs::OpenOptions::new()
        .write(true)
        .open(input.join("a.pdf"))
        .is_err());
}
