//! Runs only in the genuine, disposable, standard-user Windows native gate.
#![cfg(windows)]
use sha2::{Digest, Sha256};
use std::{
    fs,
    num::{NonZeroU64, NonZeroU8},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use worker_core::{verify_and_build_launch, WorkerPolicy};
use worker_protocol::{CampaignLimits, ControllerId, RunRequest};

struct NativeChild(Child);
impl Drop for NativeChild {
    fn drop(&mut self) {
        // Test-only teardown; production Job Object supervision is tracked by #41.
        let _ = Command::new("taskkill.exe")
            .args(["/PID", &self.0.id().to_string(), "/T", "/F"])
            .status();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires pinned genuine A4-A6 artifacts and a disposable standard-user Windows x64 environment"]
fn genuine_native_launch_matches_a5_and_preserves_file_guards() {
    assert_eq!(std::env::consts::ARCH, "x86_64");
    let root =
        PathBuf::from(std::env::var_os("SUMATRAFUZZ_NATIVE_ROOT").expect("native gate root"));
    let context: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("runs/native-execution-context.json")).unwrap())
            .unwrap();
    assert_eq!(context["administrator"], false);
    let digest = |path: &std::path::Path| format!("{:x}", Sha256::digest(fs::read(path).unwrap()));
    let lock_path = root.join("external/native-tools/locks/target-lock.json");
    let a4_path = root.join("runs/a4/debug-evidence/a4-confirmed.json");
    let limits = CampaignLimits {
        max_duration_s: NonZeroU64::new(180).unwrap(),
        max_memory_bytes: NonZeroU64::new(512 * 1024 * 1024).unwrap(),
        max_disk_bytes: NonZeroU64::new(2 * 1024 * 1024 * 1024).unwrap(),
        max_cpu_percent: NonZeroU8::new(75).unwrap(),
    };
    let output = root.join("runs/worker-native");
    fs::create_dir(&output).unwrap();
    // The CI setup owns these anchors; no controller payload can supply either.
    let policy = WorkerPolicy {
        max_limits: limits,
        pinned_target_lock_sha256: digest(&lock_path),
        pinned_a4_manifest_sha256: digest(&a4_path),
        target_lock_path: lock_path,
        a4_manifest_path: a4_path,
        harness_path: root.join("build/a3/Release/sumatrafuzz-harness.exe"),
        allowed_binary_root: root.join("build/a3/Release"),
        allowed_tool_root: root.join("external/native-tools"),
        allowed_input_root: root.join("runs/a5"),
        output_root: output,
    };
    let request = RunRequest {
        request_id: Uuid::new_v4(),
        controller_id: ControllerId(Uuid::new_v4()),
        input_bundle_id: "seeds".into(),
        target_lock_sha256: policy.pinned_target_lock_sha256.clone(),
        limits,
        label: "genuine worker argv acceptance".into(),
    };
    let spec = verify_and_build_launch(&request, &policy).unwrap();
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(&policy.harness_path)
        .is_err());
    // Diagnostic-only isolation of the known #85 failure. This is the same
    // pinned parser and immutable seed snapshot used by the real worker run.
    // Do not skip or replace the subsequent instrumented WinAFL acceptance.
    let mut seeds = fs::read_dir(&spec.argv()[1])
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    seeds.sort();
    assert!(!seeds.is_empty(), "sealed worker input is empty");
    let seed = &seeds[0];
    let mut probe = Command::new(&policy.harness_path)
        .arg(seed)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch pinned harness on sealed seed");
    let probe_begin = Instant::now();
    loop {
        if let Some(result) = probe.try_wait().unwrap() {
            assert!(result.success(), "pinned harness rejected sealed seed: {result}");
            break;
        }
        if probe_begin.elapsed() > Duration::from_secs(20) {
            let _ = probe.kill();
            let _ = probe.wait();
            panic!("pinned harness cannot parse sealed snapshot seed within 20s");
        }
        thread::sleep(Duration::from_millis(200));
    }
    eprintln!(
        "native diagnostic: sealed corpus seed count={}, direct pinned parser elapsed_ms={}",
        seeds.len(),
        probe_begin.elapsed().as_millis()
    );
    let a5: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("runs/a5/campaign/campaign-metadata.json")).unwrap(),
    )
    .unwrap();
    let previous = a5["argv"].as_array().unwrap();
    assert_eq!(
        spec.executable(),
        fs::canonicalize(previous[0].as_str().unwrap()).unwrap()
    );
    let args = spec.argv();
    assert_eq!(args.len() + 1, previous.len());
    for (i, (arg, evidence)) in args.iter().zip(&previous[1..]).enumerate() {
        if i == 1 || i == 3 {
            continue;
        } // A sealed input snapshot and a new output directory are run-specific.
        let value = evidence.as_str().unwrap();
        if PathBuf::from(value).is_absolute() {
            assert_eq!(PathBuf::from(arg), fs::canonicalize(value).unwrap());
        } else {
            assert_eq!(arg.to_str().unwrap(), value);
        }
    }
    let log = fs::File::create(root.join("runs/worker-native.stdout.log")).unwrap();
    let mut process = NativeChild(
        Command::new(spec.executable())
            .args(spec.argv())
            .current_dir(spec.working_dir())
            .env("AFL_NO_UI", "1")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let begin = Instant::now();
    let stats = spec.evidence_dir().join("fuzzer_stats");
    let mut first = None;
    let count = loop {
        if let Some(exit) = process.0.try_wait().unwrap() {
            let output = fs::read_to_string(root.join("runs/worker-native.stdout.log"))
                .unwrap_or_else(|_| "native stdout unavailable".to_owned());
            panic!("WinAFL exited early ({exit}); native diagnostic log: {output}");
        }
        assert!(
            begin.elapsed() < Duration::from_secs(180),
            "native worker argv did not reach 1000 actual executions"
        );
        if let Ok(raw) = fs::read_to_string(&stats) {
            if let Some(n) = raw
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.trim() == "execs_done")
                .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            {
                match first {
                    None => first = Some(n),
                    Some(start) if n > start && n >= 1000 => break n,
                    _ => {}
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    };
    drop(process); // Keep spec and its immutable-file handles alive until tree teardown.
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(&policy.harness_path)
        .is_err());
    fs::write(root.join("runs/worker-native-acceptance.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "source_commit": "16c59fde8b824ab54c56f23aef910a6fdd874ad0", "architecture": "x64", "administrator": false,
        "target_lock_sha256": policy.pinned_target_lock_sha256, "a4_manifest_sha256": policy.pinned_a4_manifest_sha256,
        "argv": spec.argv().iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(), "execs_done": count,
        "first_execs_done": first, "stop_reason": "bounded_acceptance_forced_tree_stop", "file_write_denied_while_verified": true
    })).unwrap()).unwrap();
    println!("Genuine worker argv reached {count} executions; matching A5, standard-user x64, guards retained");
}
