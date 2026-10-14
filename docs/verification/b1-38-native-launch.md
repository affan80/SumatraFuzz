# B1.2 verified native launch boundary (#38)

Base native gate: `dev` d362f33c63b0969bfd6bdadd0dc45bd9fc066bdd,
[run 38299032438](https://github.com/affan80/SumatraFuzz/actions/runs/38299032438), all eight jobs passed.
This change includes the independent A4 digest fix from PR #80.

## Contract and provisioning

Administrator provisioning supplies the target-lock SHA-256 and the independent
A4 manifest SHA-256. Neither comes from the run request. Parse only the bounded
bytes authenticated by those digests (including a possible UTF-8 BOM).
Require schema 1, SumatraPDF `3.6.1rel` / `16c59fde8b824ab54c56f23aef910a6fdd874ad0`,
x64 PE headers, the pinned WinAFL/DynamoRIO acquisition, `fuzz_one_file` with one
argument, and genuine ten-cycle A4 metadata for both parser DLLs.

Provisioning records a `runtime_files` inventory of x64 DynamoRIO and WinAFL
PE components. Verify and retain handles for every listed file, including the
`drconfig.exe` helper that WinAFL uses during shutdown. Older locks without this
inventory fail closed; regenerate them using the pinned provisioning script,
rerun A4–A6, review the results, and provision both new digests out of band.
The installation trees and policy must remain administrator-owned; a lock is
not an installer or a scanner for arbitrary third-party DLL dependencies.

Pinned WinAFL constructs an unquoted downstream DynamoRIO command line.
Therefore the worker rejects whitespace/quotes in DynamoRIO and client paths
and requires the checked runner to be named `drrun.exe`. Install tools under a
simple local path such as `C:\SumatraFuzz\tools`. Do not quote or sanitize an
unsafe path into a different executable identity.

Reject lexical traversal, relative/UNC/device/alternate-stream paths, redirected
ancestors, files used as directory roots, redirected/nonregular corpus entries,
empty bundles, more than 10,000 seeds, and seed bytes above the requested disk
ceiling. All four requested resource values must fit the administrator policy.
Only the verifier builds the executable, working directory and `Vec<OsString>`;
the returned plan exposes read-only accessors and cannot be freely constructed.

## Lifetime and concurrency

On Windows, open ancestors without delete sharing and verified files without
write/delete sharing, inspect the opened handle for reparse attributes, and
keep handles in `VerifiedRunSpec`. Directory opens request read-data access so
they participate in Windows sharing checks. Existing writable handles cause verification
to fail rather than racing a writer. Seed files are copied into a private per-run snapshot created with a protected
Windows DACL. After copying, deny directory mutation and owner WRITE_DAC through
an OWNER RIGHTS ACE, then retain file locks. This prevents a late `queue`
junction or new seed from changing what WinAFL reads. A noninherited cleanup
handle acquired before sealing restores access when the spec is dropped. The
snapshot is removed after its file handles close; campaign evidence is retained.
Other processes running under the trusted worker identity must not be hostile:
same-account process-handle attacks are outside a filesystem verifier boundary.

The current directory is the administrator-provisioned WinAFL binary directory,
so WinAFL's unqualified `taskkill` fallback does not search writable evidence.
Keep installation directories administrator-owned and exclude attacker-created
executables from them.
The future supervisor must own the spec until every descendant exits; dropping
it immediately after spawn releases the protection. Unix verification is useful
for portable tests but does not claim Windows sharing-lock semantics.

This verifier does not spawn. Production token enforcement, suspended creation,
Job Object assignment, descendant teardown and CPU/memory/time/disk enforcement
remain #41. This change adds a real standard-user integration test of the Rust
argv under the existing disposable Windows native gate; its forced tree stop
is test teardown and is not the production Job Object runner.

## Failure, rollback and recovery

Validation failure returns a typed error before a launch spec exists. Handles
close through RAII; no subprocess starts. The verifier creates and seals a
private corpus snapshot, removes it on failure/drop, and does not create the
campaign evidence directory. A new UUID output path never overwrites an existing campaign.
The runner must exclusively create/reserve that directory before executing,
and hold the spec for the whole process tree. Slot ownership and atomic output
reservation remain supervisor/coordinator responsibilities.

On drift or sharing failure, stop preparation, restore the reviewed pinned
installation or reprovision and regenerate genuine A4–A6 evidence. Do not edit
hashes to accept a failed file. To roll back, disable new starts and restore the
previous reviewed worker together with its matching policy and manifests;
preserve run evidence. Do not fall back to a shell or an unchecked launcher.

## Observed test-first evidence

`cargo test -p worker-core --test verified_launch --locked` initially reported
7 passed / 4 failed: invalid contract, x86/ARM binary, lexical traversal and
file-valued output root. After implementing their checks all passed.

A second RED pass reported 14 passed / 4 failed: redirected seed, substituted
runtime helper, whitespace client path, and a renamed verified runner beside
the executable WinAFL actually selects. All four pass after the shared fix.

Local verification: `cargo test --workspace --all-targets --locked`,
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
and `git diff --check`. Windows-only results require CI and are not inferred
from this macOS host.

The unchanged native A4–A6 gates remain required. The additional ignored Rust
native test is explicitly invoked by that gate as its standard user; a missing
binary or failed test fails the gate. It compares the entire argv to actual A5
evidence (apart from the sealed input snapshot and new output directory), runs the Rust-produced command,
requires increasing real WinAFL counters and at least 1,000 executions, and
checks that the genuine harness remains write-locked through process teardown.
`worker-native-acceptance.json` contains the source pin, both manifest digests,
argv, observed counters and forced-stop reason; no PDFs or crash samples are
uploaded. Final CI links are recorded in the implementing PR.

## Independent review regressions

Independent read-only review found three bypasses in the first candidate.
[Windows RED run 38633332067](https://github.com/affan80/SumatraFuzz/actions/runs/38633332067/job/116090179482)
reproduced all three: empty output root replacement, new `queue` directory after
verification, and a writable native working directory (20 passed / 3 failed).
The corrected implementation uses participating directory access, a sealed
snapshot, and a trusted binary working directory. Windows GREEN and native
results are recorded on the final PR commit.

Windows security semantics reference:
[OWNER RIGHTS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
