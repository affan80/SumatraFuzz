# A6 — Crash and hang artifact inventory / controlled replay

The Stage A A5 reference campaign on the pinned Windows x64 target produced
**4,308 executions**, **154 paths**, **0 reported unique crashes** and
**118 reported unique hangs** in GitHub Actions run
[38037190073](https://github.com/affan80/SumatraFuzz/actions/runs/38037190073).
These are raw WinAFL counters, **not validated security vulnerabilities**.
A hang is only a *candidate* until replayed and classified.

## Evidence rules

`tools/evidence/collect.py` derives `crashes` and `hangs` inventories from
the **real** campaign's `crashes/id_*` and `hangs/id_*` files. For each actual
file, it records its relative path, SHA-256, byte size, replay argv and
`classification: untriaged`. It never fabricates an input for a counter.

The verifier **fails closed** if a nonzero unique crash/hang count has no
corresponding saved artifact, fewer files are saved than the reported unique
findings, or a finding path is a symlink/nonregular file. Ordinary README
files do not count as crash samples. Raw PDFs and dump files remain private
under the ignored `runs/` directory and are **not** uploaded to public
GitHub Actions artifacts. A summary with hashes is safe to retain only
after reviewing sample identifiers for sensitive content.

Pinned WinAFL writes `fuzzer_stats` periodically while saving individual
findings as they occur. The bounded runner explicitly records a forced stop,
so the final statistics file may precede the last saved sample. The manifest
preserves the original `metrics` unchanged and records `finding_counts` with
`reported_in_stats`, `saved_artifacts`, and `additional_saved_artifacts` for
each kind. Additional files are hashed and remain untriaged; they do not
silently increase reported WinAFL counters or establish reproducibility.

A `unique_hangs` counter is not evidence that each hang is reproducible;
the final report must distinguish saved findings, reproducible timeouts,
and rejected/benign files. Do not classify any as exploits automatically.

## Manual replay in a disposable, nonadministrator Windows x64 environment

After restoring the exact pinned harness and its two sibling parser DLLs,
the `runs/a5/campaign` directory and the matching `runs/a6/evidence.json`:

```powershell
pwsh -File scripts/windows/replay-input.ps1 `
  -EvidenceManifest 'C:\fuzz\runs\a6\evidence.json' `
  -RunDir 'C:\fuzz\runs\a5\campaign' `
  -HarnessExe 'C:\fuzz\build\a3\Release\sumatrafuzz-harness.exe' `
  -Finding 'hangs/id_000001'
```

Replace the `-Finding` value with an actual `path` from the manifest. The
script checks that the finding is inventoried, matches its SHA-256, does not
escape the run directory, and that the harness matches its original binary
hash. Only then does it invoke the genuine C++ harness with discrete argv.
Administrator execution is refused. Exit 0 means parsed; exit 1 means
controlled rejection; other exits need investigation. Replaying a hang with
a real timeout or under debugger requires a separate, controlled triage
session; this script does not falsely claim timeouts reproduce.

## Verification

```powershell
Import-Module Pester -MinimumVersion 5
Invoke-Pester -Path scripts/windows/tests/replay-input.Tests.ps1 -CI
```

```bash
python3 -m unittest discover -s tools/evidence/tests -v
```

Mocks/synthetic PDF samples in these unit tests verify fail-closed code
branches only. Acceptance of A6 still requires the genuine Windows x64
WinAFL campaign and matching raw source/tool/harness hashes, logs, counter
snapshots and queue/hang files.
