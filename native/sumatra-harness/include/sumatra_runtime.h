#pragma once

// Initializes the pinned SumatraPDF PDF filter once per process, outside the
// WinAFL-instrumented fuzz_one_file() entry point. Returns false on failure.
bool prepare_sumatra_runtime();

// Releases the process-level filter and COM state after normal CLI/test exit.
// Safe to call repeatedly. WinAFL persistence may bypass this on restart.
void release_sumatra_runtime() noexcept;
