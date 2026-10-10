#pragma once

// One-time, per-thread initialization outside the WinAFL persistent target.
// WinAFL invokes fuzz_one_file on the same thread that reached it from wmain.
// No fake parser adapter may be linked into the real-engine executable.
bool prepare_sumatra_runtime();
void release_sumatra_runtime() noexcept;
