#pragma once

#include <cstdint>
#include <vector>

namespace sumatrafuzz::service_host {

// The worker and SCM host share a four-byte little-endian length followed by
// one of these fixed ASCII tokens on child stdin/stdout (stderr is redirected
// to NUL). READY is emitted only after startup; STOPPED only after teardown.
// No variable payload is accepted and stdout must not carry application logs.
enum class ControlFrame : std::uint8_t { Ready, Stop, Stopped, TrustOperationResult };
constexpr std::uint32_t kMaxControlFrameBytes = 64;
constexpr std::uint32_t kMaxTrustOperationBytes = 1024 * 1024 + 1;

std::vector<std::uint8_t> EncodeControlFrame(ControlFrame frame);
bool DecodeControlFrame(const std::vector<std::uint8_t>& bytes, ControlFrame* frame);
std::vector<std::uint8_t> EncodeTrustOperationRequest(const std::vector<std::uint8_t>& bundle);
bool DecodeTrustOperationResponse(const std::vector<std::uint8_t>& bytes, bool* succeeded);

enum class ServiceState : std::uint8_t { Stopped, StartPending, Running, StopPending };
bool IsAllowedTransition(ServiceState from, ServiceState to);

// Entry point for the standalone Windows SCM host executable. Non-Windows
// builds return an error so accidental use cannot look like service success.
int RunWindowsService();

}  // namespace sumatrafuzz::service_host
