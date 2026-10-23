#include "service_host.h"

#include <cassert>
#include <cstdint>
#include <vector>

using namespace sumatrafuzz::service_host;

int main() {
  for (const auto frame : {ControlFrame::Ready, ControlFrame::Stop, ControlFrame::Stopped}) {
    const auto bytes = EncodeControlFrame(frame);
    ControlFrame decoded{};
    assert(DecodeControlFrame(bytes, &decoded));
    assert(decoded == frame);
  }

  ControlFrame decoded{};
  assert(!DecodeControlFrame({}, &decoded));
  assert(!DecodeControlFrame({5, 0, 0, 0, 'R', 'E', 'A'}, &decoded)); // truncated
  assert(!DecodeControlFrame({1, 0, 0, 0, 'X'}, &decoded)); // unknown token
  assert(!DecodeControlFrame({65, 0, 0, 0}, &decoded)); // over bound
  assert(!DecodeControlFrame({5, 0, 0, 0, 'R', 'E', 'A', 'D', 'Y', 'X'}, &decoded)); // trailing byte
  assert(!DecodeControlFrame(EncodeControlFrame(ControlFrame::Stop), nullptr));
  assert(DecodeControlFrame({2, 0, 0, 0, 0x11, 0}, &decoded));
  assert(decoded == ControlFrame::TrustOperationResult);
  assert(DecodeControlFrame({2, 0, 0, 0, 0x11, 1}, &decoded));
  assert(decoded == ControlFrame::TrustOperationResult);
  assert(!DecodeControlFrame({2, 0, 0, 0, 0x11, 2}, &decoded));
  assert(EncodeControlFrame(ControlFrame::TrustOperationResult).empty());

  const std::vector<std::uint8_t> transaction{0x10, '{', '"', 'x', '"', ':', '1', '}'};
  const auto request = EncodeTrustOperationRequest(transaction);
  assert(request.size() == transaction.size() + 4);
  assert(request[0] == transaction.size() && request[4] == 0x10);
  assert(std::vector<std::uint8_t>(request.begin() + 4, request.end()) == transaction);
  assert(EncodeTrustOperationRequest({0x12, 'p'}).at(4) == 0x12);
  const std::vector<std::uint8_t> max_pairing(kMaxTrustOperationBytes, 0x41);
  std::vector<std::uint8_t> max_trust = max_pairing;
  max_trust[0] = 0x10;
  const auto max_trust_frame = EncodeTrustOperationRequest(max_trust);
  assert(max_trust_frame.size() == kMaxTrustOperationBytes + 4);
  assert(max_trust_frame[4] == 0x10);
  std::vector<std::uint8_t> max_pairing_frame_input = max_pairing;
  max_pairing_frame_input[0] = 0x12;
  const auto max_pairing_frame = EncodeTrustOperationRequest(max_pairing_frame_input);
  assert(max_pairing_frame.size() == kMaxTrustOperationBytes + 4);
  assert(max_pairing_frame[4] == 0x12);
  assert(EncodeTrustOperationRequest({}).empty());
  assert(EncodeTrustOperationRequest({0x11, 'x'}).empty());
  std::vector<std::uint8_t> oversized(kMaxTrustOperationBytes + 1, 0);
  oversized[0] = 0x10;
  assert(EncodeTrustOperationRequest(oversized).empty());
  bool succeeded = false;
  assert(DecodeTrustOperationResponse({2, 0, 0, 0, 0x11, 0}, &succeeded) && succeeded);
  assert(DecodeTrustOperationResponse({2, 0, 0, 0, 0x11, 1}, &succeeded) && !succeeded);
  assert(!DecodeTrustOperationResponse({2, 0, 0, 0, 0x11, 2}, &succeeded));
  assert(!DecodeTrustOperationResponse({2, 0, 0, 0, 0x10, 0}, &succeeded));
  assert(!DecodeTrustOperationResponse({2, 0, 0, 0, 0x11, 0}, nullptr));

  assert(IsAllowedTransition(ServiceState::Stopped, ServiceState::StartPending));
  assert(IsAllowedTransition(ServiceState::StartPending, ServiceState::Running));
  assert(IsAllowedTransition(ServiceState::Running, ServiceState::StopPending));
  assert(IsAllowedTransition(ServiceState::StopPending, ServiceState::Stopped));
  assert(!IsAllowedTransition(ServiceState::Stopped, ServiceState::Running));
  assert(!IsAllowedTransition(ServiceState::Running, ServiceState::StartPending));
  assert(!IsAllowedTransition(ServiceState::StopPending, ServiceState::Running));
  return 0;
}
