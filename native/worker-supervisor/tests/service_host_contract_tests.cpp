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

  assert(IsAllowedTransition(ServiceState::Stopped, ServiceState::StartPending));
  assert(IsAllowedTransition(ServiceState::StartPending, ServiceState::Running));
  assert(IsAllowedTransition(ServiceState::Running, ServiceState::StopPending));
  assert(IsAllowedTransition(ServiceState::StopPending, ServiceState::Stopped));
  assert(!IsAllowedTransition(ServiceState::Stopped, ServiceState::Running));
  assert(!IsAllowedTransition(ServiceState::Running, ServiceState::StartPending));
  assert(!IsAllowedTransition(ServiceState::StopPending, ServiceState::Running));
  return 0;
}
