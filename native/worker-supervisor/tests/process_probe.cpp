#ifdef _WIN32
#include "command_line.h"

#include <windows.h>
#include <iterator>
#include <string>
#include <vector>

namespace {

bool WriteEvidenceFile(const std::wstring& evidence_dir) {
  const std::wstring path = evidence_dir + L"\\restricted-write-" + std::to_wstring(GetCurrentProcessId());
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const char data[] = "evidence";
  DWORD written = 0;
  const bool okay = WriteFile(file, data, sizeof(data), &written, nullptr) && written == sizeof(data);
  CloseHandle(file);
  return okay;
}

bool ProtectedReadsAndWritesDenied(const std::wstring& protected_read,
                                   const std::wstring& protected_write) {
  HANDLE read_file = CreateFileW(protected_read.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (read_file != INVALID_HANDLE_VALUE) {
    CloseHandle(read_file);
    return false;
  }
  if (GetLastError() != ERROR_ACCESS_DENIED) return false;
  HANDLE write_file = CreateFileW(protected_write.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (write_file != INVALID_HANDLE_VALUE) {
    CloseHandle(write_file);
    DeleteFileW(protected_write.c_str());
    return false;
  }
  return GetLastError() == ERROR_ACCESS_DENIED;
}

bool ReadAllowedInput(const std::wstring& input_path) {
  HANDLE input = CreateFileW(input_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (input == INVALID_HANDLE_VALUE) return false;
  char value = 0;
  DWORD read = 0;
  const bool okay = ReadFile(input, &value, 1, &read, nullptr) && read == 1 && value == 'p';
  CloseHandle(input);
  return okay;
}

int RunContainmentProbe(int argc, wchar_t** argv, int probe_index) {
  if (probe_index + 5 >= argc) return 20;
  const std::wstring evidence_dir = argv[probe_index + 1];
  const std::wstring input_path = argv[probe_index + 2];
  const std::wstring protected_read = argv[probe_index + 3];
  const std::wstring protected_write = argv[probe_index + 4];
  const std::wstring event_name = argv[probe_index + 5];
  const bool child = argc > probe_index + 6 && std::wstring(argv[probe_index + 6]) == L"--child";
  if (!WriteEvidenceFile(evidence_dir) || !ReadAllowedInput(input_path) ||
      !ProtectedReadsAndWritesDenied(protected_read, protected_write)) return 21;
  if (child) {
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name.c_str());
    if (!event) return 22;
    const bool signaled = SetEvent(event) != FALSE;
    CloseHandle(event);
    if (!signaled) return 23;
    for (;;) Sleep(1000);
  }

  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());
  if (!event) return 24;
  const std::vector<std::wstring> arguments{
      argv[0], L"--containment-probe", evidence_dir, input_path,
      protected_read, protected_write, event_name, L"--child"};
  std::wstring command = sumatrafuzz::supervisor::BuildWindowsCommandLine(arguments);
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                      nullptr, nullptr, &startup, &process)) {
    CloseHandle(event);
    return 25;
  }
  CloseHandle(process.hThread);
  const DWORD signaled = WaitForSingleObject(event, 10000);
  CloseHandle(event);
  if (signaled != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, ERROR_OPERATION_ABORTED);
    WaitForSingleObject(process.hProcess, 5000);
    CloseHandle(process.hProcess);
    return 26;
  }
  CloseHandle(process.hProcess);
  for (;;) Sleep(1000);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  wchar_t secret[16]{};
  if (GetEnvironmentVariableW(L"SUMATRAFUZZ_TEST_SECRET", secret, static_cast<DWORD>(std::size(secret))) > 0) return 11;
  for (int i = 1; i < argc; ++i) {
    if (std::wstring(argv[i]) == L"--containment-probe") return RunContainmentProbe(argc, argv, i);
  }
  if (argc > 1 && std::wstring(argv[1]) == L"--child") {
    for (;;) Sleep(1000);
  }
  std::wstring command = L"\"" + std::wstring(argv[0]) + L"\" --child";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return 10;
  CloseHandle(process.hThread);
  WaitForSingleObject(process.hProcess, INFINITE);
  CloseHandle(process.hProcess);
  return 0;
}
#else
int main() { return 77; }
#endif
