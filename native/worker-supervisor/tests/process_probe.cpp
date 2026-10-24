#ifdef _WIN32
#include "command_line.h"
#include "private_acl.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstring>
#include <iterator>
#include <sstream>
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

bool WriteNamedEventMarker(const std::wstring& evidence_dir) {
  const std::wstring path = evidence_dir + L"\\named-event-" + std::to_wstring(GetCurrentProcessId());
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const char data[] = "named event signaled";
  DWORD written = 0;
  const bool okay = WriteFile(file, data, sizeof(data), &written, nullptr) && written == sizeof(data);
  CloseHandle(file);
  return okay;
}

// Probe diagnostics intentionally contain only a stable code and Win32 error.
DWORD ProbeEventCreation(const std::wstring& name, SECURITY_ATTRIBUTES* attributes = nullptr) {
  SetLastError(ERROR_SUCCESS);
  HANDLE event = CreateEventExW(attributes, name.empty() ? nullptr : name.c_str(),
                                CREATE_EVENT_MANUAL_RESET,
                                EVENT_MODIFY_STATE | SYNCHRONIZE);
  const DWORD error = GetLastError();
  if (event) CloseHandle(event);
  return event ? (error == ERROR_ALREADY_EXISTS ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS) : error;
}

void WriteNamedEventFailureDiagnostic(const std::wstring& evidence_dir, DWORD error,
                                      DWORD unnamed_error, DWORD local_error,
                                      DWORD explicit_local_error) {
  const std::string contents = "private_event_failed=" + std::to_string(error) +
      ",unnamed_event_error=" + std::to_string(unnamed_error) +
      ",local_named_event_error=" + std::to_string(local_error) +
      ",explicit_local_event_error=" + std::to_string(explicit_local_error) + "\n";
  const std::wstring path = evidence_dir + L"\\named-event-diagnostic.txt";
  HANDLE report = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (report == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(report, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr);
  CloseHandle(report);
}

void WriteNamespaceFailureDiagnostic(const std::wstring& evidence_dir, unsigned stage, DWORD error) {
  const std::string contents = "namespace_initialization_stage=" + std::to_string(stage) +
      ",win32_error=" + std::to_string(error) + "\n";
  const std::wstring path = evidence_dir + L"\\namespace-diagnostic.txt";
  HANDLE report = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (report == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(report, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr);
  CloseHandle(report);
}

void WriteContainmentFailureDiagnostic(const std::wstring& evidence_dir, const char* stage,
                                       DWORD error) {
  const std::string contents = "containment_stage=" + std::string(stage) +
      ",win32_error=" + std::to_string(error) + "\n";
  const std::wstring path = evidence_dir + L"\\containment-diagnostic.txt";
  HANDLE report = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (report == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(report, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr);
  CloseHandle(report);
}

bool ValidAlias(const std::wstring& alias) {
  if (alias.size() != 41 || alias.compare(0, 5, L"SFWR-") != 0) return false;
  for (size_t i = 5; i < alias.size(); ++i) {
    if (i == 13 || i == 18 || i == 23 || i == 28) {
      if (alias[i] != L'-') return false;
    } else if (!((alias[i] >= L'0' && alias[i] <= L'9') ||
                 (alias[i] >= L'a' && alias[i] <= L'f') ||
                 (alias[i] >= L'A' && alias[i] <= L'F'))) return false;
  }
  return true;
}

bool RunSid(PSID sid) {
  SID_IDENTIFIER_AUTHORITY authority{{0x53, 0x46, 0x57, 0x52, 0x4b, 0x31}};
  return sid && IsValidSid(sid) && *GetSidSubAuthorityCount(sid) == 3 &&
      std::memcmp(GetSidIdentifierAuthority(sid), &authority, sizeof(authority)) == 0;
}

struct ProbeNamespace {
  HANDLE token = nullptr;
  HANDLE boundary = nullptr;
  HANDLE handle = nullptr;
  std::vector<BYTE> user;
  std::wstring alias;
  ~ProbeNamespace() {
    if (handle) ClosePrivateNamespace(handle, 0);
    if (boundary) DeleteBoundaryDescriptor(boundary);
    if (token) CloseHandle(token);
  }
  bool Initialize(unsigned* failure_stage = nullptr, DWORD* failure_error = nullptr) {
    const auto fail = [failure_stage, failure_error](unsigned stage, DWORD error) {
      if (failure_stage) *failure_stage = stage;
      if (failure_error) *failure_error = error;
      return false;
    };
    const auto fail_last_error = [&fail](unsigned stage) { return fail(stage, GetLastError()); };
    wchar_t alias_text[64]{}, sid_text[185]{};
    const DWORD alias_size = GetEnvironmentVariableW(L"SUMATRAFUZZ_NAMESPACE_ALIAS", alias_text, 64);
    const DWORD sid_size = GetEnvironmentVariableW(L"SUMATRAFUZZ_RUN_SID", sid_text, 185);
    if (!alias_size || alias_size >= 64 || !sid_size || sid_size >= 185)
      return fail_last_error(1);
    alias = alias_text;
    PSID run_sid = nullptr;
    if (!ValidAlias(alias) || !ConvertStringSidToSidW(sid_text, &run_sid) ||
        !RunSid(run_sid)) {
      if (run_sid) LocalFree(run_sid);
      return fail_last_error(2);
    }
    LPWSTR canonical = nullptr;
    if (!ConvertSidToStringSidW(run_sid, &canonical)) {
      LocalFree(run_sid);
      return fail_last_error(3);
    }
    const bool exact = std::wstring(canonical) == sid_text;
    LocalFree(canonical);
    if (!exact) {
      LocalFree(run_sid);
      return fail_last_error(4);
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      LocalFree(run_sid);
      return fail_last_error(5);
    }
    DWORD bytes = 0;
    GetTokenInformation(token, TokenRestrictedSids, nullptr, 0, &bytes);
    if (!bytes) {
      LocalFree(run_sid);
      return fail_last_error(6);
    }
    std::vector<BYTE> restrictions(bytes);
    if (!GetTokenInformation(token, TokenRestrictedSids, restrictions.data(), bytes, &bytes)) {
      LocalFree(run_sid);
      return fail_last_error(7);
    }
    auto* groups = reinterpret_cast<TOKEN_GROUPS*>(restrictions.data());
    unsigned matches = 0, run_sids = 0;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
      if (RunSid(groups->Groups[i].Sid)) ++run_sids;
      if (EqualSid(groups->Groups[i].Sid, run_sid)) ++matches;
    }
    if (matches != 1 || run_sids != 1) {
      LocalFree(run_sid);
      return fail_last_error(8);
    }
    bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (!bytes) {
      LocalFree(run_sid);
      return fail_last_error(9);
    }
    user.resize(bytes);
    const bool user_read = GetTokenInformation(token, TokenUser, user.data(), bytes, &bytes) != FALSE;
    LocalFree(run_sid);
    if (!user_read) return fail_last_error(10);
    return true;
  }
  bool Open(const std::wstring& target_alias) {
    if (!ValidAlias(target_alias)) { SetLastError(ERROR_INVALID_NAME); return false; }
    boundary = CreateBoundaryDescriptorW(target_alias.c_str(), 0);
    if (!boundary || !AddSIDToBoundaryDescriptor(&boundary,
        reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid)) return false;
    handle = OpenPrivateNamespaceW(boundary, target_alias.c_str());
    return handle != nullptr;
  }
};

bool ProtectedReadsAndWritesDenied(const std::wstring& protected_read,
                                   const std::wstring& protected_write,
                                   const std::wstring& evidence_dir) {
  HANDLE read_file = CreateFileW(protected_read.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (read_file != INVALID_HANDLE_VALUE) {
    CloseHandle(read_file);
    WriteContainmentFailureDiagnostic(evidence_dir, "protected_read_unexpected_success",
                                      ERROR_SUCCESS);
    return false;
  }
  const DWORD read_error = GetLastError();
  if (read_error != ERROR_ACCESS_DENIED) {
    WriteContainmentFailureDiagnostic(evidence_dir, "protected_read", read_error);
    return false;
  }
  HANDLE write_file = CreateFileW(protected_write.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (write_file != INVALID_HANDLE_VALUE) {
    CloseHandle(write_file);
    DeleteFileW(protected_write.c_str());
    WriteContainmentFailureDiagnostic(evidence_dir, "protected_write_unexpected_success",
                                      ERROR_SUCCESS);
    return false;
  }
  const DWORD write_error = GetLastError();
  if (write_error != ERROR_ACCESS_DENIED) {
    WriteContainmentFailureDiagnostic(evidence_dir, "protected_write", write_error);
    return false;
  }
  return true;
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
  const std::wstring object_name = argv[probe_index + 5];
  if (object_name.empty() || object_name.size() > 128 ||
      object_name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") != std::wstring::npos) return 30;
  ProbeNamespace ns;
  unsigned namespace_stage = 0;
  DWORD namespace_error = ERROR_SUCCESS;
  if (!ns.Initialize(&namespace_stage, &namespace_error)) {
    WriteNamespaceFailureDiagnostic(evidence_dir, namespace_stage, namespace_error);
    return 30;
  }
  if (!ns.Open(ns.alias)) return 31;
  const std::wstring event_name = ns.alias + L"\\" + object_name;
  const bool grandchild = argc > probe_index + 6 && std::wstring(argv[probe_index + 6]) == L"--grandchild";
  const bool child = grandchild || (argc > probe_index + 6 && std::wstring(argv[probe_index + 6]) == L"--child");
  if (!WriteEvidenceFile(evidence_dir)) {
    WriteContainmentFailureDiagnostic(evidence_dir, "evidence_write", GetLastError());
    return 21;
  }
  if (!ReadAllowedInput(input_path)) {
    WriteContainmentFailureDiagnostic(evidence_dir, "input_read", GetLastError());
    return 21;
  }
  if (!ProtectedReadsAndWritesDenied(protected_read, protected_write, evidence_dir)) return 21;
  if (child) {
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name.c_str());
    if (!event) return 2200 + static_cast<int>(GetLastError());
    const bool signaled = SetEvent(event) != FALSE;
    CloseHandle(event);
    if (!signaled) return 23;
    if (!WriteNamedEventMarker(evidence_dir)) return 27;
    if (grandchild) { for (;;) Sleep(1000); }
    const std::vector<std::wstring> descendants{
        argv[0], L"--containment-probe", evidence_dir, input_path,
        protected_read, protected_write, object_name, L"--grandchild"};
    std::wstring command = sumatrafuzz::supervisor::BuildWindowsCommandLine(descendants);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) return 25;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    for (;;) Sleep(1000);
  }

  // Match the WinAFL shim: named objects receive an explicit protected DACL
  // granting access only to the worker identity and this run's random SID.
  wchar_t run_sid_text[185]{};
  const DWORD run_sid_size = GetEnvironmentVariableW(L"SUMATRAFUZZ_RUN_SID", run_sid_text,
                                                       static_cast<DWORD>(std::size(run_sid_text)));
  PSID run_sid = nullptr;
  if (!run_sid_size || run_sid_size >= std::size(run_sid_text) ||
      !ConvertStringSidToSidW(run_sid_text, &run_sid) || !RunSid(run_sid)) {
    if (run_sid) LocalFree(run_sid);
    return 29;
  }
  auto* token_user = reinterpret_cast<TOKEN_USER*>(ns.user.data());
  const ACCESS_MASK event_rights = EVENT_MODIFY_STATE | SYNCHRONIZE;
  const sumatrafuzz::supervisor::PrivateAclGrant event_grants[] = {
      {token_user->User.Sid, event_rights}, {run_sid, event_rights}};
  PACL event_acl = sumatrafuzz::supervisor::CreatePrivateAccessAcl(event_grants,
                                                                    std::size(event_grants));
  SECURITY_DESCRIPTOR event_descriptor{};
  const bool event_acl_ready = event_acl &&
      InitializeSecurityDescriptor(&event_descriptor, SECURITY_DESCRIPTOR_REVISION) &&
      SetSecurityDescriptorDacl(&event_descriptor, TRUE, event_acl, FALSE) &&
      SetSecurityDescriptorControl(&event_descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
  if (!event_acl_ready) {
    if (event_acl) LocalFree(event_acl);
    LocalFree(run_sid);
    return 29;
  }
  SECURITY_ATTRIBUTES event_attributes{sizeof(event_attributes), &event_descriptor, FALSE};
  SetLastError(ERROR_SUCCESS);
  HANDLE event = CreateEventExW(&event_attributes, event_name.c_str(), CREATE_EVENT_MANUAL_RESET,
                                event_rights);
  const DWORD event_error = GetLastError();
  if (!event || event_error == ERROR_ALREADY_EXISTS) {
    const DWORD error = event_error;
    if (event) CloseHandle(event);
    // Gather safe comparisons only after the required private-namespace event
    // fails. This distinguishes token default-DACL failures from namespace
    // object-creation failures without weakening the acceptance check.
    const DWORD unnamed_error = ProbeEventCreation(L"");
    const std::wstring local_name = L"Local\\SFProbe-" + std::to_wstring(GetCurrentProcessId());
    const DWORD local_error = ProbeEventCreation(local_name);
    const DWORD explicit_local_error = ProbeEventCreation(local_name, &event_attributes);
    WriteNamedEventFailureDiagnostic(evidence_dir, error, unnamed_error, local_error,
                                     explicit_local_error);
    LocalFree(event_acl);
    LocalFree(run_sid);
    return 2400 + static_cast<int>(error);
  }
  LocalFree(event_acl);
  LocalFree(run_sid);
  const std::wstring name_path = evidence_dir + L"\\private-event-name.txt";
  HANDLE name_file = CreateFileW(name_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (name_file == INVALID_HANDLE_VALUE) { CloseHandle(event); return 28; }
  const std::string name(event_name.begin(), event_name.end());
  DWORD written = 0;
  const bool saved = WriteFile(name_file, name.data(), static_cast<DWORD>(name.size()), &written, nullptr) && written == name.size();
  CloseHandle(name_file);
  if (!saved) { CloseHandle(event); return 28; }
  const std::vector<std::wstring> arguments{
      argv[0], L"--containment-probe", evidence_dir, input_path,
      protected_read, protected_write, object_name, L"--child"};
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
  if (argc == 3 && std::wstring(argv[1]) == L"--namespace-gone") {
    ProbeNamespace ns;
    if (!ValidAlias(argv[2]) || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ns.token)) return 44;
    DWORD bytes = 0;
    GetTokenInformation(ns.token, TokenUser, nullptr, 0, &bytes);
    if (!bytes) return 44;
    ns.user.resize(bytes);
    if (!GetTokenInformation(ns.token, TokenUser, ns.user.data(), bytes, &bytes)) return 44;
    if (ns.Open(argv[2])) return 45;
    // Access denied would only establish isolation, not destruction.
    return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND ? 0 : 46;
  }
  if (argc == 2 && std::wstring(argv[1]) == L"--validate-identifiers") {
    ProbeNamespace ns;
    return ns.Initialize() ? 0 : 30;
  }
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::wstring(argv[i]) == L"--deny-open-event") {
      ProbeNamespace ns;
      if (!ns.Initialize()) return 30;
      const std::wstring name = argv[i + 1];
      const size_t separator = name.find(L'\\');
      if (separator == std::wstring::npos || !ValidAlias(name.substr(0, separator))) return 43;
      // A private alias must be opened in this process before addressing its objects.
      // Denial at namespace entry is sufficient; never fall back to a session name.
      if (!ns.Open(name.substr(0, separator))) return GetLastError() == ERROR_ACCESS_DENIED ? 0 : 42;
      HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
      if (event) {
        CloseHandle(event);
        return 41;
      }
      return GetLastError() == ERROR_ACCESS_DENIED ? 0 : 42;
    }
  }
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
