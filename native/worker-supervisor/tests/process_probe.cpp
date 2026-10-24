#ifdef _WIN32
#include "command_line.h"
#include "private_acl.h"

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>
#include <sddl.h>
#include <cstring>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>

namespace {

void ReportAppContainerFailure(const wchar_t* step, HRESULT result, DWORD win32_error) {
  std::fwprintf(stderr, L"AppContainer probe failed: step=%ls hresult=0x%08lx win32=%lu\n",
                step, static_cast<unsigned long>(result),
                static_cast<unsigned long>(win32_error));
}

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

bool AppContainerChild(const std::wstring& output, const std::wstring& world,
                       const std::wstring& authenticated, const std::wstring& world_low,
                       const std::wstring& authenticated_low) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD is_appcontainer = 0;
  DWORD bytes = 0;
  bool okay = GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer,
                                  sizeof(is_appcontainer), &bytes) && is_appcontainer != 0;
  // A zero-capability AppContainer is required; the package SID is separate
  // from TokenCapabilities and must not be counted as a granted capability.
  std::vector<BYTE> capabilities(sizeof(TOKEN_GROUPS));
  auto* groups = reinterpret_cast<TOKEN_GROUPS*>(capabilities.data());
  DWORD capability_bytes = static_cast<DWORD>(capabilities.size());
  okay = okay && GetTokenInformation(token, TokenCapabilities, groups, capability_bytes,
                                     &capability_bytes) && groups->GroupCount == 0;
  CloseHandle(token);
  if (!okay) return false;
  const std::wstring output_file = output + L"\\appcontainer-probe-result";
  HANDLE file = CreateFileW(output_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const char marker[] = "appcontainer-write";
  DWORD written = 0;
  okay = WriteFile(file, marker, sizeof(marker), &written, nullptr) && written == sizeof(marker);
  CloseHandle(file);
  for (const auto* sentinel : {&world, &authenticated, &world_low, &authenticated_low}) {
    SetLastError(ERROR_SUCCESS);
    HANDLE denied = CreateFileW(sentinel->c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD error = GetLastError();
    if (denied != INVALID_HANDLE_VALUE) CloseHandle(denied);
    okay = okay && denied == INVALID_HANDLE_VALUE && error == ERROR_ACCESS_DENIED;
  }
  return okay;
}

bool GrantAppContainerDirectoryAccess(const std::wstring& output, PSID sid) {
  PACL existing_dacl = nullptr;
  const DWORD query = GetNamedSecurityInfoW(const_cast<LPWSTR>(output.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, &existing_dacl, nullptr, nullptr);
  if (query != ERROR_SUCCESS) { SetLastError(query); return false; }
  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
  access.grfAccessMode = GRANT_ACCESS;
  access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
  PACL dacl = nullptr;
  const DWORD acl_result = SetEntriesInAclW(1, &access, existing_dacl, &dacl);
  if (existing_dacl) LocalFree(existing_dacl);
  if (acl_result != ERROR_SUCCESS) { SetLastError(acl_result); return false; }
  const DWORD result = SetNamedSecurityInfoW(const_cast<LPWSTR>(output.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
  LocalFree(dacl);
  if (result != ERROR_SUCCESS) SetLastError(result);
  return result == ERROR_SUCCESS;
}

bool DeleteProbeProfiles(const std::wstring& profile, const std::wstring& second_profile,
                         bool first_created, bool second_created) {
  bool okay = true;
  if (first_created) {
    const HRESULT result = DeleteAppContainerProfile(profile.c_str());
    if (FAILED(result)) {
      ReportAppContainerFailure(L"delete_primary_profile", result, ERROR_SUCCESS);
      okay = false;
    }
  }
  if (second_created) {
    const HRESULT result = DeleteAppContainerProfile(second_profile.c_str());
    if (FAILED(result)) {
      ReportAppContainerFailure(L"delete_secondary_profile", result, ERROR_SUCCESS);
      okay = false;
    }
  }
  return okay;
}

bool RunAppContainerProbe(const std::wstring& executable, const std::wstring& output,
                          const std::wstring& world, const std::wstring& authenticated,
                          const std::wstring& world_low, const std::wstring& authenticated_low) {
  const std::wstring profile = L"SumatraFuzz-Probe-" + std::to_wstring(GetCurrentProcessId()) +
                               L"-" + std::to_wstring(GetTickCount64());
  const std::wstring second_profile = profile + L"-unique";
  PSID sid = nullptr;
  PSID second_sid = nullptr;
  bool first_created = false;
  bool second_created = false;
  bool okay = false;
  PWSTR profile_path = nullptr;
  try {
    HRESULT result = CreateAppContainerProfile(profile.c_str(), L"SumatraFuzz API Probe",
                                                L"Ephemeral feasibility probe", nullptr, 0, &sid);
    if (FAILED(result) || !sid) {
      ReportAppContainerFailure(L"create_profile", result, ERROR_SUCCESS);
      goto cleanup;
    }
    first_created = true;
    {
      LPWSTR sid_string = nullptr;
      if (!ConvertSidToStringSidW(sid, &sid_string)) {
        ReportAppContainerFailure(L"convert_profile_sid", S_OK, GetLastError());
        goto cleanup;
      }
      result = GetAppContainerFolderPath(sid_string, &profile_path);
      LocalFree(sid_string);
    }
    if (FAILED(result) || !profile_path || GetFullPathNameW(profile_path, 0, nullptr, nullptr) == 0) {
      ReportAppContainerFailure(L"get_profile_folder", result,
                                FAILED(result) ? ERROR_SUCCESS : GetLastError());
      goto cleanup;
    }
    std::fwprintf(stdout, L"AppContainerProfilePath=%ls\n", profile_path);
    std::fwprintf(stdout, L"AppContainerTempPath=%ls\n", output.c_str());
    result = CreateAppContainerProfile(second_profile.c_str(), L"SumatraFuzz API Probe",
                                        L"Ephemeral feasibility probe", nullptr, 0, &second_sid);
    if (FAILED(result) || !second_sid) {
      ReportAppContainerFailure(L"create_unique_profile", result, ERROR_SUCCESS);
      goto cleanup;
    }
    if (EqualSid(sid, second_sid)) {
      ReportAppContainerFailure(L"verify_unique_package_sid", HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
                                ERROR_INVALID_DATA);
      goto cleanup;
    }
    second_created = true;
    if (!GrantAppContainerDirectoryAccess(output, sid)) {
      ReportAppContainerFailure(L"grant_output_acl", S_OK, GetLastError());
      goto cleanup;
    }
    {
      const std::wstring appcontainer_executable = output + L"\\appcontainer-probe.exe";
      if (!CopyFileW(executable.c_str(), appcontainer_executable.c_str(), TRUE)) {
        ReportAppContainerFailure(L"copy_probe_executable", S_OK, GetLastError());
        goto cleanup;
      }
      SIZE_T bytes = 0;
      InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
      if (bytes == 0) {
        ReportAppContainerFailure(L"size_process_attributes", S_OK, GetLastError());
        goto cleanup;
      }
      std::vector<BYTE> attributes(bytes);
      auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
      if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) {
        ReportAppContainerFailure(L"initialize_process_attributes", S_OK, GetLastError());
        goto cleanup;
      }
      SECURITY_CAPABILITIES security{};
      security.AppContainerSid = sid;
      security.CapabilityCount = 0;
      security.Capabilities = nullptr;
      const bool updated = UpdateProcThreadAttribute(list, 0,
          PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security, sizeof(security), nullptr, nullptr);
      if (!updated) {
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(list);
        ReportAppContainerFailure(L"set_security_capabilities", S_OK, error);
        goto cleanup;
      }
      STARTUPINFOEXW startup{};
      startup.StartupInfo.cb = sizeof(startup);
      startup.lpAttributeList = list;
      PROCESS_INFORMATION process{};
      std::wstring command = L"\"" + appcontainer_executable + L"\" --appcontainer-child \"" + output +
          L"\" \"" + world + L"\" \"" + authenticated + L"\" \"" + world_low +
          L"\" \"" + authenticated_low + L"\"";
      const BOOL launched = CreateProcessW(appcontainer_executable.c_str(), command.data(), nullptr, nullptr,
          FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, output.c_str(),
          &startup.StartupInfo, &process);
      DeleteProcThreadAttributeList(list);
      if (!launched) {
        ReportAppContainerFailure(L"launch_appcontainer", S_OK, GetLastError());
        goto cleanup;
      }
      DWORD wait = WaitForSingleObject(process.hProcess, 30000);
      if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        wait = WaitForSingleObject(process.hProcess, 30000);
      }
      DWORD exit_code = 0xffffffff;
      if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exit_code);
      else ReportAppContainerFailure(L"wait_for_appcontainer", S_OK, GetLastError());
      CloseHandle(process.hThread);
      CloseHandle(process.hProcess);
      okay = wait == WAIT_OBJECT_0 && exit_code == 0;
      if (wait == WAIT_OBJECT_0 && exit_code != 0)
        ReportAppContainerFailure(L"verify_appcontainer_child", HRESULT_FROM_WIN32(exit_code), exit_code);
    }
  cleanup:
    if (profile_path) CoTaskMemFree(profile_path);
    if (sid) FreeSid(sid);
    if (second_sid) FreeSid(second_sid);
    const bool profiles_deleted = DeleteProbeProfiles(profile, second_profile,
                                                       first_created, second_created);
    okay = profiles_deleted && okay;
    return okay;
  } catch (...) {
    ReportAppContainerFailure(L"handle_probe_exception", E_FAIL, ERROR_SUCCESS);
    if (profile_path) CoTaskMemFree(profile_path);
    if (sid) FreeSid(sid);
    if (second_sid) FreeSid(second_sid);
    const bool cleanup_succeeded = DeleteProbeProfiles(profile, second_profile,
                                                        first_created, second_created);
    if (!cleanup_succeeded)
      std::fwprintf(stderr, L"AppContainer probe exception left profile cleanup incomplete\n");
    return false;
  }
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

DWORD CheckObjectDacl(SECURITY_DESCRIPTOR* descriptor, DWORD desired_access,
                      GENERIC_MAPPING mapping, BOOL* access_granted) {
  *access_granted = FALSE;
  HANDLE process_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token))
    return GetLastError();
  HANDLE impersonation_token = nullptr;
  if (!DuplicateTokenEx(process_token, TOKEN_QUERY, nullptr, SecurityImpersonation,
                        TokenImpersonation, &impersonation_token)) {
    const DWORD error = GetLastError();
    CloseHandle(process_token);
    return error;
  }
  CloseHandle(process_token);
  DWORD owner_bytes = 0;
  DWORD group_bytes = 0;
  GetTokenInformation(impersonation_token, TokenOwner, nullptr, 0, &owner_bytes);
  if (owner_bytes < sizeof(TOKEN_OWNER)) {
    const DWORD error = GetLastError();
    CloseHandle(impersonation_token);
    return error;
  }
  GetTokenInformation(impersonation_token, TokenPrimaryGroup, nullptr, 0, &group_bytes);
  if (group_bytes < sizeof(TOKEN_PRIMARY_GROUP)) {
    const DWORD error = GetLastError();
    CloseHandle(impersonation_token);
    return error;
  }
  std::vector<BYTE> owner_storage(owner_bytes);
  std::vector<BYTE> group_storage(group_bytes);
  if (!GetTokenInformation(impersonation_token, TokenOwner, owner_storage.data(), owner_bytes,
                           &owner_bytes) ||
      !GetTokenInformation(impersonation_token, TokenPrimaryGroup, group_storage.data(), group_bytes,
                           &group_bytes)) {
    const DWORD error = GetLastError();
    CloseHandle(impersonation_token);
    return error;
  }
  PSID descriptor_owner = nullptr;
  PSID descriptor_group = nullptr;
  BOOL owner_defaulted = FALSE;
  BOOL group_defaulted = FALSE;
  SECURITY_DESCRIPTOR check_descriptor{};
  PSECURITY_DESCRIPTOR descriptor_for_check = descriptor;
  if (!GetSecurityDescriptorOwner(descriptor, &descriptor_owner, &owner_defaulted) ||
      !GetSecurityDescriptorGroup(descriptor, &descriptor_group, &group_defaulted)) {
    const DWORD error = GetLastError();
    CloseHandle(impersonation_token);
    return error;
  }
  if (!descriptor_owner || !descriptor_group) {
    // The event probe uses an absolute descriptor with omitted owner/group.
    // The namespace descriptor from GetSecurityInfo is self-relative and
    // already carries both, so it must be passed through without shallow copy.
    check_descriptor = *descriptor;
    if (!SetSecurityDescriptorOwner(
            &check_descriptor, reinterpret_cast<TOKEN_OWNER*>(owner_storage.data())->Owner, FALSE) ||
        !SetSecurityDescriptorGroup(
            &check_descriptor,
            reinterpret_cast<TOKEN_PRIMARY_GROUP*>(group_storage.data())->PrimaryGroup, FALSE)) {
      const DWORD error = GetLastError();
      CloseHandle(impersonation_token);
      return error;
    }
    descriptor_for_check = &check_descriptor;
  }
  PRIVILEGE_SET privileges{};
  DWORD privilege_bytes = sizeof(privileges);
  DWORD granted_access = 0;
  BOOL granted = FALSE;
  const BOOL checked = AccessCheck(descriptor_for_check, impersonation_token, desired_access,
                                   &mapping, &privileges, &privilege_bytes,
                                   &granted_access, &granted);
  const DWORD error = checked ? ERROR_SUCCESS : GetLastError();
  CloseHandle(impersonation_token);
  if (checked) *access_granted = granted;
  return error;
}

DWORD CheckExplicitEventDacl(SECURITY_DESCRIPTOR* descriptor, DWORD desired_access,
                             BOOL* access_granted) {
  const GENERIC_MAPPING mapping{READ_CONTROL | SYNCHRONIZE,
                                READ_CONTROL | EVENT_MODIFY_STATE,
                                READ_CONTROL | SYNCHRONIZE, EVENT_ALL_ACCESS};
  return CheckObjectDacl(descriptor, desired_access, mapping, access_granted);
}

DWORD CheckPrivateNamespaceDacl(HANDLE namespace_handle, BOOL* traverse_granted,
                                BOOL* create_object_granted) {
  *traverse_granted = FALSE;
  *create_object_granted = FALSE;
  DWORD descriptor_bytes = 0;
  constexpr SECURITY_INFORMATION kNamespaceSecurity = OWNER_SECURITY_INFORMATION |
      GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
  GetKernelObjectSecurity(namespace_handle, kNamespaceSecurity, nullptr, 0,
                          &descriptor_bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || descriptor_bytes == 0)
    return GetLastError();
  std::vector<BYTE> descriptor_storage(descriptor_bytes);
  if (!GetKernelObjectSecurity(namespace_handle, kNamespaceSecurity,
                               descriptor_storage.data(), descriptor_bytes,
                               &descriptor_bytes)) return GetLastError();
  // Object-directory rights are not exported by the user-mode SDK headers.
  // Use their documented values and map GENERIC_ALL to DIRECTORY_ALL_ACCESS.
  constexpr DWORD kDirectoryTraverse = 0x0002;
  constexpr DWORD kDirectoryCreateObject = 0x0004;
  constexpr DWORD kDirectoryAllAccess = 0x000F000F;
  const GENERIC_MAPPING mapping{READ_CONTROL | 0x0003, READ_CONTROL | 0x000C,
                                READ_CONTROL | kDirectoryTraverse, kDirectoryAllAccess};
  const DWORD traverse_error = CheckObjectDacl(
      reinterpret_cast<SECURITY_DESCRIPTOR*>(descriptor_storage.data()),
      kDirectoryTraverse, mapping, traverse_granted);
  const DWORD create_error = CheckObjectDacl(
      reinterpret_cast<SECURITY_DESCRIPTOR*>(descriptor_storage.data()),
      kDirectoryCreateObject, mapping, create_object_granted);
  if (traverse_error != ERROR_SUCCESS) return traverse_error;
  return create_error;
}

void WriteNamedEventFailureDiagnostic(const std::wstring& evidence_dir, DWORD error,
                                      DWORD unnamed_error, DWORD local_error,
                                      DWORD explicit_local_error, DWORD dacl_check_error,
                                      BOOL dacl_granted, DWORD default_private_error,
                                      DWORD namespace_acl_error, BOOL namespace_traverse_granted,
                                      BOOL namespace_create_granted) {
  const std::string contents = "private_event_failed=" + std::to_string(error) +
      ",unnamed_event_error=" + std::to_string(unnamed_error) +
      ",local_named_event_error=" + std::to_string(local_error) +
      ",explicit_local_event_error=" + std::to_string(explicit_local_error) +
      ",explicit_dacl_access_error=" + std::to_string(dacl_check_error) +
      ",explicit_dacl_granted=" + std::to_string(dacl_granted ? 1 : 0) +
      ",default_private_event_error=" + std::to_string(default_private_error) +
      ",namespace_acl_access_error=" + std::to_string(namespace_acl_error) +
      ",namespace_traverse_granted=" + std::to_string(namespace_traverse_granted ? 1 : 0) +
      ",namespace_create_granted=" + std::to_string(namespace_create_granted ? 1 : 0) + "\n";
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

bool AddLowIntegrityBoundaryLabel(HANDLE* boundary) {
  DWORD bytes = 0;
  CreateWellKnownSid(WinLowLabelSid, nullptr, nullptr, &bytes);
  if (bytes == 0) return false;
  std::vector<BYTE> storage(bytes);
  PSID sid = storage.data();
  return CreateWellKnownSid(WinLowLabelSid, nullptr, sid, &bytes) &&
         AddIntegrityLabelToBoundaryDescriptor(boundary, sid);
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
        reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid) ||
        !AddLowIntegrityBoundaryLabel(&boundary)) return false;
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
  PACL event_sacl = sumatrafuzz::supervisor::CreateLowIntegrityMandatorySacl();
  SECURITY_DESCRIPTOR event_descriptor{};
  // Explicit descriptors without an integrity label default to medium; mark
  // this run-private IPC object low so the low worker can create and signal it.
  const bool event_acl_ready = event_acl &&
      event_sacl &&
      InitializeSecurityDescriptor(&event_descriptor, SECURITY_DESCRIPTOR_REVISION) &&
      SetSecurityDescriptorDacl(&event_descriptor, TRUE, event_acl, FALSE) &&
      SetSecurityDescriptorSacl(&event_descriptor, TRUE, event_sacl, FALSE) &&
      SetSecurityDescriptorControl(&event_descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
  if (!event_acl_ready) {
    if (event_acl) LocalFree(event_acl);
    if (event_sacl) LocalFree(event_sacl);
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
    BOOL dacl_granted = FALSE;
    const DWORD dacl_check_error = CheckExplicitEventDacl(
        &event_descriptor, event_rights, &dacl_granted);
    // Compare with an otherwise identical event using the token's default
    // descriptor. This is a diagnostic only; acceptance still requires the
    // explicit worker-and-run DACL above. A default event that also fails
    // isolates the denial to private-namespace object creation/access.
    const std::wstring default_private_name = ns.alias + L"\\Default-" +
        std::to_wstring(GetCurrentProcessId());
    const DWORD default_private_error = ProbeEventCreation(default_private_name);
    BOOL namespace_traverse_granted = FALSE;
    BOOL namespace_create_granted = FALSE;
    const DWORD namespace_acl_error = CheckPrivateNamespaceDacl(
        ns.handle, &namespace_traverse_granted, &namespace_create_granted);
    WriteNamedEventFailureDiagnostic(evidence_dir, error, unnamed_error, local_error,
                                     explicit_local_error, dacl_check_error, dacl_granted,
                                     default_private_error, namespace_acl_error,
                                     namespace_traverse_granted, namespace_create_granted);
    LocalFree(event_acl);
    LocalFree(event_sacl);
    LocalFree(run_sid);
    return 2400 + static_cast<int>(error);
  }
  LocalFree(event_acl);
  LocalFree(event_sacl);
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
  if (argc == 7 && std::wstring(argv[1]) == L"--appcontainer-child")
    return AppContainerChild(argv[2], argv[3], argv[4], argv[5], argv[6]) ? 0 : 81;
  if (argc == 7 && std::wstring(argv[1]) == L"--appcontainer-probe")
    return RunAppContainerProbe(argv[0], argv[2], argv[3], argv[4], argv[5], argv[6]) ? 0 : 82;
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::wstring(argv[i]) == L"--startup-marker") {
      HANDLE marker = CreateFileW(argv[i + 1], GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
      if (marker == INVALID_HANDLE_VALUE) return 51;
      CloseHandle(marker);
    }
  }
  wchar_t secret[16]{};
  if (GetEnvironmentVariableW(L"SUMATRAFUZZ_TEST_SECRET", secret, static_cast<DWORD>(std::size(secret))) > 0) return 11;
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::wstring(argv[i]) == L"--expect-write-denied") {
      HANDLE file = CreateFileW(argv[i + 1], FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        return 49;
      }
      return GetLastError() == ERROR_ACCESS_DENIED ? 0 : 50;
    }
  }
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
