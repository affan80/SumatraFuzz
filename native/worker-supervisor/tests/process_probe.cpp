#ifdef _WIN32
#include "command_line.h"
#include "private_acl.h"
#include "run_resources.h"

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>
#include <winioctl.h>
#include <sddl.h>
#include <cstring>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <thread>

namespace {

void WriteAppContainerDiagnostic(const char* message, DWORD length);

void ResourceContractDiagnostic(const char* stage, int line, DWORD error, const char* detail) {
  char message[1024]{};
  const int length = std::snprintf(message, sizeof(message),
      "resource-contract: stage=%s line=%d win32=%lu detail=%s\n", stage, line,
      static_cast<unsigned long>(error), detail);
  if (length > 0 && static_cast<size_t>(length) < sizeof(message))
    WriteAppContainerDiagnostic(message, static_cast<DWORD>(length));
}

bool ResourceContractFailure(const char* stage, int line, DWORD error) {
  ResourceContractDiagnostic(stage, line, error, "FAIL");
  return false;
}

bool ResourceContractHresultFailure(const char* stage, int line, HRESULT result) {
  char detail[40]{};
  std::snprintf(detail, sizeof(detail), "hresult=0x%08lX", static_cast<unsigned long>(result));
  const DWORD code = HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : ERROR_GEN_FAILURE;
  ResourceContractDiagnostic(stage, line, code, detail);
  return ResourceContractFailure(stage, line, code);
}

std::wstring CanonicalResourceContractRoot(const std::wstring& supplied_root) {
  using namespace sumatrafuzz::supervisor;
  // Only canonicalize here: release the temporary data-sharing root pin before
  // any fixture mutation. Production grant pins remain unchanged.
  auto root_handle = OpenRunResource(supplied_root, FILE_READ_ATTRIBUTES, true);
  std::wstring root(32768, L'\0');
  const DWORD length = GetFinalPathNameByHandleW(root_handle.value, root.data(),
      static_cast<DWORD>(root.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!length) ResourceError(GetLastError(), "fixture root canonicalization");
  if (length >= root.size()) ResourceError(ERROR_INSUFFICIENT_BUFFER, "fixture root canonicalization");
  root.resize(length);
  if (root.compare(0, 4, L"\\\\?\\") != 0) ResourceError(ERROR_INVALID_NAME, "fixture root prefix");
  return root.substr(4);
}

// Real helper contract: no child launch here (Task 3 owns token integration).
DWORD PackageAceMask(const std::wstring& path, PSID sid) {
  PACL acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD mask = 0;
  const DWORD result = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS || !acl) {
    if (descriptor) LocalFree(descriptor);
    throw std::system_error(result == ERROR_SUCCESS ? ERROR_INVALID_ACL : result,
                            std::system_category(), "contract ACL query failed");
  }
  for (DWORD i = 0; i < acl->AceCount; ++i) {
    void* entry = nullptr;
    if (!GetAce(acl, i, &entry)) { LocalFree(descriptor); throw std::runtime_error("contract ACE query failed"); }
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
    if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid(&ace->SidStart, sid)) {
      if (ace->Header.AceFlags != 0) { LocalFree(descriptor); throw std::runtime_error("inheritable package ACE"); }
      mask |= ace->Mask;
    }
  }
  LocalFree(descriptor);
  return mask;
}

bool SetContractJunction(HANDLE handle, const std::wstring& destination) {
  struct JunctionData {
    DWORD tag;
    WORD length, reserved, substitute_offset, substitute_length, print_offset, print_length;
    wchar_t paths[1024];
  } junction{};
  const std::wstring target = L"\\??\\" + destination;
  if (target.size() + destination.size() + 2 > std::size(junction.paths)) return false;
  junction.tag = IO_REPARSE_TAG_MOUNT_POINT;
  junction.substitute_length = static_cast<WORD>(target.size() * sizeof(wchar_t));
  junction.print_offset = junction.substitute_length + sizeof(wchar_t);
  junction.print_length = static_cast<WORD>(destination.size() * sizeof(wchar_t));
  std::memcpy(junction.paths, target.c_str(), (target.size() + 1) * sizeof(wchar_t));
  std::memcpy(reinterpret_cast<BYTE*>(junction.paths) + junction.print_offset,
              destination.c_str(), (destination.size() + 1) * sizeof(wchar_t));
  junction.length = static_cast<WORD>(8 + junction.print_offset + junction.print_length + sizeof(wchar_t));
  DWORD returned = 0;
  return DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, &junction,
                        junction.length + 8, nullptr, 0, &returned, nullptr) != FALSE;
}

bool RunResourceContract(const std::wstring& supplied_root) {
  using namespace sumatrafuzz::supervisor;
  const char* stage = "entry";
  const auto checkpoint = [&](const char* next) {
    stage = next;
    ResourceContractDiagnostic(stage, __LINE__, ERROR_SUCCESS, "BEGIN");
  };
  checkpoint(stage);
  try {
    // Windows TEMP may use an 8.3 alias. Authorize the canonical fixture root,
    // just as Task 3 must bind its policy to held proof handles.
    checkpoint("canonical-root");
    const std::wstring root = CanonicalResourceContractRoot(supplied_root);
    checkpoint("volume-root-key");
    if (ResourcePathKey(L"C:\\") != L"c:\\") return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    const std::wstring tool = root + L"\\tool.exe";
    const std::wstring input_dir = root + L"\\inputs";
    const std::wstring input = input_dir + L"\\input.pdf";
    const std::wstring output = root + L"\\evidence";
    const std::wstring sibling = root + L"\\sibling";
    const std::wstring secret = root + L"\\credentials";
    const std::wstring link = root + L"\\alias.pdf";
    checkpoint("create-input-directory");
    if (!CreateDirectoryW(input_dir.c_str(), nullptr)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    for (const auto& file : {tool, input, secret}) {
      checkpoint(file == tool ? "create-tool-file" : file == input ? "create-input-file" : "create-secret-file");
      ResourceHandle created(CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                        FILE_ATTRIBUTE_NORMAL, nullptr));
      if (created.value == INVALID_HANDLE_VALUE) return ResourceContractFailure(stage, __LINE__, GetLastError());
    }
    checkpoint("create-evidence-sibling");
    if (!CreateDirectoryW(output.c_str(), nullptr) || !CreateDirectoryW(sibling.c_str(), nullptr)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    std::vector<ResourceHandle> proof_handles;
    const auto rule = [&](const std::wstring& path, RunResourceAccess access) {
      proof_handles.emplace_back(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      if (proof_handles.back().value == INVALID_HANDLE_VALUE) throw std::runtime_error("proof fixture open");
      return RunResourceRule{path, access, proof_handles.back().value};
    };
    checkpoint("build-proof-policy");
    RunResourcePolicy policy{{rule(tool, RunResourceAccess::ToolReadExecute),
                             rule(input, RunResourceAccess::InputRead),
                             rule(input_dir, RunResourceAccess::InputRead),
                             rule(output, RunResourceAccess::EvidenceModify),
                             rule(secret, RunResourceAccess::EvidenceModify)}, {secret}};
    checkpoint("create-run-profiles");
    RunResources resources;
    resources.state->profile = CreateRunAppContainerProfile();
    auto& profile = resources.state->profile;
    auto second = CreateRunAppContainerProfile();
    if (!IsRunPackageSid(profile.sid) || EqualSid(profile.sid, second.sid) || profile.name.size() > 64) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    const auto rejected = [&](const std::wstring& path, RunResourceAccess access, PSID identity) {
      try { auto unexpected = GrantRunResourceAccess(path, identity, access, policy); }
      catch (const std::system_error&) { return true; }
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    };
    checkpoint("excluded-volume");
    RunResourcePolicy volume_policy{{rule(output, RunResourceAccess::EvidenceModify)}, {root.substr(0, 3)}};
    try {
      auto denied_volume = GrantRunResourceAccess(output, profile.sid, RunResourceAccess::EvidenceModify, volume_policy);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error&) {}
    checkpoint("reject-volume-grant");
    RunResourcePolicy volume_grant{{rule(root.substr(0, 3), RunResourceAccess::InputRead)}, {}};
    try {
      auto denied_root = GrantRunResourceAccess(root.substr(0, 3), profile.sid, RunResourceAccess::InputRead, volume_grant);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error&) {}
    checkpoint("reject-missing-proof");
    RunResourcePolicy missing_proof{{{input, RunResourceAccess::InputRead}}, {}};
    try {
      auto unbound = GrantRunResourceAccess(input, profile.sid, RunResourceAccess::InputRead, missing_proof);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error& error) {
      if (error.code().value() != ERROR_INVALID_HANDLE) throw;
    }
    // A stale path authorization must not grant the replacement object.
    checkpoint("create-replacement-fixture");
    const std::wstring replaced = root + L"\\replaced.pdf";
    {
      ResourceHandle created(CreateFileW(replaced.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
      if (created.value == INVALID_HANDLE_VALUE) return ResourceContractFailure(stage, __LINE__, GetLastError());
    }
    checkpoint("capture-replacement-proof");
    RunResourcePolicy replacement_policy{{rule(replaced, RunResourceAccess::InputRead)}, {}};
    // Positive control for the previous accidental fixture pin. A root pin
    // must block this rename; after that scope exits only the metadata proof
    // remains, and the rename/replacement below must succeed.
    checkpoint("parent-pin-control");
    {
      auto parent_pin = OpenRunResource(root, FILE_READ_ATTRIBUTES, true);
      const BOOL renamed = MoveFileExW(replaced.c_str(), (root + L"\\former.pdf").c_str(), 0);
      const DWORD error = renamed ? ERROR_SUCCESS : GetLastError();
      ResourceContractDiagnostic(stage, __LINE__, error, "rename-while-parent-pinned");
      if (renamed || error != ERROR_SHARING_VIOLATION)
        return ResourceContractFailure(stage, __LINE__, renamed ? ERROR_INVALID_DATA : error);
    }
    checkpoint("replace-after-proof");
    if (!MoveFileExW(replaced.c_str(), (root + L"\\former.pdf").c_str(), 0)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    {
      ResourceHandle created(CreateFileW(replaced.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
      if (created.value == INVALID_HANDLE_VALUE) return ResourceContractFailure(stage, __LINE__, GetLastError());
    }
    try {
      auto unauthorized = GrantRunResourceAccess(replaced, profile.sid, RunResourceAccess::InputRead, replacement_policy);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error& error) {
      if (error.code().value() != ERROR_FILE_INVALID) throw;
    }
    if (PackageAceMask(replaced, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    checkpoint("reject-broad-excluded-unselected");
    BYTE broad[SECURITY_MAX_SID_SIZE]{};
    DWORD broad_size = sizeof(broad);
    if (!CreateWellKnownSid(WinWorldSid, nullptr, broad, &broad_size)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    if (!rejected(output, RunResourceAccess::EvidenceModify, broad) ||
        !rejected(sibling, RunResourceAccess::EvidenceModify, profile.sid) ||
        !rejected(secret, RunResourceAccess::EvidenceModify, profile.sid) ||
        !rejected(input, RunResourceAccess::ToolReadExecute, profile.sid) ||
        !rejected(root + L"\\evidence\\..\\input.pdf", RunResourceAccess::InputRead, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    checkpoint("create-initial-hardlink");
    if (!CreateHardLinkW(link.c_str(), input.c_str(), nullptr)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    policy.objects.push_back(rule(link, RunResourceAccess::InputRead));
    if (!rejected(link, RunResourceAccess::InputRead, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    checkpoint("delete-initial-hardlink");
    if (!DeleteFileW(link.c_str())) return ResourceContractFailure(stage, __LINE__, GetLastError());
    // Directory junctions are rejected without requiring symlink privileges.
    checkpoint("create-junction-directory");
    if (!CreateDirectoryW(link.c_str(), nullptr)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    {
      ResourceHandle reparse(CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
          FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      if (!SetContractJunction(reparse.value, sibling)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    }
    checkpoint("reject-junction");
    policy.objects.back() = rule(link, RunResourceAccess::InputRead);
    if (!rejected(link, RunResourceAccess::InputRead, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    // Existing data writers must prevent acquiring a supposedly stable pin.
    checkpoint("reject-existing-writer");
    for (const auto& directory : {output, input_dir}) {
      ResourceHandle writer(CreateFileW(directory.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      if (writer.value == INVALID_HANDLE_VALUE) return ResourceContractFailure(stage, __LINE__, GetLastError());
      try {
        auto unstable = GrantRunResourceAccess(directory == output ? output : input, profile.sid,
            directory == output ? RunResourceAccess::EvidenceModify : RunResourceAccess::InputRead, policy);
        return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
      } catch (const std::system_error& error) {
        if (error.code().value() != ERROR_SHARING_VIOLATION) throw;
      }
    }
    checkpoint("reject-writable-file");
    RunResourcePolicy writable_file{{rule(input, RunResourceAccess::EvidenceModify)}, {}};
    try {
      auto unstable_file = GrantRunResourceAccess(input, profile.sid, RunResourceAccess::EvidenceModify, writable_file);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error& error) {
      if (error.code().value() != ERROR_ACCESS_DENIED) throw;
    }
    // Partial setup owns a profile too: unwind it only after undoing grants.
    checkpoint("partial-setup-rollback");
    std::wstring partial_name;
    std::vector<BYTE> partial_sid;
    try {
      RunResources partial;
      partial.state->profile = CreateRunAppContainerProfile();
      partial_name = partial.state->profile.name;
      partial_sid.resize(GetLengthSid(partial.state->profile.sid));
      if (!CopySid(static_cast<DWORD>(partial_sid.size()), partial_sid.data(), partial.state->profile.sid)) return ResourceContractFailure(stage, __LINE__, GetLastError());
      partial.state->grants.push_back(GrantRunResourceAccess(output, partial.state->profile.sid,
          RunResourceAccess::EvidenceModify, policy));
      auto denied = GrantRunResourceAccess(sibling, partial.state->profile.sid, RunResourceAccess::EvidenceModify, policy);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error&) {}
    if (partial_name.empty() || partial_sid.empty() || PackageAceMask(output, partial_sid.data()) != 0) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    checkpoint("verify-partial-profile-deletion");
    PSID recreated_partial = nullptr;
    const HRESULT recreate_partial_result = CreateAppContainerProfile(partial_name.c_str(), L"Contract", L"Contract", nullptr, 0, &recreated_partial);
    if (FAILED(recreate_partial_result)) return ResourceContractHresultFailure(stage, __LINE__, recreate_partial_result);
    const HRESULT removed_partial = DeleteAppContainerProfile(partial_name.c_str());
    FreeSid(recreated_partial);
    if (FAILED(removed_partial)) return ResourceContractHresultFailure(stage, __LINE__, removed_partial);
    checkpoint("grant-resource-policy");
    for (const auto& rule : policy.objects) {
      if (rule.path == secret || rule.path == link) continue;
      resources.state->grants.push_back(GrantRunResourceAccess(rule.path, profile.sid, rule.access, policy));
    }
    checkpoint("verify-resource-masks");
    const DWORD tool_mask = PackageAceMask(tool, profile.sid);
    const DWORD input_mask = PackageAceMask(input, profile.sid);
    const DWORD output_mask = PackageAceMask(output, profile.sid);
    const DWORD input_dir_mask = PackageAceMask(input_dir, profile.sid);
    if ((tool_mask & (FILE_READ_DATA | FILE_EXECUTE)) != (FILE_READ_DATA | FILE_EXECUTE) ||
        (tool_mask & (FILE_WRITE_DATA | DELETE | WRITE_DAC)) ||
        !(input_mask & FILE_READ_DATA) || (input_mask & (FILE_EXECUTE | FILE_WRITE_DATA | DELETE | WRITE_DAC)) ||
        (output_mask & (FILE_WRITE_DATA | DELETE | FILE_DELETE_CHILD)) != (FILE_WRITE_DATA | DELETE | FILE_DELETE_CHILD) ||
        (output_mask & (WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES)) ||
        !(input_dir_mask & FILE_TRAVERSE) || (input_dir_mask & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | DELETE | WRITE_DAC))) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    // A separate thread attempts namespace mutation while grants remain held.
    checkpoint("concurrent-mutations");
    bool mutation_denied = false;
    std::thread mutation([&] {
      const auto rename_denied = [&](const std::wstring& from, const std::wstring& to, DWORD flags) {
        return !MoveFileExW(from.c_str(), to.c_str(), flags) && GetLastError() == ERROR_SHARING_VIOLATION;
      };
      const bool input_pinned = rename_denied(input, root + L"\\renamed.pdf", 0);
      const bool ancestor_pinned = rename_denied(input_dir, root + L"\\renamed-inputs", 0);
      const bool output_pinned = rename_denied(output, root + L"\\renamed-evidence", 0);
      const bool replacement_pinned = rename_denied(replaced, input, MOVEFILE_REPLACE_EXISTING);
      const bool input_linked = CreateHardLinkW((root + L"\\concurrent-input.pdf").c_str(), input.c_str(), nullptr) != FALSE;
      const DWORD input_link_error = input_linked ? ERROR_SUCCESS : GetLastError();
      const bool tool_linked = CreateHardLinkW((root + L"\\concurrent-tool.exe").c_str(), tool.c_str(), nullptr) != FALSE;
      const DWORD tool_link_error = tool_linked ? ERROR_SUCCESS : GetLastError();
      ResourceHandle writer(CreateFileW(output.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      const bool retarget_denied = writer.value == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
      ResourceHandle metadata(CreateFileW(output.c_str(), FILE_WRITE_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      const bool metadata_retargeted = metadata.value != INVALID_HANDLE_VALUE && SetContractJunction(metadata.value, sibling);
      const DWORD metadata_retarget_error = metadata_retargeted ? ERROR_SUCCESS : GetLastError();
      const bool metadata_retarget_denied = !metadata_retargeted;
      ResourceHandle child(CreateFileW((output + L"\\new.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ,
          nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
      DWORD written = 0;
      const bool output_writable = child.value != INVALID_HANDLE_VALUE && WriteFile(child.value, "x", 1, &written, nullptr) && written == 1;
      char mutation_message[1024]{};
      const int mutation_length = std::snprintf(mutation_message, sizeof(mutation_message), "resource-pin: inputRenameDenied=%d ancestorRenameDenied=%d evidenceRenameDenied=%d replacementDenied=%d writeOpenDenied=%d metadataRetargetDenied=%d metadataError=%lu inputHardlinkDenied=%d inputLinkError=%lu toolHardlinkDenied=%d toolLinkError=%lu childWrite=%d\n",
          input_pinned, ancestor_pinned, output_pinned, replacement_pinned, retarget_denied,
          metadata_retarget_denied, static_cast<unsigned long>(metadata_retarget_error),
          !input_linked, static_cast<unsigned long>(input_link_error), !tool_linked,
          static_cast<unsigned long>(tool_link_error), output_writable);
      if (mutation_length > 0 && static_cast<size_t>(mutation_length) < sizeof(mutation_message))
        WriteAppContainerDiagnostic(mutation_message, static_cast<DWORD>(mutation_length));
      mutation_denied = input_pinned && ancestor_pinned && output_pinned && replacement_pinned &&
          retarget_denied && metadata_retarget_denied && !input_linked && !tool_linked && output_writable;
    });
    mutation.join();
    if (!mutation_denied) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    // Case-sensitive NTFS can resolve folded-equal names to different IDs.
    checkpoint("create-case-sensitive-directory");
    const std::wstring case_dir = root + L"\\case-sensitive";
    if (!CreateDirectoryW(case_dir.c_str(), nullptr)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    {
      ResourceHandle directory(CreateFileW(case_dir.c_str(), FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE |
          FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      struct { ULONG flags; } case_sensitive{1};
      // FileCaseSensitiveInfo is Win32 FILE_INFO_BY_HANDLE_CLASS value 23.
      if (directory.value == INVALID_HANDLE_VALUE || !SetFileInformationByHandle(directory.value,
          static_cast<FILE_INFO_BY_HANDLE_CLASS>(23), &case_sensitive, sizeof(case_sensitive)))
        throw std::system_error(GetLastError(), std::system_category(), "case-sensitive fixture required");
    }
    checkpoint("create-case-distinct-files");
    const std::wstring lower = case_dir + L"\\input.pdf";
    const std::wstring upper = case_dir + L"\\INPUT.pdf";
    for (const auto& name : {lower, upper}) {
      ResourceHandle created(CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
          FILE_FLAG_POSIX_SEMANTICS | FILE_ATTRIBUTE_NORMAL, nullptr));
      if (created.value == INVALID_HANDLE_VALUE) return ResourceContractFailure(stage, __LINE__, GetLastError());
    }
    checkpoint("reject-case-distinct-identity");
    RunResourcePolicy case_policy{{rule(lower, RunResourceAccess::InputRead)}, {}};
    try {
      auto unauthorized = GrantRunResourceAccess(upper, profile.sid, RunResourceAccess::InputRead, case_policy);
      return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    } catch (const std::system_error& error) {
      if (error.code().value() != ERROR_FILE_INVALID) throw;
    }
    if (PackageAceMask(upper, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    {
      auto correct_case = GrantRunResourceAccess(lower, profile.sid, RunResourceAccess::InputRead, case_policy);
      if (!PackageAceMask(lower, profile.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    }
    ResourceContractDiagnostic(stage, __LINE__, ERROR_SUCCESS,
        "replacementDenied=1 caseDistinctDenied=1 correctCaseGranted=1");
    // A concurrent independent package grant must survive our rollback.
    checkpoint("preserve-other-package-grant");
    auto unrelated = GrantRunResourceAccess(output, second.sid, RunResourceAccess::EvidenceModify, policy);
    std::vector<BYTE> first_sid(GetLengthSid(profile.sid));
    if (!CopySid(static_cast<DWORD>(first_sid.size()), first_sid.data(), profile.sid)) return ResourceContractFailure(stage, __LINE__, GetLastError());
    const std::wstring name = profile.name;
    checkpoint("close-moved-resources");
    RunResources moved(std::move(resources));
    const DWORD moved_from_close = resources.Close();
    if (moved_from_close != ERROR_SUCCESS) return ResourceContractFailure(stage, __LINE__, moved_from_close);
    const DWORD moved_close = moved.Close();
    if (moved_close != ERROR_SUCCESS) return ResourceContractFailure(stage, __LINE__, moved_close);
    if (PackageAceMask(tool, first_sid.data()) || PackageAceMask(input, first_sid.data()) || PackageAceMask(input_dir, first_sid.data()) ||
        PackageAceMask(output, first_sid.data()) || !PackageAceMask(output, second.sid)) return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
    const DWORD unrelated_remove = unrelated->Remove();
    if (unrelated_remove != ERROR_SUCCESS) return ResourceContractFailure(stage, __LINE__, unrelated_remove);
    const DWORD second_close = second.Close();
    if (second_close != ERROR_SUCCESS) return ResourceContractFailure(stage, __LINE__, second_close);
    // Creation with the exact former name succeeds only after actual deletion.
    checkpoint("verify-final-profile-deletion");
    PSID recreated = nullptr;
    const HRESULT recreate_result = CreateAppContainerProfile(name.c_str(), L"Contract", L"Contract", nullptr, 0, &recreated);
    if (FAILED(recreate_result)) return ResourceContractHresultFailure(stage, __LINE__, recreate_result);
    const HRESULT deleted = DeleteAppContainerProfile(name.c_str());
    FreeSid(recreated);
    if (FAILED(deleted)) return ResourceContractHresultFailure(stage, __LINE__, deleted);
    ResourceContractDiagnostic(stage, __LINE__, ERROR_SUCCESS, "PASS");
    return true;
  } catch (const std::system_error& error) {
    const DWORD code = static_cast<DWORD>(error.code().value());
    ResourceContractDiagnostic(stage, __LINE__, code, error.what());
    return ResourceContractFailure(stage, __LINE__, code);
  } catch (const std::exception& error) {
    ResourceContractDiagnostic(stage, __LINE__, ERROR_INVALID_DATA, error.what());
    return ResourceContractFailure(stage, __LINE__, ERROR_INVALID_DATA);
  }
}

void WriteAppContainerDiagnostic(const char* message, DWORD length) {
  HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
  if (error == nullptr || error == INVALID_HANDLE_VALUE || length == 0) return;
  DWORD written = 0;
  WriteFile(error, message, length, &written, nullptr);
}

void AppContainerCheckpoint(const char* stage) {
  WriteAppContainerDiagnostic(stage, static_cast<DWORD>(std::strlen(stage)));
}

void ReportAppContainerFailure(const char* step, HRESULT result, DWORD win32_error) {
  char message[160]{};
  const int length = std::snprintf(message, sizeof(message),
      "AppContainer probe failed: step=%s hresult=0x%08lX win32=%lu\n", step,
      static_cast<unsigned long>(result), static_cast<unsigned long>(win32_error));
  if (length > 0 && static_cast<size_t>(length) < sizeof(message))
    WriteAppContainerDiagnostic(message, static_cast<DWORD>(length));
}

bool WriteAppContainerPath(const char* label, PCWSTR path) {
  char message[4096]{};
  const int label_length = std::snprintf(message, sizeof(message), "%s", label);
  if (label_length <= 0 || static_cast<size_t>(label_length) >= sizeof(message)) return false;
  const int path_length = WideCharToMultiByte(CP_UTF8, 0, path, -1,
      message + label_length, static_cast<int>(sizeof(message) - label_length - 1), nullptr, nullptr);
  if (path_length <= 1 || static_cast<size_t>(label_length + path_length) >= sizeof(message)) return false;
  message[label_length + path_length - 1] = '\n';
  WriteAppContainerDiagnostic(message, static_cast<DWORD>(label_length + path_length));
  return true;
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
  AppContainerCheckpoint("AC:ACL_QUERY_BEGIN\n");
  PACL existing_dacl = nullptr;
  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  const DWORD query = GetNamedSecurityInfoW(const_cast<LPWSTR>(output.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, &existing_dacl, nullptr, &security_descriptor);
  if (query != ERROR_SUCCESS) {
    if (security_descriptor) LocalFree(security_descriptor);
    SetLastError(query);
    return false;
  }
  AppContainerCheckpoint("AC:ACL_QUERY_OK\n");
  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
  access.grfAccessMode = GRANT_ACCESS;
  access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
  PACL dacl = nullptr;
  AppContainerCheckpoint("AC:ACL_BUILD_BEGIN\n");
  const DWORD acl_result = SetEntriesInAclW(1, &access, existing_dacl, &dacl);
  AppContainerCheckpoint("AC:ACL_BUILD_RETURNED\n");
  // existing_dacl points into this returned descriptor; it is not separately
  // allocated and must remain valid until SetEntriesInAclW has copied it.
  if (security_descriptor) AppContainerCheckpoint("AC:ACL_DESCRIPTOR_FREE_BEGIN\n");
  if (security_descriptor) LocalFree(security_descriptor);
  if (security_descriptor) AppContainerCheckpoint("AC:ACL_DESCRIPTOR_FREE_DONE\n");
  if (acl_result != ERROR_SUCCESS) {
    if (dacl) LocalFree(dacl);
    SetLastError(acl_result);
    return false;
  }
  if (!dacl) {
    SetLastError(ERROR_INVALID_DATA);
    return false;
  }
  AppContainerCheckpoint("AC:ACL_BUILD_OK\n");
  AppContainerCheckpoint("AC:ACL_SET_BEGIN\n");
  const DWORD result = SetNamedSecurityInfoW(const_cast<LPWSTR>(output.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
  AppContainerCheckpoint("AC:ACL_SET_RETURNED\n");
  AppContainerCheckpoint("AC:ACL_FREE_BEGIN\n");
  LocalFree(dacl);
  AppContainerCheckpoint("AC:ACL_FREE_DONE\n");
  if (result != ERROR_SUCCESS) SetLastError(result);
  if (result == ERROR_SUCCESS) AppContainerCheckpoint("AC:ACL_SET_OK\n");
  return result == ERROR_SUCCESS;
}

void ReleaseProbeMemory(PWSTR profile_path, PSID sid, PSID second_sid) {
  AppContainerCheckpoint("AC:RESOURCE_FREE_BEGIN\n");
  if (profile_path) AppContainerCheckpoint("AC:PROFILE_PATH_FREE_BEGIN\n");
  if (profile_path) CoTaskMemFree(profile_path);
  if (profile_path) AppContainerCheckpoint("AC:PROFILE_PATH_FREE_DONE\n");
  if (sid) AppContainerCheckpoint("AC:PRIMARY_SID_FREE_BEGIN\n");
  if (sid) FreeSid(sid);
  if (sid) AppContainerCheckpoint("AC:PRIMARY_SID_FREE_DONE\n");
  if (second_sid) AppContainerCheckpoint("AC:SECONDARY_SID_FREE_BEGIN\n");
  if (second_sid) FreeSid(second_sid);
  if (second_sid) AppContainerCheckpoint("AC:SECONDARY_SID_FREE_DONE\n");
  AppContainerCheckpoint("AC:RESOURCE_FREE_DONE\n");
}

bool DeleteProbeProfiles(const std::wstring& profile, const std::wstring& second_profile,
                         bool first_created, bool second_created) {
  bool okay = true;
  if (first_created) {
    AppContainerCheckpoint("AC:DELETE_PRIMARY_BEGIN\n");
    const HRESULT result = DeleteAppContainerProfile(profile.c_str());
    AppContainerCheckpoint("AC:DELETE_PRIMARY_RETURNED\n");
    if (FAILED(result)) {
      ReportAppContainerFailure("delete_primary_profile", result, ERROR_SUCCESS);
      okay = false;
    }
  }
  if (second_created) {
    AppContainerCheckpoint("AC:DELETE_SECONDARY_BEGIN\n");
    const HRESULT result = DeleteAppContainerProfile(second_profile.c_str());
    AppContainerCheckpoint("AC:DELETE_SECONDARY_RETURNED\n");
    if (FAILED(result)) {
      ReportAppContainerFailure("delete_secondary_profile", result, ERROR_SUCCESS);
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
    AppContainerCheckpoint("AC:CREATE_PRIMARY_BEGIN\n");
    HRESULT result = CreateAppContainerProfile(profile.c_str(), L"SumatraFuzz API Probe",
                                                L"Ephemeral feasibility probe", nullptr, 0, &sid);
    AppContainerCheckpoint("AC:CREATE_PRIMARY_RETURNED\n");
    if (FAILED(result) || !sid) {
      ReportAppContainerFailure("create_profile", result, ERROR_SUCCESS);
      goto cleanup;
    }
    first_created = true;
    {
      LPWSTR sid_string = nullptr;
      AppContainerCheckpoint("AC:SID_STRING_BEGIN\n");
      if (!ConvertSidToStringSidW(sid, &sid_string)) {
        ReportAppContainerFailure("convert_profile_sid", S_OK, GetLastError());
        goto cleanup;
      }
      AppContainerCheckpoint("AC:SID_STRING_RETURNED\n");
      AppContainerCheckpoint("AC:FOLDER_QUERY_BEGIN\n");
      result = GetAppContainerFolderPath(sid_string, &profile_path);
      AppContainerCheckpoint("AC:FOLDER_QUERY_RETURNED\n");
      AppContainerCheckpoint("AC:SID_STRING_FREE_BEGIN\n");
      LocalFree(sid_string);
      AppContainerCheckpoint("AC:SID_STRING_FREE_DONE\n");
    }
    if (FAILED(result) || !profile_path || GetFullPathNameW(profile_path, 0, nullptr, nullptr) == 0) {
      ReportAppContainerFailure("get_profile_folder", result,
                                FAILED(result) ? ERROR_SUCCESS : GetLastError());
      goto cleanup;
    }
    if (!WriteAppContainerPath("AppContainerProfilePath=", profile_path)) {
      ReportAppContainerFailure("write_profile_path", S_OK, GetLastError());
      goto cleanup;
    }
    if (!WriteAppContainerPath("AppContainerTempPath=", output.c_str())) {
      ReportAppContainerFailure("write_temp_path", S_OK, GetLastError());
      goto cleanup;
    }
    AppContainerCheckpoint("AC:CREATE_SECONDARY_BEGIN\n");
    result = CreateAppContainerProfile(second_profile.c_str(), L"SumatraFuzz API Probe",
                                        L"Ephemeral feasibility probe", nullptr, 0, &second_sid);
    AppContainerCheckpoint("AC:CREATE_SECONDARY_RETURNED\n");
    if (FAILED(result) || !second_sid) {
      ReportAppContainerFailure("create_unique_profile", result, ERROR_SUCCESS);
      goto cleanup;
    }
    if (EqualSid(sid, second_sid)) {
      ReportAppContainerFailure("verify_unique_package_sid", HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
                                ERROR_INVALID_DATA);
      goto cleanup;
    }
    second_created = true;
    AppContainerCheckpoint("AC:ACL_CALL_BEGIN\n");
    if (!GrantAppContainerDirectoryAccess(output, sid)) {
      ReportAppContainerFailure("grant_output_acl", S_OK, GetLastError());
      goto cleanup;
    }
    AppContainerCheckpoint("AC:ACL_CALL_DONE\n");
    {
      const std::wstring appcontainer_executable = output + L"\\appcontainer-probe.exe";
      if (!CopyFileW(executable.c_str(), appcontainer_executable.c_str(), TRUE)) {
        ReportAppContainerFailure("copy_probe_executable", S_OK, GetLastError());
        goto cleanup;
      }
      SIZE_T bytes = 0;
      InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
      if (bytes == 0) {
        ReportAppContainerFailure("size_process_attributes", S_OK, GetLastError());
        goto cleanup;
      }
      std::vector<BYTE> attributes(bytes);
      auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
      if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) {
        ReportAppContainerFailure("initialize_process_attributes", S_OK, GetLastError());
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
        ReportAppContainerFailure("set_security_capabilities", S_OK, error);
        goto cleanup;
      }
      STARTUPINFOEXW startup{};
      startup.StartupInfo.cb = sizeof(startup);
      startup.lpAttributeList = list;
      PROCESS_INFORMATION process{};
      std::wstring command = L"\"" + appcontainer_executable + L"\" --appcontainer-child \"" + output +
          L"\" \"" + world + L"\" \"" + authenticated + L"\" \"" + world_low +
          L"\" \"" + authenticated_low + L"\"";
      AppContainerCheckpoint("AC:CHILD_LAUNCH_BEGIN\n");
      const BOOL launched = CreateProcessW(appcontainer_executable.c_str(), command.data(), nullptr, nullptr,
          FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, output.c_str(),
          &startup.StartupInfo, &process);
      AppContainerCheckpoint("AC:CHILD_LAUNCH_RETURNED\n");
      DeleteProcThreadAttributeList(list);
      if (!launched) {
        ReportAppContainerFailure("launch_appcontainer", S_OK, GetLastError());
        goto cleanup;
      }
      AppContainerCheckpoint("AC:CHILD_LAUNCHED\n");
      DWORD wait = WaitForSingleObject(process.hProcess, 30000);
      if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        wait = WaitForSingleObject(process.hProcess, 30000);
      }
      DWORD exit_code = 0xffffffff;
      if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exit_code);
      else ReportAppContainerFailure("wait_for_appcontainer", S_OK, GetLastError());
      AppContainerCheckpoint("AC:CHILD_EXIT_OBSERVED\n");
      CloseHandle(process.hThread);
      CloseHandle(process.hProcess);
      okay = wait == WAIT_OBJECT_0 && exit_code == 0;
      if (wait == WAIT_OBJECT_0 && exit_code != 0)
        ReportAppContainerFailure("verify_appcontainer_child", HRESULT_FROM_WIN32(exit_code), exit_code);
    }
  cleanup:
    ReleaseProbeMemory(profile_path, sid, second_sid);
    const bool profiles_deleted = DeleteProbeProfiles(profile, second_profile,
                                                       first_created, second_created);
    okay = profiles_deleted && okay;
    return okay;
  } catch (...) {
    ReportAppContainerFailure("handle_probe_exception", E_FAIL, ERROR_SUCCESS);
    ReleaseProbeMemory(profile_path, sid, second_sid);
    const bool cleanup_succeeded = DeleteProbeProfiles(profile, second_profile,
                                                        first_created, second_created);
    if (!cleanup_succeeded)
      AppContainerCheckpoint("AC:EXCEPTION_CLEANUP_INCOMPLETE\n");
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
  if (argc == 3 && std::wstring(argv[1]) == L"--run-resource-contract")
    return RunResourceContract(argv[2]) ? 0 : 83;
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
