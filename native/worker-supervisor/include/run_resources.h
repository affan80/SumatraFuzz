#pragma once

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <userenv.h>
#include <objbase.h>

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace sumatrafuzz::supervisor {

inline void ResourceError(DWORD code, const char* operation) {
  throw std::system_error(static_cast<int>(code), std::system_category(), operation);
}

inline bool IsRunPackageSid(PSID sid) {
  const SID_IDENTIFIER_AUTHORITY package = SECURITY_APP_PACKAGE_AUTHORITY;
  return sid && IsValidSid(sid) &&
      std::memcmp(GetSidIdentifierAuthority(sid), &package, sizeof(package)) == 0 &&
      *GetSidSubAuthorityCount(sid) == SECURITY_APP_PACKAGE_RID_COUNT &&
      *GetSidSubAuthority(sid, 0) == SECURITY_APP_PACKAGE_BASE_RID;
}

struct ProfileCleanupRecord {
  std::wstring name;
  PSID sid = nullptr;
  ProfileCleanupRecord* next = nullptr;
};
inline ProfileCleanupRecord* g_profile_cleanup_quarantine = nullptr;

struct AppContainerProfile {
  std::wstring name;
  PSID sid = nullptr;
  bool created = false;
  std::unique_ptr<ProfileCleanupRecord> cleanup_record;
  AppContainerProfile() : cleanup_record(std::make_unique<ProfileCleanupRecord>()) {}
  AppContainerProfile(const AppContainerProfile&) = delete;
  AppContainerProfile& operator=(const AppContainerProfile&) = delete;
  AppContainerProfile(AppContainerProfile&& other) noexcept { Swap(other); }
  AppContainerProfile& operator=(AppContainerProfile&& other) noexcept {
    // Transfer the old ownership to other; never discard an undeleted profile.
    Swap(other);
    return *this;
  }
  void Swap(AppContainerProfile& other) noexcept {
    name.swap(other.name);
    std::swap(sid, other.sid);
    std::swap(created, other.created);
    cleanup_record.swap(other.cleanup_record);
  }
  DWORD Close() noexcept {
    if (!created) return ERROR_SUCCESS;
    const HRESULT result = DeleteAppContainerProfile(name.c_str());
    if (FAILED(result)) return HRESULT_FACILITY(result) == FACILITY_WIN32
        ? HRESULT_CODE(result) : ERROR_GEN_FAILURE;
    if (sid) FreeSid(sid);
    sid = nullptr;
    created = false;
    name.clear();
    return ERROR_SUCCESS;
  }
  ~AppContainerProfile() {
    if (Close() != ERROR_SUCCESS) {
      cleanup_record->name.swap(name);
      cleanup_record->sid = sid;
      cleanup_record->next = g_profile_cleanup_quarantine;
      g_profile_cleanup_quarantine = cleanup_record.release();
      OutputDebugStringW(L"SumatraFuzz AppContainer profile cleanup failed; identity quarantined\n");
    }
  }
};

inline AppContainerProfile CreateRunAppContainerProfile() {
  GUID id{};
  const HRESULT generated = CoCreateGuid(&id);
  if (FAILED(generated)) ResourceError(ERROR_GEN_FAILURE, "AppContainer identity generation");
  wchar_t text[40]{};
  if (!StringFromGUID2(id, text, 40)) ResourceError(ERROR_GEN_FAILURE, "AppContainer identity formatting");
  AppContainerProfile profile;
  // 39 ASCII characters, below the API's 64-character profile-name limit.
  profile.name = L"SF-" + std::wstring(text + 1, 36);
  const HRESULT result = CreateAppContainerProfile(profile.name.c_str(), L"SumatraFuzz run",
      L"Ephemeral worker run", nullptr, 0, &profile.sid);
  // Collisions are fatal. Never derive/open/delete a profile we did not create.
  if (FAILED(result)) {
    if (profile.sid) FreeSid(profile.sid);
    profile.sid = nullptr;
    ResourceError(HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : ERROR_GEN_FAILURE,
                  "AppContainer profile creation");
  }
  profile.created = true;
  if (!IsRunPackageSid(profile.sid)) ResourceError(ERROR_INVALID_SID, "AppContainer package identity");
  return profile;
}

enum class RunResourceAccess { ToolReadExecute, InputRead, EvidenceModify };
struct RunResourceRule {
  std::wstring path;
  RunResourceAccess access;
  // Borrowed from the native verifier/selector; must stay open through grant
  // acquisition. Path text alone is never an authorization identity.
  HANDLE proof = INVALID_HANDLE_VALUE;
};
// The launch builder must populate exact objects from held VerifyProofs handles,
// selected input enumeration and the newly-created run evidence/scratch objects.
// There is deliberately no recursive/root authorization or arbitrary ACL mask.
struct RunResourcePolicy {
  std::vector<RunResourceRule> objects;
  std::vector<std::wstring> excluded_roots;  // trust, audit and credential stores
};

inline std::wstring ResourcePathKey(std::wstring path) {
  if (path.size() < 3 || !std::iswalpha(path[0]) || path[1] != L':' || path[2] != L'\\' ||
      path.find(L'\0') != std::wstring::npos || path.find(L'/', 0) != std::wstring::npos ||
      path.find(L':', 2) != std::wstring::npos)
    ResourceError(ERROR_INVALID_NAME, "run resource local path");
  size_t start = 3;
  while (start < path.size()) {
    const size_t end = path.find(L'\\', start);
    const auto part = path.substr(start, end == std::wstring::npos ? end : end - start);
    if (part.empty() || part.back() == L'.' || part.back() == L' ')
      ResourceError(ERROR_INVALID_NAME, "run resource path component");
    if (end == std::wstring::npos) break;
    start = end + 1;
    if (start == path.size()) ResourceError(ERROR_INVALID_NAME, "run resource trailing separator");
  }
  std::transform(path.begin(), path.end(), path.begin(), [](wchar_t c) { return std::towlower(c); });
  return path;
}

struct ResourceHandle {
  HANDLE value = INVALID_HANDLE_VALUE;
  ResourceHandle() = default;
  explicit ResourceHandle(HANDLE handle) : value(handle) {}
  ResourceHandle(const ResourceHandle&) = delete;
  ResourceHandle& operator=(const ResourceHandle&) = delete;
  ResourceHandle(ResourceHandle&& other) noexcept : value(other.value) { other.value = INVALID_HANDLE_VALUE; }
  ~ResourceHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

inline ResourceHandle OpenRunResource(const std::wstring& path, DWORD access, bool directory) {
  // FILE_READ_DATA (FILE_LIST_DIRECTORY for directories) makes this open
  // participate in MS-FSA sharing checks. Metadata-only opens do not pin names.
  // Omit WRITE/DELETE sharing to block data-writer opens and rename. This
  // alone does not establish denial of metadata-only reparse/hardlink changes;
  // the Windows mutation contract must prove that boundary before integration.
  ResourceHandle handle(CreateFileW(path.c_str(), access | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (handle.value == INVALID_HANDLE_VALUE) ResourceError(GetLastError(), "run resource open");
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle.value, &info)) ResourceError(GetLastError(), "run resource attributes");
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      (directory && !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) || info.nNumberOfLinks > 1)
    ResourceError(ERROR_ACCESS_DENIED, "run resource redirected or aliased");
  return handle;
}

struct GrantCleanupRecord {
  std::vector<ResourceHandle> ancestors;
  ResourceHandle object;
  std::vector<BYTE> sid;
  GrantCleanupRecord* next = nullptr;
};
inline GrantCleanupRecord* g_grant_cleanup_quarantine = nullptr;

struct RunResourceGrant {
  std::vector<ResourceHandle> ancestors;
  ResourceHandle object;
  std::vector<BYTE> sid;
  bool active = false;
  std::unique_ptr<GrantCleanupRecord> cleanup_record = std::make_unique<GrantCleanupRecord>();
  RunResourceGrant() = default;
  RunResourceGrant(const RunResourceGrant&) = delete;
  RunResourceGrant& operator=(const RunResourceGrant&) = delete;
  DWORD Remove() noexcept {
    if (!active) return ERROR_SUCCESS;
    PACL current = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD result = GetSecurityInfo(object.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                  nullptr, nullptr, &current, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) { if (descriptor) LocalFree(descriptor); return result; }
    if (!current || !IsValidAcl(current)) {
      LocalFree(descriptor);
      return ERROR_INVALID_ACL;
    }
    std::vector<BYTE> storage;
    // Reserve rollback storage before mutation; allocation failure is reported,
    // never allowed to throw through process-tree teardown.
    try { storage.resize(current->AclSize); }
    catch (...) { LocalFree(descriptor); return ERROR_NOT_ENOUGH_MEMORY; }
    PACL updated = reinterpret_cast<PACL>(storage.data());
    if (!InitializeAcl(updated, current->AclSize, current->AclRevision)) result = GetLastError();
    for (DWORD i = 0; result == ERROR_SUCCESS && i < current->AceCount; ++i) {
      void* ace = nullptr;
      if (!GetAce(current, i, &ace)) { result = GetLastError(); break; }
      auto* header = static_cast<ACE_HEADER*>(ace);
      const bool ours = header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
          EqualSid(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, sid.data());
      if (!ours && !AddAce(updated, current->AclRevision, MAXDWORD, ace, header->AceSize)) result = GetLastError();
    }
    if (result == ERROR_SUCCESS) result = SetSecurityInfo(object.value, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, updated, nullptr);
    LocalFree(descriptor);
    if (result == ERROR_SUCCESS) active = false;
    return result;
  }
  ~RunResourceGrant() {
    if (Remove() != ERROR_SUCCESS) {
      cleanup_record->ancestors.swap(ancestors);
      std::swap(cleanup_record->object.value, object.value);
      cleanup_record->sid.swap(sid);
      cleanup_record->next = g_grant_cleanup_quarantine;
      g_grant_cleanup_quarantine = cleanup_record.release();
      OutputDebugStringW(L"SumatraFuzz run ACL cleanup failed; handles quarantined\n");
    }
  }
};

inline std::unique_ptr<RunResourceGrant> GrantRunResourceAccess(
    const std::wstring& path, PSID sid, RunResourceAccess access, const RunResourcePolicy& policy) {
  if (!IsRunPackageSid(sid)) ResourceError(ERROR_INVALID_SID, "run resource package identity");
  const std::wstring key = ResourcePathKey(path);
  if (key.size() == 3) ResourceError(ERROR_ACCESS_DENIED, "volume root is not a run resource");
  for (const auto& excluded : policy.excluded_roots) {
    const auto root = ResourcePathKey(excluded);
    if (key == root || (key.size() > root.size() && key.compare(0, root.size(), root) == 0 &&
        (root.back() == L'\\' || key[root.size()] == L'\\')))
      ResourceError(ERROR_ACCESS_DENIED, "excluded run resource");
  }
  const auto approved = std::find_if(policy.objects.begin(), policy.objects.end(), [&](const RunResourceRule& rule) {
    return access == rule.access && key == ResourcePathKey(rule.path);
  });
  if (approved == policy.objects.end()) ResourceError(ERROR_ACCESS_DENIED, "unapproved run resource");
  auto grant = std::make_unique<RunResourceGrant>();
  grant->sid.resize(GetLengthSid(sid));
  if (!CopySid(static_cast<DWORD>(grant->sid.size()), grant->sid.data(), sid))
    ResourceError(GetLastError(), "run resource SID copy");
  // Hold sharing-participating ancestor handles through ACL removal. Bind
  // the final opened object to its held proof identity before changing its ACL.
  grant->ancestors.push_back(OpenRunResource(path.substr(0, 3), FILE_READ_ATTRIBUTES, true));
  for (size_t end = path.find(L'\\', 3); end != std::wstring::npos; end = path.find(L'\\', end + 1))
    grant->ancestors.push_back(OpenRunResource(path.substr(0, end), FILE_READ_ATTRIBUTES, true));
  ResourceHandle object = OpenRunResource(path, READ_CONTROL | WRITE_DAC, false);
  grant->object.value = object.value;
  object.value = INVALID_HANDLE_VALUE;
  std::wstring final_path(32768, L'\0');
  const DWORD final_length = GetFinalPathNameByHandleW(grant->object.value, final_path.data(),
      static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!final_length || final_length >= final_path.size()) ResourceError(ERROR_INVALID_NAME, "run resource canonical path");
  final_path.resize(final_length);
  if (final_path.compare(0, 4, L"\\\\?\\") != 0 || ResourcePathKey(final_path.substr(4)) != key)
    ResourceError(ERROR_ACCESS_DENIED, "run resource path alias");
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(grant->object.value, &info)) ResourceError(GetLastError(), "run resource attributes");
  const bool directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  FILE_ID_INFO actual_id{}, proof_id{};
  if (approved->proof == INVALID_HANDLE_VALUE || approved->proof == nullptr)
    ResourceError(ERROR_INVALID_HANDLE, "run resource held proof required");
  if (!GetFileInformationByHandleEx(approved->proof, FileIdInfo, &proof_id, sizeof(proof_id)) ||
      !GetFileInformationByHandleEx(grant->object.value, FileIdInfo, &actual_id, sizeof(actual_id)))
    ResourceError(GetLastError(), "run resource proof identity query");
  if (actual_id.VolumeSerialNumber != proof_id.VolumeSerialNumber ||
      std::memcmp(&actual_id.FileId, &proof_id.FileId, sizeof(actual_id.FileId)) != 0)
    ResourceError(ERROR_FILE_INVALID, "run resource proof identity changed");
  if (access == RunResourceAccess::ToolReadExecute && directory)
    ResourceError(ERROR_ACCESS_DENIED, "tool grants require verified files");
  // Writable file handles require FILE_SHARE_WRITE, which would also allow
  // reparse retargeting. Only the pinned evidence/scratch directory receives
  // Modify here; child objects must use the run token's scoped/default DACL.
  if (access == RunResourceAccess::EvidenceModify && !directory)
    ResourceError(ERROR_ACCESS_DENIED, "evidence grants require run directories");
  DWORD mask = FILE_GENERIC_READ;
  if (directory) mask |= FILE_TRAVERSE;
  if (access == RunResourceAccess::ToolReadExecute) mask |= FILE_GENERIC_EXECUTE;
  if (access == RunResourceAccess::EvidenceModify) {
    mask |= (FILE_GENERIC_WRITE & ~FILE_WRITE_ATTRIBUTES) | DELETE;
    if (directory) mask |= FILE_DELETE_CHILD;
  }
  PACL current = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD result = GetSecurityInfo(grant->object.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &current, nullptr, &descriptor);
  if (result != ERROR_SUCCESS) {
    if (descriptor) LocalFree(descriptor);
    ResourceError(result, "run resource ACL read");
  }
  struct DescriptorOwner {
    PSECURITY_DESCRIPTOR value;
    ~DescriptorOwner() { if (value) LocalFree(value); }
  } owner{descriptor};
  if (!current || !IsValidAcl(current)) ResourceError(ERROR_INVALID_ACL, "run resource ACL validation");
  const DWORD bytes = current->AclSize + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(sid);
  if (bytes > MAXWORD) ResourceError(ERROR_INVALID_ACL, "run resource ACL size");
  std::vector<BYTE> storage(bytes);
  PACL updated = reinterpret_cast<PACL>(storage.data());
  if (!InitializeAcl(updated, bytes, current->AclRevision)) ResourceError(GetLastError(), "run resource ACL initialization");
  bool inserted = false;
  for (DWORD i = 0; i < current->AceCount; ++i) {
    void* ace = nullptr;
    if (!GetAce(current, i, &ace)) ResourceError(GetLastError(), "run resource ACE read");
    auto* header = static_cast<ACE_HEADER*>(ace);
    if ((header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
        EqualSid(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, sid))
      ResourceError(ERROR_ALREADY_EXISTS, "run resource package ACE already exists");
    if (!inserted && (header->AceFlags & INHERITED_ACE)) {
      if (!AddAccessAllowedAceEx(updated, current->AclRevision, NO_INHERITANCE, mask, sid))
        ResourceError(GetLastError(), "run resource ACE creation");
      inserted = true;
    }
    if (!AddAce(updated, current->AclRevision, MAXDWORD, ace, header->AceSize))
      ResourceError(GetLastError(), "run resource ACL copy");
  }
  if (!inserted && !AddAccessAllowedAceEx(updated, current->AclRevision, NO_INHERITANCE, mask, sid))
    ResourceError(GetLastError(), "run resource ACE creation");
  result = SetSecurityInfo(grant->object.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, updated, nullptr);
  if (result != ERROR_SUCCESS) ResourceError(result, "run resource ACL grant");
  grant->active = true;
  return grant;
}

// Retain cleanup failures for the supervisor lifetime. This avoids losing the
// retryable profile/handles or declaring successful cleanup after an OS error.
struct RunResourceState {
  AppContainerProfile profile;
  std::vector<std::unique_ptr<RunResourceGrant>> grants;
  RunResourceState* next = nullptr;
};
inline RunResourceState* g_resource_cleanup_quarantine = nullptr;
struct RunResources {
  std::unique_ptr<RunResourceState> state = std::make_unique<RunResourceState>();
  RunResources() = default;
  RunResources(const RunResources&) = delete;
  RunResources& operator=(const RunResources&) = delete;
  RunResources(RunResources&& other) noexcept : state(std::move(other.state)) {}
  RunResources& operator=(RunResources&& other) noexcept {
    // Swap preserves any previous owner until the other object is destroyed.
    state.swap(other.state);
    return *this;
  }
  DWORD Close() noexcept {
    if (!state) return ERROR_SUCCESS;
    for (auto it = state->grants.rbegin(); it != state->grants.rend(); ++it) {
      const DWORD result = (*it)->Remove();
      if (result != ERROR_SUCCESS) return result;
    }
    state->grants.clear();
    return state->profile.Close();
  }
  ~RunResources() {
    if (Close() != ERROR_SUCCESS) {
      state->next = g_resource_cleanup_quarantine;
      g_resource_cleanup_quarantine = state.release();
      OutputDebugStringW(L"SumatraFuzz run resource cleanup unconfirmed; resources quarantined\n");
    }
  }
};

}  // namespace sumatrafuzz::supervisor
#endif
