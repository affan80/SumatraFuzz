#include "service_host.h"
#include "command_line.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <memory>
#include <objbase.h>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

using sumatrafuzz::service_host::ControlFrame;
using sumatrafuzz::service_host::ServiceState;

constexpr wchar_t kServiceName[] = L"SumatraFuzzWorker";
constexpr wchar_t kHostFileName[] = L"SumatraFuzzWorkerHost.exe";
constexpr wchar_t kWorkerRelativePath[] = L"apps\\worker-service\\dist\\src\\service-entry.js";
constexpr wchar_t kNodeRelativePath[] = L"runtime\\node.exe";
constexpr DWORD kReadyTimeoutMs = 30000;
constexpr DWORD kStopTimeoutMs = 60000;
constexpr DWORD kExitAfterStopTimeoutMs = 5000;
constexpr DWORD kTrustPipeReadTimeoutMs = 10000;
constexpr DWORD kTrustOperationTimeoutMs = 30000;
constexpr BYTE kTrustPipeReceiptAck = 0xa5;
constexpr DWORD kPollMs = 25;
constexpr DWORD kForcedStopCode = 0x2001;
constexpr DWORD kStartupFailureCode = 0x2002;

struct Handle final {
  HANDLE value = nullptr;
  Handle() = default;
  explicit Handle(HANDLE handle) : value(handle) {}
  ~Handle() { Reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value(other.value) { other.value = nullptr; }
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) { Reset(); value = other.value; other.value = nullptr; }
    return *this;
  }
  void Reset(HANDLE handle = nullptr) {
    if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    value = handle;
  }
  HANDLE Get() const { return value; }
  explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};

struct VectorScrubber final {
  std::vector<std::uint8_t>& bytes;
  ~VectorScrubber() {
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
  }
};

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
DWORD g_checkpoint = 0;
SRWLOCK g_status_lock = SRWLOCK_INIT;

std::wstring WinError(const wchar_t* what, DWORD error = GetLastError()) {
  return std::wstring(what) + L" (Windows error " + std::to_wstring(error) + L")";
}

bool WritePipeBounded(HANDLE pipe, const BYTE* source, DWORD size, DWORD timeout_ms, bool observe_stop);

void SetStatus(DWORD state, DWORD win32_exit = NO_ERROR, DWORD service_exit = 0) {
  if (!g_status_handle) return;
  AcquireSRWLockExclusive(&g_status_lock);
  const auto current = g_status.dwCurrentState == SERVICE_START_PENDING ? ServiceState::StartPending :
                       g_status.dwCurrentState == SERVICE_RUNNING ? ServiceState::Running :
                       g_status.dwCurrentState == SERVICE_STOP_PENDING ? ServiceState::StopPending : ServiceState::Stopped;
  const auto next = state == SERVICE_START_PENDING ? ServiceState::StartPending :
                    state == SERVICE_RUNNING ? ServiceState::Running :
                    state == SERVICE_STOP_PENDING ? ServiceState::StopPending : ServiceState::Stopped;
  if (!sumatrafuzz::service_host::IsAllowedTransition(current, next)) {
    ReleaseSRWLockExclusive(&g_status_lock);
    return;
  }
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = state;
  g_status.dwWin32ExitCode = win32_exit;
  g_status.dwServiceSpecificExitCode = service_exit;
  g_status.dwWaitHint = state == SERVICE_START_PENDING ? kReadyTimeoutMs :
                        state == SERVICE_STOP_PENDING ? kStopTimeoutMs : 0;
  if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
    g_status.dwControlsAccepted = 0;
    g_status.dwCheckPoint = ++g_checkpoint;
  } else {
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_status.dwCheckPoint = 0;
  }
  SetServiceStatus(g_status_handle, &g_status);
  ReleaseSRWLockExclusive(&g_status_lock);
}

void WINAPI ServiceControlHandler(DWORD control) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
    SetStatus(SERVICE_STOP_PENDING);
    if (g_stop_event) SetEvent(g_stop_event);
  } else if (control == SERVICE_CONTROL_INTERROGATE && g_status_handle) {
    AcquireSRWLockShared(&g_status_lock);
    SetServiceStatus(g_status_handle, &g_status);
    ReleaseSRWLockShared(&g_status_lock);
  }
}

std::wstring ModulePath() {
  std::wstring path(32768, L'\0');
  const DWORD count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (count == 0 || count >= path.size()) throw WinError(L"cannot resolve service host path");
  path.resize(count);
  return path;
}

std::wstring FinalPath(HANDLE handle) {
  std::wstring path(32768, L'\0');
  const DWORD count = GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (count == 0 || count >= path.size()) throw WinError(L"cannot canonicalize protected path");
  path.resize(count);
  return path;
}

Handle OpenPath(const std::wstring& path, bool directory) {
  const DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
  Handle handle(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, flags, nullptr));
  if (!handle) throw WinError(L"cannot open protected install path");
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle.Get(), &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      (directory != ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0))) {
    throw std::runtime_error("protected install path is redirected or has the wrong type");
  }
  return handle;
}

bool IsWriteMask(DWORD mask) {
  constexpr DWORD write_bits = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                               FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER |
                               GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED;
  return (mask & write_bits) != 0;
}

enum class ServiceWriteAccess { None, RuntimeDirectory, CredentialFile, DeleteStagedFile };

bool IsAllowedServiceWriteMask(DWORD mask, ServiceWriteAccess access) {
  constexpr DWORD forbidden = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL |
                              MAXIMUM_ALLOWED | WRITE_DAC | WRITE_OWNER;
  if ((mask & forbidden) != 0 || access == ServiceWriteAccess::None) return false;
  constexpr DWORD runtime = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                            FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                            FILE_DELETE_CHILD | DELETE;
  constexpr DWORD credential = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                               FILE_WRITE_ATTRIBUTES | DELETE;
  constexpr DWORD staged = DELETE;
  const DWORD allowed = access == ServiceWriteAccess::RuntimeDirectory ? runtime :
                        access == ServiceWriteAccess::CredentialFile ? credential : staged;
  constexpr DWORD write_bits = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                               FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE |
                               WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL |
                               MAXIMUM_ALLOWED;
  const DWORD requested = mask & write_bits;
  return requested != 0 && (requested & ~allowed) == 0;
}

bool SidMatchesWellKnown(PSID sid, WELL_KNOWN_SID_TYPE type) {
  std::array<BYTE, SECURITY_MAX_SID_SIZE> bytes{};
  DWORD size = static_cast<DWORD>(bytes.size());
  return CreateWellKnownSid(type, nullptr, bytes.data(), &size) && EqualSid(sid, bytes.data());
}

std::wstring Lower(std::wstring value);

bool SamePath(std::wstring left, std::wstring right) {
  const auto strip_extended_prefix = [](std::wstring* path) {
    if (path->rfind(L"\\\\?\\UNC\\", 0) == 0) *path = L"\\\\" + path->substr(8);
    else if (path->rfind(L"\\\\?\\", 0) == 0) *path = path->substr(4);
  };
  strip_extended_prefix(&left);
  strip_extended_prefix(&right);
  return Lower(std::move(left)) == Lower(std::move(right));
}

bool IsLocalDrivePath(const std::wstring& path) {
  return path.size() >= 3 && std::iswalpha(path[0]) && path[1] == L':' &&
         (path[2] == L'\\' || path[2] == L'/') && path.rfind(L"\\\\", 0) != 0;
}

std::vector<BYTE> ResolveServiceSid() {
  DWORD sid_size = 0;
  DWORD domain_chars = 0;
  LookupAccountNameW(nullptr, L"NT SERVICE\\SumatraFuzzWorker", nullptr, &sid_size, nullptr, &domain_chars, nullptr);
  if (sid_size == 0 || domain_chars == 0) throw WinError(L"cannot resolve dedicated service SID", ERROR_NONE_MAPPED);
  std::vector<BYTE> sid(sid_size);
  std::vector<wchar_t> domain(domain_chars + 1);
  SID_NAME_USE use{};
  if (!LookupAccountNameW(nullptr, L"NT SERVICE\\SumatraFuzzWorker", sid.data(), &sid_size,
                          domain.data(), &domain_chars, &use)) throw WinError(L"cannot resolve dedicated service SID");
  return sid;
}

bool IsTrustedWritePrincipal(PSID sid, bool allow_service_write, PSID service_sid) {
  if (SidMatchesWellKnown(sid, WinLocalSystemSid) ||
      SidMatchesWellKnown(sid, WinBuiltinAdministratorsSid)) return true;
  static const std::vector<BYTE> trusted_installer_sid = [] {
    DWORD sid_size = 0;
    DWORD domain_chars = 0;
    LookupAccountNameW(nullptr, L"NT SERVICE\\TrustedInstaller", nullptr, &sid_size, nullptr, &domain_chars, nullptr);
    if (sid_size == 0 || domain_chars == 0) return std::vector<BYTE>{};
    std::vector<BYTE> resolved(sid_size);
    std::vector<wchar_t> domain(domain_chars + 1);
    SID_NAME_USE use{};
    if (!LookupAccountNameW(nullptr, L"NT SERVICE\\TrustedInstaller", resolved.data(), &sid_size,
                            domain.data(), &domain_chars, &use)) return std::vector<BYTE>{};
    return resolved;
  }();
  if (!trusted_installer_sid.empty() && EqualSid(sid, const_cast<BYTE*>(trusted_installer_sid.data()))) return true;
  return allow_service_write && service_sid && EqualSid(sid, service_sid);
}

void RequireProtectedDacl(HANDLE file, ServiceWriteAccess service_write = ServiceWriteAccess::None) {
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD result = GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS) throw WinError(L"cannot inspect install ACL", result);
  std::unique_ptr<void, decltype(&LocalFree)> security(descriptor, LocalFree);
  if (!dacl || !IsValidAcl(dacl)) throw std::runtime_error("missing or malformed DACL on protected service path");
  const std::vector<BYTE> service_sid_bytes = service_write != ServiceWriteAccess::None ? ResolveServiceSid() : std::vector<BYTE>{};
  PSID service_sid = service_sid_bytes.empty() ? nullptr : const_cast<BYTE*>(service_sid_bytes.data());
  for (DWORD index = 0; index < dacl->AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(dacl, index, &raw)) throw WinError(L"cannot inspect install ACL");
    const auto* header = static_cast<ACE_HEADER*>(raw);
    const bool ordinary_allow = header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
      header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
      header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
      header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
    if (header->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE) {
      throw std::runtime_error("unsupported compound allow ACE on protected service path");
    }
    if (!ordinary_allow) continue;
    DWORD mask = 0;
    PSID sid = nullptr;
    if (header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
      if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(DWORD)) throw std::runtime_error("invalid access-control entry");
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      mask = ace->Mask;
      sid = const_cast<DWORD*>(&ace->SidStart);
    } else {
      if (header->AceSize < offsetof(ACCESS_ALLOWED_OBJECT_ACE, ObjectType)) throw std::runtime_error("invalid object access-control entry");
      const auto* ace = static_cast<ACCESS_ALLOWED_OBJECT_ACE*>(raw);
      mask = ace->Mask;
      BYTE* sid_start = reinterpret_cast<BYTE*>(const_cast<GUID*>(&ace->ObjectType));
      if ((ace->Flags & ACE_OBJECT_TYPE_PRESENT) != 0) sid_start += sizeof(GUID);
      if ((ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0) sid_start += sizeof(GUID);
      if (sid_start >= reinterpret_cast<BYTE*>(raw) + header->AceSize) throw std::runtime_error("invalid object access-control SID");
      sid = sid_start;
    }
    const auto* ace_begin = reinterpret_cast<const BYTE*>(raw);
    const auto* sid_begin = reinterpret_cast<const BYTE*>(sid);
    const size_t sid_offset = static_cast<size_t>(sid_begin - ace_begin);
    const size_t sid_available = sid_offset <= header->AceSize ? header->AceSize - sid_offset : 0;
    if (sid_available < 8) throw std::runtime_error("invalid access-control SID");
    const auto* sid_header = static_cast<const SID*>(sid);
    const size_t sid_size = 8 + static_cast<size_t>(sid_header->SubAuthorityCount) * sizeof(DWORD);
    if (sid_header->Revision != SID_REVISION || sid_header->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
        sid_size > sid_available || !IsValidSid(sid) || GetLengthSid(sid) != sid_size) {
      throw std::runtime_error("invalid access-control SID");
    }
    if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
        header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
        header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE ||
        (header->AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) != 0) {
      throw std::runtime_error("unsupported object, callback, or inherited allow ACE on protected service path");
    }
    constexpr DWORD generic_write_bits = GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL |
                                         MAXIMUM_ALLOWED | WRITE_DAC | WRITE_OWNER;
    if (IsWriteMask(mask) && (mask & generic_write_bits) != 0)
      throw std::runtime_error("generic write rights are forbidden on protected service paths");
    const bool trusted = IsTrustedWritePrincipal(sid, service_write != ServiceWriteAccess::None, service_sid);
    const bool service_allowed = service_sid && EqualSid(sid, service_sid) &&
                                 IsAllowedServiceWriteMask(mask, service_write);
    if (IsWriteMask(mask) && !trusted && !service_allowed) {
      throw std::runtime_error("untrusted write access exists on protected service path");
    }
  }
}

std::wstring ParentPath(const std::wstring& path) {
  const size_t separator = path.find_last_of(L"\\/");
  if (separator == std::wstring::npos) throw std::runtime_error("invalid install path layout");
  return path.substr(0, separator);
}

bool IsLocalVolumeRoot(const std::wstring& path) {
  return (path.size() == 3 && std::iswalpha(path[0]) && path[1] == L':' &&
          (path[2] == L'\\' || path[2] == L'/')) ||
         (path.size() == 7 && path.compare(0, 4, L"\\\\?\\") == 0 &&
          std::iswalpha(path[4]) && path[5] == L':' && path[6] == L'\\');
}

void VerifyProtectedInstallAncestors(const std::wstring& install_root) {
  std::wstring ancestor = ParentPath(install_root);
  for (;;) {
    // ParentPath trims the separator at a volume root; restore it before opening.
    if (ancestor.size() == 6 && ancestor.compare(0, 4, L"\\\\?\\") == 0 &&
        std::iswalpha(ancestor[4]) && ancestor[5] == L':') {
      ancestor += L"\\";
    }
    Handle directory = OpenPath(ancestor, true);
    RequireProtectedDacl(directory.Get());
    if (IsLocalVolumeRoot(ancestor)) return;
    const std::wstring parent = ParentPath(ancestor);
    if (parent == ancestor || parent.empty())
      throw std::runtime_error("protected service install ancestor chain is incomplete");
    ancestor = parent;
  }
}

std::wstring Join(const std::wstring& root, const wchar_t* relative) {
  return root + L"\\" + relative;
}

void VerifyProtectedDirectoryChain(const std::wstring& base, const std::vector<std::wstring>& components) {
  std::wstring current = base;
  for (const auto& component : components) {
    current = Join(current, component.c_str());
    Handle directory = OpenPath(current, true);
    RequireProtectedDacl(directory.Get());
  }
}

void VerifyProtectedInstallTree(const std::wstring& root) {
  // Node resolves package code below the entrypoint at runtime. Verify every
  // installed object, not just node.exe and the entry script, so a writable
  // nested node_modules directory cannot become a code-injection path.
  constexpr size_t kMaximumInstallEntries = 100000;
  std::vector<std::wstring> pending{root};
  size_t entries = 0;
  while (!pending.empty()) {
    std::wstring directory = std::move(pending.back());
    pending.pop_back();
    const std::wstring pattern = Join(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(pattern.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) throw WinError(L"cannot enumerate protected install tree");
    struct SearchGuard { HANDLE value; ~SearchGuard() { if (value != INVALID_HANDLE_VALUE) FindClose(value); } } guard{search};
    do {
      if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
      if (++entries > kMaximumInstallEntries) {
        throw std::runtime_error("protected install tree exceeds the verification bound");
      }
      const bool is_directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        throw std::runtime_error("reparse point exists in the protected install tree");
      }
      const std::wstring path = Join(directory, data.cFileName);
      Handle object = OpenPath(path, is_directory);
      RequireProtectedDacl(object.Get());
      if (is_directory) pending.push_back(path);
    } while (FindNextFileW(search, &data));
    const DWORD enumeration_error = GetLastError();
    guard.value = INVALID_HANDLE_VALUE;
    FindClose(search);
    if (enumeration_error != ERROR_NO_MORE_FILES) throw WinError(L"cannot finish protected install tree verification", enumeration_error);
  }
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), towlower);
  return value;
}

struct InstallPaths final {
  std::wstring root;
  std::wstring host;
  std::wstring node;
  std::wstring worker;
  std::wstring data;
};

std::wstring ResolveDataPath() {
  std::array<wchar_t, MAX_PATH + 1> windows{};
  const UINT count = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (count < 3 || count >= windows.size() || windows[1] != L':') throw WinError(L"cannot resolve Windows directory");
  return std::wstring(windows.data(), 3) + L"ProgramData\\SumatraFuzz\\Worker";
}

std::wstring WithTrailingBackslash(std::wstring value) {
  if (value.empty() || (value.back() != L'\\' && value.back() != L'/')) value.push_back(L'\\');
  return value;
}

std::wstring VolumeNameForMountPoint(const std::wstring& mount_point) {
  std::array<wchar_t, 128> volume_name{};
  const std::wstring normalized = WithTrailingBackslash(mount_point);
  if (!GetVolumeNameForVolumeMountPointW(normalized.c_str(), volume_name.data(),
                                         static_cast<DWORD>(volume_name.size()))) {
    throw WinError(L"cannot resolve worker data volume mount point");
  }
  return volume_name.data();
}

void VerifyDedicatedDataVolumeMountPoint(const std::wstring& data_path) {
  const DWORD attributes = GetFileAttributesW(data_path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
    throw std::runtime_error("worker data path must be the fixed dedicated-volume mount point");
  }
  std::array<wchar_t, 32768> mounted_path{};
  if (!GetVolumePathNameW(data_path.c_str(), mounted_path.data(),
                          static_cast<DWORD>(mounted_path.size()))) {
    throw WinError(L"cannot resolve worker data mount root");
  }
  if (!SamePath(WithTrailingBackslash(data_path), mounted_path.data())) {
    throw std::runtime_error("worker data path does not name the mounted volume root");
  }
  const std::wstring data_volume = VolumeNameForMountPoint(mounted_path.data());

  std::array<wchar_t, MAX_PATH + 1> windows{};
  const UINT count = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (count < 3 || count >= windows.size()) throw WinError(L"cannot resolve Windows volume");
  const std::wstring system_volume = VolumeNameForMountPoint(std::wstring(windows.data(), 3));
  if (SamePath(data_volume, system_volume)) {
    throw std::runtime_error("worker data volume must be separate from installed code and Windows");
  }
  std::array<wchar_t, 32> filesystem{};
  if (!GetVolumeInformationW(mounted_path.data(), nullptr, 0, nullptr, nullptr, nullptr,
                             filesystem.data(), static_cast<DWORD>(filesystem.size())) ||
      _wcsicmp(filesystem.data(), L"NTFS") != 0) {
    throw std::runtime_error("worker data volume must use NTFS");
  }
}

Handle OpenWorkerDataVolumeRoot(const std::wstring& path) {
  // Follow only the exact volume mount point already validated above. Opening
  // the target (rather than the reparse object) lets ACL checks cover the
  // dedicated volume root whose quota and identity the worker relies on.
  Handle handle(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (!handle) throw WinError(L"cannot open dedicated worker data volume root");
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle.Get(), &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
    throw std::runtime_error("worker data mount did not resolve to an ordinary volume root");
  }
  return handle;
}

InstallPaths ResolveAndVerifyInstall() {
  InstallPaths paths;
  paths.host = ModulePath();
  if (!IsLocalDrivePath(paths.host)) throw std::runtime_error("service install must use a local drive path");
  Handle host_handle = OpenPath(paths.host, false);
  RequireProtectedDacl(host_handle.Get());
  paths.host = FinalPath(host_handle.Get());
  if (Lower(paths.host.substr(paths.host.find_last_of(L"\\/") + 1)) != Lower(kHostFileName)) {
    throw std::runtime_error("service host executable name does not match the protected layout");
  }
  const std::wstring service_dir = ParentPath(paths.host);
  paths.root = ParentPath(service_dir);
  if (Lower(service_dir.substr(service_dir.find_last_of(L"\\/") + 1)) != L"service" ||
      Lower(paths.root.substr(paths.root.find_last_of(L"\\/") + 1)) != L"sumatrafuzz") {
    throw std::runtime_error("service host is outside the fixed SumatraFuzz install layout");
  }
  Handle service_dir_handle = OpenPath(service_dir, true);
  Handle root_handle = OpenPath(paths.root, true);
  RequireProtectedDacl(service_dir_handle.Get());
  RequireProtectedDacl(root_handle.Get());
  if (!SamePath(FinalPath(service_dir_handle.Get()), service_dir) ||
      !SamePath(FinalPath(root_handle.Get()), paths.root)) {
    throw std::runtime_error("service install root changed during validation");
  }
  VerifyProtectedInstallAncestors(paths.root);
  VerifyProtectedInstallTree(paths.root);
  paths.node = Join(paths.root, kNodeRelativePath);
  paths.worker = Join(paths.root, kWorkerRelativePath);
  VerifyProtectedDirectoryChain(paths.root, {L"runtime"});
  VerifyProtectedDirectoryChain(paths.root, {L"apps", L"worker-service", L"dist"});
  Handle node_handle = OpenPath(paths.node, false);
  Handle worker_handle = OpenPath(paths.worker, false);
  RequireProtectedDacl(node_handle.Get());
  RequireProtectedDacl(worker_handle.Get());
  if (!SamePath(FinalPath(node_handle.Get()), paths.node) || !SamePath(FinalPath(worker_handle.Get()), paths.worker)) {
    throw std::runtime_error("worker executable or entrypoint escaped the protected install root");
  }
  paths.data = ResolveDataPath();
  Handle program_data_handle = OpenPath(ParentPath(ParentPath(paths.data)), true);
  Handle data_parent_handle = OpenPath(ParentPath(paths.data), true);
  RequireProtectedDacl(program_data_handle.Get());
  RequireProtectedDacl(data_parent_handle.Get());
  VerifyDedicatedDataVolumeMountPoint(paths.data);
  Handle data_handle = OpenWorkerDataVolumeRoot(paths.data);
  // Keep the data root itself read-only to the worker so it cannot replace the
  // administrator-owned runtime config or DPAPI credential envelope.
  RequireProtectedDacl(data_handle.Get());
  for (const wchar_t* name : {L"trust", L"runs", L"evidence", L"tmp", L"state", L"security", L"security\\audit", L"inputs", L"outputs"}) {
    Handle data_child = OpenPath(Join(paths.data, name), true);
    RequireProtectedDacl(data_child.Get(), ServiceWriteAccess::RuntimeDirectory);
  }
  for (const wchar_t* name : {L"worker-config.json", L"credentials.dpapi"}) {
    Handle protected_config = OpenPath(Join(paths.data, name), false);
    RequireProtectedDacl(protected_config.Get(), wcscmp(name, L"credentials.dpapi") == 0
      ? ServiceWriteAccess::CredentialFile : ServiceWriteAccess::None);
  }
  Handle staging = OpenPath(Join(paths.data, L"staging"), true);
  RequireProtectedDacl(staging.Get());
  for (const wchar_t* name : {L"worker-credentials.json", L"worker-pairing.sfpair", L"worker-trust-operation.sftxn"}) {
    Handle staged = OpenPath(Join(Join(paths.data, L"staging"), name), false);
    RequireProtectedDacl(staged.Get(), ServiceWriteAccess::DeleteStagedFile);
  }
  return paths;
}

void RequireServiceIdentity() {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw_token)) throw WinError(L"cannot inspect service token");
  Handle token(raw_token);
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  if (!GetTokenInformation(token.Get(), TokenElevation, &elevation, sizeof(elevation), &returned)) throw WinError(L"cannot inspect service elevation");
  if (elevation.TokenIsElevated) throw std::runtime_error("worker service must not run elevated");
  std::array<BYTE, SECURITY_MAX_SID_SIZE> sid_bytes{};
  DWORD sid_size = static_cast<DWORD>(sid_bytes.size());
  if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sid_bytes.data(), &sid_size)) throw WinError(L"cannot resolve SYSTEM identity");
  TOKEN_USER* user = nullptr;
  DWORD user_size = 0;
  GetTokenInformation(token.Get(), TokenUser, nullptr, 0, &user_size);
  std::vector<BYTE> user_buffer(user_size);
  user = reinterpret_cast<TOKEN_USER*>(user_buffer.data());
  if (!GetTokenInformation(token.Get(), TokenUser, user, user_size, &returned)) throw WinError(L"cannot inspect service account");
  if (EqualSid(user->User.Sid, sid_bytes.data())) throw std::runtime_error("worker service must not run as LocalSystem");
  HANDLE raw_membership_token = nullptr;
  if (!DuplicateTokenEx(token.Get(), TOKEN_QUERY, nullptr, SecurityImpersonation, TokenImpersonation,
                        &raw_membership_token)) {
    throw WinError(L"cannot inspect service group membership");
  }
  Handle membership_token(raw_membership_token);
  BOOL is_admin = FALSE;
  std::array<BYTE, SECURITY_MAX_SID_SIZE> admin_bytes{};
  DWORD admin_size = static_cast<DWORD>(admin_bytes.size());
  if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_bytes.data(), &admin_size)) throw WinError(L"cannot resolve administrator group");
  if (!CheckTokenMembership(membership_token.Get(), admin_bytes.data(), &is_admin)) throw WinError(L"cannot inspect administrator membership");
  if (is_admin) throw std::runtime_error("worker service must not run as an administrator");

  const std::vector<BYTE> service_sid = ResolveServiceSid();
  if (!CheckTokenMembership(membership_token.Get(), const_cast<BYTE*>(service_sid.data()), &is_admin) || !is_admin) {
    throw std::runtime_error("worker process lacks its dedicated service SID");
  }
}

std::vector<wchar_t> BuildSanitizedEnvironment(const InstallPaths& paths) {
  std::array<wchar_t, MAX_PATH + 1> windows{};
  const UINT count = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (count < 3 || count >= windows.size()) throw WinError(L"cannot resolve Windows directory");
  const std::wstring system_root(windows.data(), count);
  const std::wstring temporary = Join(paths.data, L"tmp");
  if (!CreateDirectoryW(temporary.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) throw WinError(L"cannot create service temp directory");
  Handle temp_handle = OpenPath(temporary, true);
  RequireProtectedDacl(temp_handle.Get(), ServiceWriteAccess::RuntimeDirectory);
  std::vector<std::wstring> entries{
    L"NODE_ENV=production",
    L"PATH=" + Join(paths.root, L"runtime") + L";" + system_root + L"\\System32",
    L"SystemRoot=" + system_root,
    L"WINDIR=" + system_root,
    L"TEMP=" + temporary,
    L"TMP=" + temporary,
  };
  std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) { return Lower(left) < Lower(right); });
  std::vector<wchar_t> block;
  for (const auto& entry : entries) {
    block.insert(block.end(), entry.begin(), entry.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

bool WriteFrame(HANDLE pipe, ControlFrame frame, DWORD timeout_ms) {
  const auto bytes = sumatrafuzz::service_host::EncodeControlFrame(frame);
  return WritePipeBounded(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), timeout_ms, false);
}

enum class FrameRead { Complete, Timeout, Invalid, PipeError, ChildExited };

FrameRead ReadFrameUntil(HANDLE pipe, HANDLE process, DWORD timeout_ms, ControlFrame* frame,
                         bool observe_stop = true) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  std::array<std::uint8_t, 4 + sumatrafuzz::service_host::kMaxControlFrameBytes> bytes{};
  size_t expected = 4;
  size_t used = 0;
  while (GetTickCount64() < deadline) {
    DWORD available = 0;
    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
      if (GetLastError() == ERROR_BROKEN_PIPE) return FrameRead::ChildExited;
      return FrameRead::PipeError;
    }
    if (available > 0) {
      const DWORD wanted = static_cast<DWORD>(std::min<size_t>(available, expected - used));
      DWORD read = 0;
      if (!ReadFile(pipe, bytes.data() + used, wanted, &read, nullptr) || read == 0) return FrameRead::PipeError;
      used += read;
      if (used == 4) {
        const std::uint32_t payload = static_cast<std::uint32_t>(bytes[0]) |
          (static_cast<std::uint32_t>(bytes[1]) << 8) | (static_cast<std::uint32_t>(bytes[2]) << 16) |
          (static_cast<std::uint32_t>(bytes[3]) << 24);
        if (payload == 0 || payload > sumatrafuzz::service_host::kMaxControlFrameBytes) return FrameRead::Invalid;
        expected = 4 + payload;
      }
      if (used == expected) {
        std::vector<std::uint8_t> complete(bytes.begin(), bytes.begin() + expected);
        return sumatrafuzz::service_host::DecodeControlFrame(complete, frame) ? FrameRead::Complete : FrameRead::Invalid;
      }
      continue;
    }
    if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return FrameRead::ChildExited;
    if (observe_stop && g_stop_event && WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) {
      return FrameRead::Timeout;
    }
    Sleep(kPollMs);
  }
  return FrameRead::Timeout;
}

struct Child final {
  Handle job;
  Handle process;
  Handle ready_read;
  Handle ready_write;
  Handle control_read;
  Handle control_write;
  DWORD pid = 0;
};

void CreatePipePair(Handle* read_end, Handle* write_end, bool read_inheritable, bool write_inheritable) {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  if (!CreatePipe(&read_end->value, &write_end->value, &security, 0)) throw WinError(L"cannot create service control pipe");
  if (!read_inheritable && !SetHandleInformation(read_end->Get(), HANDLE_FLAG_INHERIT, 0)) throw WinError(L"cannot secure pipe handle inheritance");
  if (!write_inheritable && !SetHandleInformation(write_end->Get(), HANDLE_FLAG_INHERIT, 0)) throw WinError(L"cannot secure pipe handle inheritance");
}

void CreateOverlappedControlPipe(Handle* child_read, Handle* parent_write) {
  const std::vector<BYTE> service_sid = ResolveServiceSid();
  LPWSTR service_sid_text = nullptr;
  if (!ConvertSidToStringSidW(const_cast<BYTE*>(service_sid.data()), &service_sid_text)) {
    throw WinError(L"cannot format worker service SID for control pipe");
  }
  const std::wstring sddl = L"D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;" + std::wstring(service_sid_text) + L")";
  LocalFree(service_sid_text);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
    throw WinError(L"cannot protect worker control pipe");
  }
  std::unique_ptr<void, decltype(&LocalFree)> descriptor_owner(descriptor, LocalFree);
  SECURITY_ATTRIBUTES server_security{sizeof(server_security), descriptor, FALSE};
  SECURITY_ATTRIBUTES child_security{sizeof(child_security), nullptr, TRUE};
  GUID identifier{};
  if (CoCreateGuid(&identifier) != S_OK) throw WinError(L"cannot create worker control pipe identity");
  std::array<wchar_t, 40> identifier_text{};
  if (StringFromGUID2(identifier, identifier_text.data(), static_cast<int>(identifier_text.size())) == 0) {
    throw std::runtime_error("cannot format worker control pipe identity");
  }
  const std::wstring pipe_name = std::wstring(L"\\\\.\\pipe\\SumatraFuzzWorker-control-") + identifier_text.data();
  Handle server(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                 1, 4096, 0, 0, &server_security));
  if (!server) throw WinError(L"cannot create protected worker control pipe");
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) throw WinError(L"cannot create worker control pipe event");
  OVERLAPPED operation{};
  operation.hEvent = event.Get();
  bool connect_pending = false;
  if (!ConnectNamedPipe(server.Get(), &operation)) {
    const DWORD error = GetLastError();
    if (error == ERROR_IO_PENDING) {
      connect_pending = true;
    } else if (error != ERROR_PIPE_CONNECTED) {
      throw WinError(L"cannot begin child worker control pipe connection", error);
    }
  }
  Handle client(CreateFileW(pipe_name.c_str(), GENERIC_READ, 0, &child_security, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!client) {
    if (connect_pending) {
      CancelIoEx(server.Get(), &operation);
      DWORD ignored = 0;
      GetOverlappedResult(server.Get(), &operation, &ignored, TRUE);
    }
    throw WinError(L"cannot connect child worker control pipe");
  }
  if (connect_pending) {
    if (WaitForSingleObject(event.Get(), 2000) != WAIT_OBJECT_0) {
      CancelIoEx(server.Get(), &operation);
      DWORD ignored = 0;
      GetOverlappedResult(server.Get(), &operation, &ignored, TRUE);
      throw WinError(L"cannot complete child worker control pipe connection", ERROR_TIMEOUT);
    }
    DWORD ignored = 0;
    if (!GetOverlappedResult(server.Get(), &operation, &ignored, FALSE)) {
      throw WinError(L"cannot complete child worker control pipe connection");
    }
  }
  child_read->value = client.value;
  client.value = nullptr;
  parent_write->value = server.value;
  server.value = nullptr;
}

Child LaunchWorker(const InstallPaths& paths) {
  Child child;
  CreatePipePair(&child.ready_read, &child.ready_write, false, true);
  CreateOverlappedControlPipe(&child.control_read, &child.control_write);
  SECURITY_ATTRIBUTES null_security{sizeof(null_security), nullptr, TRUE};
  Handle null_device(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &null_security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!null_device) throw WinError(L"cannot open sanitized worker stderr sink");
  std::vector<HANDLE> inherited{child.control_read.Get(), child.ready_write.Get(), null_device.Get()};
  auto environment = BuildSanitizedEnvironment(paths);
  SIZE_T attribute_bytes = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_bytes);
  std::vector<BYTE> attribute_storage(attribute_bytes);
  auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_bytes)) throw WinError(L"cannot initialize process handle allowlist");
  struct AttributeGuard { PPROC_THREAD_ATTRIBUTE_LIST value; ~AttributeGuard() { DeleteProcThreadAttributeList(value); } } guard{attributes};
  if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), inherited.size() * sizeof(HANDLE), nullptr, nullptr)) {
    throw WinError(L"cannot constrain inherited service handles");
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = child.control_read.Get();
  startup.StartupInfo.hStdOutput = child.ready_write.Get();
  startup.StartupInfo.hStdError = null_device.Get();
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION process{};
  const std::wstring script = paths.worker;
  std::vector<std::wstring> arguments{paths.node, script};
  std::wstring command = sumatrafuzz::supervisor::BuildWindowsCommandLine(arguments);
  if (command.size() > 32766) throw std::runtime_error("fixed worker command line exceeds Windows bounds");
  DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
  if (!CreateProcessW(paths.node.c_str(), command.data(), nullptr, nullptr, TRUE, flags, environment.data(), paths.root.c_str(), &startup.StartupInfo, &process)) {
    throw WinError(L"cannot launch fixed TypeScript worker");
  }
  child.process.Reset(process.hProcess);
  Handle thread(process.hThread);
  child.pid = process.dwProcessId;
  child.job.Reset(CreateJobObjectW(nullptr, nullptr));
  if (!child.job) {
    TerminateProcess(child.process.Get(), kStartupFailureCode);
    WaitForSingleObject(child.process.Get(), 5000);
    throw WinError(L"cannot create outer worker job");
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(child.job.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    TerminateProcess(child.process.Get(), kStartupFailureCode);
    WaitForSingleObject(child.process.Get(), 5000);
    throw WinError(L"cannot set outer job containment");
  }
  if (!AssignProcessToJobObject(child.job.Get(), child.process.Get())) {
    TerminateProcess(child.process.Get(), kStartupFailureCode);
    WaitForSingleObject(child.process.Get(), 5000);
    throw WinError(L"cannot assign worker to outer job");
  }
  child.ready_write.Reset();
  child.control_read.Reset();
  null_device.Reset();
  if (ResumeThread(thread.Get()) == static_cast<DWORD>(-1)) {
    TerminateJobObject(child.job.Get(), kStartupFailureCode);
    WaitForSingleObject(child.process.Get(), 5000);
    throw WinError(L"cannot resume worker process");
  }
  return child;
}

DWORD ChildExitCode(HANDLE process) {
  DWORD code = ERROR_PROCESS_ABORTED;
  if (process) GetExitCodeProcess(process, &code);
  return code;
}

bool StopChild(Child& child, bool* graceful, DWORD stop_timeout_ms = kStopTimeoutMs) {
  *graceful = false;
  if (!child.process) return true;
  if (WaitForSingleObject(child.process.Get(), 0) == WAIT_OBJECT_0) return false;
  const ULONGLONG deadline = GetTickCount64() + stop_timeout_ms;
  if (stop_timeout_ms == 0) {
    TerminateJobObject(child.job.Get(), kForcedStopCode);
    WaitForSingleObject(child.process.Get(), 5000);
    return false;
  }
  ULONGLONG now = GetTickCount64();
  if (now >= deadline ||
      !WriteFrame(child.control_write.Get(), ControlFrame::Stop, static_cast<DWORD>(deadline - now))) {
    TerminateJobObject(child.job.Get(), kForcedStopCode);
    WaitForSingleObject(child.process.Get(), 5000);
    return false;
  }
  for (;;) {
    now = GetTickCount64();
    if (now >= deadline) {
      TerminateJobObject(child.job.Get(), kForcedStopCode);
      WaitForSingleObject(child.process.Get(), 5000);
      return false;
    }
    ControlFrame response{};
    const FrameRead result = ReadFrameUntil(child.ready_read.Get(), child.process.Get(),
                                             static_cast<DWORD>(deadline - now), &response, false);
    if (result != FrameRead::Complete ||
        (response != ControlFrame::Stopped && response != ControlFrame::TrustOperationResult)) {
      TerminateJobObject(child.job.Get(), kForcedStopCode);
      WaitForSingleObject(child.process.Get(), 5000);
      return false;
    }
    if (response == ControlFrame::Stopped) break;
  }
  now = GetTickCount64();
  const DWORD remaining = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
  const DWORD wait = WaitForSingleObject(child.process.Get(), std::min(remaining, kExitAfterStopTimeoutMs));
  if (wait != WAIT_OBJECT_0 || ChildExitCode(child.process.Get()) != 0) {
    TerminateJobObject(child.job.Get(), kForcedStopCode);
    WaitForSingleObject(child.process.Get(), 5000);
    return false;
  }
  *graceful = true;
  return true;
}

bool WaitOverlapped(HANDLE pipe, OVERLAPPED* operation, DWORD timeout_ms, bool observe_stop = true) {
  HANDLE waits[] = {g_stop_event, operation->hEvent};
  const DWORD wait = observe_stop && g_stop_event
    ? WaitForMultipleObjects(2, waits, FALSE, timeout_ms)
    : WaitForSingleObject(operation->hEvent, timeout_ms) == WAIT_OBJECT_0 ? WAIT_OBJECT_0 + 1 : WAIT_TIMEOUT;
  if (wait != WAIT_OBJECT_0 + 1) {
    CancelIoEx(pipe, operation);
    DWORD ignored = 0;
    GetOverlappedResult(pipe, operation, &ignored, TRUE);
    return false;
  }
  DWORD transferred = 0;
  return GetOverlappedResult(pipe, operation, &transferred, FALSE) != FALSE;
}

bool WritePipeBounded(HANDLE pipe, const BYTE* source, DWORD size, DWORD timeout_ms, bool observe_stop) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  DWORD offset = 0;
  while (offset < size) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) return false;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.Get();
    DWORD written = 0;
    const BOOL complete = WriteFile(pipe, source + offset, size - offset, &written, &operation);
    if (!complete && GetLastError() != ERROR_IO_PENDING) return false;
    if (!complete) {
      if (!WaitOverlapped(pipe, &operation, static_cast<DWORD>(deadline - now), observe_stop) ||
          !GetOverlappedResult(pipe, &operation, &written, FALSE)) {
        return false;
      }
    }
    if (written == 0 || written > size - offset) return false;
    offset += written;
  }
  return true;
}

bool ReadPipeExact(HANDLE pipe, BYTE* destination, DWORD size, DWORD timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  DWORD offset = 0;
  while (offset < size) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) return false;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.Get();
    DWORD read = 0;
    const BOOL complete = ReadFile(pipe, destination + offset, size - offset, &read, &operation);
    if (!complete && GetLastError() != ERROR_IO_PENDING) return false;
    if (!complete) {
      if (!WaitOverlapped(pipe, &operation, static_cast<DWORD>(deadline - now))) return false;
      if (!GetOverlappedResult(pipe, &operation, &read, FALSE)) return false;
    }
    if (read == 0 || read > size - offset) return false;
    offset += read;
  }
  return true;
}

bool WritePipeExact(HANDLE pipe, const BYTE* source, DWORD size, DWORD timeout_ms, bool allow_during_stop = false) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  DWORD offset = 0;
  while (offset < size) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) return false;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.Get();
    DWORD written = 0;
    const BOOL complete = WriteFile(pipe, source + offset, size - offset, &written, &operation);
    if (!complete && GetLastError() != ERROR_IO_PENDING) return false;
    if (!complete) {
      if (!WaitOverlapped(pipe, &operation, static_cast<DWORD>(deadline - now), !allow_during_stop)) return false;
      if (!GetOverlappedResult(pipe, &operation, &written, FALSE)) return false;
    }
    if (written == 0 || written > size - offset) return false;
    offset += written;
  }
  return true;
}

bool ConnectLocalAdminPipe(HANDLE pipe) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  OVERLAPPED operation{};
  operation.hEvent = event.Get();
  if (ConnectNamedPipe(pipe, &operation)) return true;
  const DWORD error = GetLastError();
  if (error == ERROR_PIPE_CONNECTED) return true;
  if (error != ERROR_IO_PENDING) return false;
  return WaitOverlapped(pipe, &operation, INFINITE);
}

enum class PipeClientAuthorization { Denied, Authorized, Fatal };

PipeClientAuthorization AuthorizeElevatedLocalAdministrator(HANDLE pipe) {
  if (!ImpersonateNamedPipeClient(pipe)) return PipeClientAuthorization::Denied;
  bool allowed = false;
  HANDLE token = nullptr;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    Handle token_handle(token);
    std::array<BYTE, SECURITY_MAX_SID_SIZE> admin_bytes{};
    DWORD admin_size = static_cast<DWORD>(admin_bytes.size());
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    BOOL member = FALSE;
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_bytes.data(), &admin_size) &&
        GetTokenInformation(token_handle.Get(), TokenElevation, &elevation, sizeof(elevation), &returned) &&
        CheckTokenMembership(token_handle.Get(), admin_bytes.data(), &member)) {
      allowed = member && elevation.TokenIsElevated != 0;
    }
  }
  if (!RevertToSelf()) return PipeClientAuthorization::Fatal;
  return allowed ? PipeClientAuthorization::Authorized : PipeClientAuthorization::Denied;
}

bool ReadTrustOperationResultUntil(HANDLE pipe, HANDLE process, DWORD timeout_ms, bool* succeeded) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  std::array<std::uint8_t, 10> bytes{};
  size_t used = 0;
  while (GetTickCount64() < deadline) {
    if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return false;
    DWORD available = 0;
    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
    if (available > 0) {
      const DWORD wanted = static_cast<DWORD>(std::min<size_t>(available, bytes.size() - used));
      DWORD read = 0;
      if (!ReadFile(pipe, bytes.data() + used, wanted, &read, nullptr) || read == 0) return false;
      used += read;
      if (used >= 4) {
        const std::uint32_t length = static_cast<std::uint32_t>(bytes[0]) |
          (static_cast<std::uint32_t>(bytes[1]) << 8) | (static_cast<std::uint32_t>(bytes[2]) << 16) |
          (static_cast<std::uint32_t>(bytes[3]) << 24);
        if (length != 2 || used > length + 4) return false;
        if (used == length + 4) {
          const std::vector<std::uint8_t> response(bytes.begin(), bytes.begin() + used);
          return sumatrafuzz::service_host::DecodeTrustOperationResponse(response, succeeded);
        }
      }
      continue;
    }
    Sleep(kPollMs);
  }
  return false;
}

void ServeLocalTrustPipe(Child& child) {
  constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\SumatraFuzzWorker-trust";
  const std::vector<BYTE> service_sid = ResolveServiceSid();
  LPWSTR service_sid_text = nullptr;
  if (!ConvertSidToStringSidW(const_cast<BYTE*>(service_sid.data()), &service_sid_text)) return;
  std::wstring sddl = L"D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;" + std::wstring(service_sid_text) + L")";
  LocalFree(service_sid_text);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return;
  std::unique_ptr<void, decltype(&LocalFree)> descriptor_owner(descriptor, LocalFree);
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  Handle pipe(CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                               1, 4096, 4096, 0, &attributes));
  if (!pipe) return;
  while (!g_stop_event || WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
    if (!ConnectLocalAdminPipe(pipe.Get())) {
      if (g_stop_event && WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) break;
      return;
    }
    bool succeeded = false;
    std::array<BYTE, 4> header{};
    if (ReadPipeExact(pipe.Get(), header.data(), static_cast<DWORD>(header.size()), kTrustPipeReadTimeoutMs)) {
      const std::uint32_t length = static_cast<std::uint32_t>(header[0]) |
        (static_cast<std::uint32_t>(header[1]) << 8) | (static_cast<std::uint32_t>(header[2]) << 16) |
        (static_cast<std::uint32_t>(header[3]) << 24);
      if (length >= 2 && length <= sumatrafuzz::service_host::kMaxTrustOperationBytes) {
        const auto client_authorization = AuthorizeElevatedLocalAdministrator(pipe.Get());
        if (client_authorization == PipeClientAuthorization::Fatal) {
          if (g_stop_event) SetEvent(g_stop_event);
          return;
        }
        if (client_authorization == PipeClientAuthorization::Authorized) {
          std::vector<std::uint8_t> command(length);
          VectorScrubber command_scrubber{command};
          if (ReadPipeExact(pipe.Get(), command.data(), length, kTrustPipeReadTimeoutMs) &&
              (command[0] == 0x10 || command[0] == 0x12)) {
            auto frame = sumatrafuzz::service_host::EncodeTrustOperationRequest(command);
            VectorScrubber frame_scrubber{frame};
            if (frame.empty() ||
                !WritePipeBounded(child.control_write.Get(), frame.data(), static_cast<DWORD>(frame.size()),
                                  kTrustOperationTimeoutMs, true) ||
                !ReadTrustOperationResultUntil(child.ready_read.Get(), child.process.Get(), kTrustOperationTimeoutMs, &succeeded)) {
              // A partial command or missing/malformed receipt desynchronizes stdio. Stop this
              // worker instead of risking a later administrator request matching a stale receipt.
              if (g_stop_event) SetEvent(g_stop_event);
              return;
            }
          }
        }
      }
    }
    const BYTE status = succeeded ? 0 : 1;
    const std::array<BYTE, 5> response{1, 0, 0, 0, status};
    if (!WritePipeExact(pipe.Get(), response.data(), static_cast<DWORD>(response.size()), 2000, true)) {
      return;
    }
    BYTE acknowledgement = 0;
    if (!ReadPipeExact(pipe.Get(), &acknowledgement, sizeof(acknowledgement), kTrustPipeReadTimeoutMs) ||
        acknowledgement != kTrustPipeReceiptAck) {
      if (!DisconnectNamedPipe(pipe.Get())) return;
      continue;
    }
    if (!DisconnectNamedPipe(pipe.Get())) return;
  }
}

void ServiceMain(DWORD, wchar_t**) {
  g_status_handle = RegisterServiceCtrlHandlerW(kServiceName, ServiceControlHandler);
  if (!g_status_handle) return;
  if (!g_stop_event) g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stop_event) { SetStatus(SERVICE_STOPPED, GetLastError(), kStartupFailureCode); return; }
  SetStatus(SERVICE_START_PENDING);
  DWORD service_exit = 0;
  DWORD win32_exit = NO_ERROR;
  Child child;
  std::thread trust_pipe_thread;
  try {
    RequireServiceIdentity();
    InstallPaths paths = ResolveAndVerifyInstall();
    if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) {
      // SCM cancelled startup before a worker process existed.
    } else {
      child = LaunchWorker(paths);
      ControlFrame frame{};
      const FrameRead ready = ReadFrameUntil(child.ready_read.Get(), child.process.Get(), kReadyTimeoutMs, &frame);
      if (ready != FrameRead::Complete || frame != ControlFrame::Ready) {
        service_exit = kStartupFailureCode;
        win32_exit = ERROR_SERVICE_SPECIFIC_ERROR;
        TerminateJobObject(child.job.Get(), kStartupFailureCode);
        WaitForSingleObject(child.process.Get(), 5000);
      } else {
        if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) {
          SetStatus(SERVICE_STOP_PENDING);
          bool graceful = false;
          if (!StopChild(child, &graceful) || !graceful) {
            service_exit = kForcedStopCode;
            win32_exit = ERROR_SERVICE_SPECIFIC_ERROR;
          }
        } else {
          trust_pipe_thread = std::thread([&child] {
            try { ServeLocalTrustPipe(child); } catch (...) {}
            if (g_stop_event && WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) SetEvent(g_stop_event);
          });
          SetStatus(SERVICE_RUNNING);
          HANDLE waits[] = {g_stop_event, child.process.Get()};
          const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
          const ULONGLONG stop_deadline = GetTickCount64() + kStopTimeoutMs;
          if (g_stop_event) SetEvent(g_stop_event);
          if (trust_pipe_thread.joinable()) {
            CancelSynchronousIo(trust_pipe_thread.native_handle());
            trust_pipe_thread.join();
          }
          if (wait == WAIT_OBJECT_0) {
            SetStatus(SERVICE_STOP_PENDING);
            bool graceful = false;
            const ULONGLONG now = GetTickCount64();
            const DWORD remaining = now < stop_deadline ? static_cast<DWORD>(stop_deadline - now) : 0;
            if (!StopChild(child, &graceful, remaining) || !graceful) {
              service_exit = kForcedStopCode;
              win32_exit = ERROR_SERVICE_SPECIFIC_ERROR;
            }
          } else {
            // An unrequested child exit is never treated as an orderly service stop.
            service_exit = ChildExitCode(child.process.Get());
            if (service_exit == NO_ERROR) service_exit = kStartupFailureCode;
            win32_exit = ERROR_SERVICE_SPECIFIC_ERROR;
          }
        }
      }
    }
  } catch (...) {
    service_exit = kStartupFailureCode;
    win32_exit = ERROR_SERVICE_SPECIFIC_ERROR;
    if (g_stop_event) SetEvent(g_stop_event);
    if (trust_pipe_thread.joinable()) {
      CancelSynchronousIo(trust_pipe_thread.native_handle());
      trust_pipe_thread.join();
    }
    if (child.job) TerminateJobObject(child.job.Get(), kStartupFailureCode);
    if (child.process) WaitForSingleObject(child.process.Get(), 5000);
  }
  // If the SCM requests stop during startup, honor it without ever reporting a
  // successful teardown receipt for a worker that did not complete STOPPED.
  if (g_stop_event && WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0 && child.process &&
      WaitForSingleObject(child.process.Get(), 0) != WAIT_OBJECT_0 && service_exit == 0) {
    bool graceful = false;
    if (!StopChild(child, &graceful) || !graceful) { service_exit = kForcedStopCode; win32_exit = ERROR_SERVICE_SPECIFIC_ERROR; }
  }
  if (child.job) child.job.Reset(); // KILL_ON_JOB_CLOSE is the outer final boundary.
  SetStatus(SERVICE_STOPPED, win32_exit, service_exit);
  CloseHandle(g_stop_event);
  g_stop_event = nullptr;
}

}  // namespace

namespace sumatrafuzz::service_host {

int RunWindowsService() {
  g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stop_event) return static_cast<int>(GetLastError());
  SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), ServiceMain}, {nullptr, nullptr}};
  if (!StartServiceCtrlDispatcherW(table)) {
    const DWORD error = GetLastError();
    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    return static_cast<int>(error);
  }
  return 0;
}

}  // namespace sumatrafuzz::service_host

#if defined(SUMATRAFUZZ_SERVICE_HOST_STANDALONE)
int wmain() { return sumatrafuzz::service_host::RunWindowsService(); }
#endif

#else

namespace sumatrafuzz::service_host {
int RunWindowsService() { return 1; }
}  // namespace sumatrafuzz::service_host

#endif

namespace sumatrafuzz::service_host {

std::vector<std::uint8_t> EncodeControlFrame(ControlFrame frame) {
  const char* token = nullptr;
  switch (frame) {
    case ControlFrame::Ready: token = "READY"; break;
    case ControlFrame::Stop: token = "STOP"; break;
    case ControlFrame::Stopped: token = "STOPPED"; break;
    default: return {};
  }
  std::size_t size = 0;
  while (token[size] != '\0') ++size;
  if (size == 0 || size > kMaxControlFrameBytes) return {};
  std::vector<std::uint8_t> bytes(4 + size);
  const auto length = static_cast<std::uint32_t>(size);
  bytes[0] = static_cast<std::uint8_t>(length);
  bytes[1] = static_cast<std::uint8_t>(length >> 8);
  bytes[2] = static_cast<std::uint8_t>(length >> 16);
  bytes[3] = static_cast<std::uint8_t>(length >> 24);
  for (std::size_t i = 0; i < size; ++i) bytes[4 + i] = static_cast<std::uint8_t>(token[i]);
  return bytes;
}

bool DecodeControlFrame(const std::vector<std::uint8_t>& bytes, ControlFrame* frame) {
  if (!frame || bytes.size() < 4) return false;
  const std::uint32_t length = static_cast<std::uint32_t>(bytes[0]) |
    (static_cast<std::uint32_t>(bytes[1]) << 8) | (static_cast<std::uint32_t>(bytes[2]) << 16) |
    (static_cast<std::uint32_t>(bytes[3]) << 24);
  if (length == 0 || length > kMaxControlFrameBytes || bytes.size() != 4 + length) return false;
  if (length == 2 && bytes[4] == 0x11 && bytes[5] <= 1) {
    *frame = ControlFrame::TrustOperationResult;
    return true;
  }
  const std::string token(bytes.begin() + 4, bytes.end());
  if (token == "READY") *frame = ControlFrame::Ready;
  else if (token == "STOP") *frame = ControlFrame::Stop;
  else if (token == "STOPPED") *frame = ControlFrame::Stopped;
  else return false;
  return true;
}

std::vector<std::uint8_t> EncodeTrustOperationRequest(const std::vector<std::uint8_t>& bundle) {
  if (bundle.size() < 2 || bundle.size() > kMaxTrustOperationBytes ||
      (bundle[0] != 0x10 && bundle[0] != 0x12)) return {};
  const std::uint32_t length = static_cast<std::uint32_t>(bundle.size());
  std::vector<std::uint8_t> bytes(4 + length);
  bytes[0] = static_cast<std::uint8_t>(length);
  bytes[1] = static_cast<std::uint8_t>(length >> 8);
  bytes[2] = static_cast<std::uint8_t>(length >> 16);
  bytes[3] = static_cast<std::uint8_t>(length >> 24);
  std::copy(bundle.begin(), bundle.end(), bytes.begin() + 4);
  return bytes;
}

bool DecodeTrustOperationResponse(const std::vector<std::uint8_t>& bytes, bool* succeeded) {
  if (!succeeded || bytes.size() != 6 || bytes[0] != 2 || bytes[1] != 0 ||
      bytes[2] != 0 || bytes[3] != 0 || bytes[4] != 0x11 || bytes[5] > 1) return false;
  *succeeded = bytes[5] == 0;
  return true;
}

bool IsAllowedTransition(ServiceState from, ServiceState to) {
  if (from == ServiceState::Stopped) return to == ServiceState::StartPending;
  if (from == ServiceState::StartPending) return to == ServiceState::Running || to == ServiceState::StopPending || to == ServiceState::Stopped;
  if (from == ServiceState::Running) return to == ServiceState::StopPending || to == ServiceState::Stopped;
  if (from == ServiceState::StopPending) return to == ServiceState::Stopped;
  return false;
}

}  // namespace sumatrafuzz::service_host
