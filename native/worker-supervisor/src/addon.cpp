#include <napi.h>

#include "command_line.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cwctype>
#include <iterator>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <stdexcept>
#include <cwctype>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <objbase.h>
#endif

namespace {

struct Job {
#ifdef _WIN32
  HANDLE job = nullptr;
  HANDLE process = nullptr;
  DWORD process_id = 0;
  ULONGLONG previous_cpu_100ns = 0;
  ULONGLONG previous_sample_ms = 0;
  ~Job() {
    if (job) CloseHandle(job);  // KILL_ON_JOB_CLOSE is the final containment boundary.
    if (process) CloseHandle(process);
  }
#endif
};

std::map<std::string, std::unique_ptr<Job>> g_jobs;

Napi::Error NativeError(Napi::Env env, const char* message) {
  return Napi::Error::New(env, message);
}

#ifdef _WIN32

std::wstring Wide(const Napi::Value& value, const char* field) {
  if (!value.IsString()) throw Napi::TypeError::New(value.Env(), std::string(field) + " must be a string");
  const std::u16string utf16 = value.As<Napi::String>().Utf16Value();
  std::wstring result(utf16.begin(), utf16.end());
  if (result.find(L'\0') != std::wstring::npos) throw std::runtime_error(std::string(field) + " contains a NUL character");
  return result;
}

std::string IdString() {
  GUID guid{};
  if (CoCreateGuid(&guid) != S_OK) throw std::runtime_error("CoCreateGuid failed");
  wchar_t text[40]{};
  if (StringFromGUID2(guid, text, 40) == 0) throw std::runtime_error("StringFromGUID2 failed");
  std::wstring value(text);
  value.erase(std::remove(value.begin(), value.end(), L'{'), value.end());
  value.erase(std::remove(value.begin(), value.end(), L'}'), value.end());
  return std::string(value.begin(), value.end());
}

std::wstring FinalPath(HANDLE handle) {
  std::wstring buffer(32768, L'\0');
  const DWORD count = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (count == 0 || count >= buffer.size()) throw std::runtime_error("cannot canonicalize proof path");
  buffer.resize(count);
  return buffer;
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), towlower);
  return value;
}

std::wstring FullLocalPath(const std::wstring& value) {
  std::wstring buffer(32768, L'\0');
  const DWORD count = GetFullPathNameW(value.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  if (count == 0 || count >= buffer.size()) throw std::runtime_error("could not normalize local launch path");
  buffer.resize(count);
  while (buffer.size() > 3 && (buffer.back() == L'\\' || buffer.back() == L'/')) buffer.pop_back();
  return Lower(buffer);
}

bool IsOrdinaryLocalPath(const std::wstring& value) {
  return value.size() >= 3 && std::iswalpha(value[0]) && value[1] == L':' &&
         (value[2] == L'\\' || value[2] == L'/') && value.rfind(L"\\\\", 0) != 0;
}

std::wstring EnvironmentValue(const wchar_t* name) {
  const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
  if (size == 0 || size > 32767) throw std::runtime_error("required Windows environment variable is unavailable");
  std::wstring value(size, L'\0');
  const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
  if (written == 0 || written >= size) throw std::runtime_error("could not read required Windows environment variable");
  value.resize(written);
  return value;
}

std::vector<wchar_t> BuildWorkerEnvironment(const std::wstring& working_dir, const std::wstring& tool_dir) {
  const std::wstring system_root = EnvironmentValue(L"SystemRoot");
  std::map<std::wstring, std::wstring> values;
  values.emplace(L"PATH", tool_dir + L";" + system_root + L"\\System32");
  values.emplace(L"SystemRoot", system_root);
  values.emplace(L"TEMP", working_dir);
  values.emplace(L"TMP", working_dir);
  values.emplace(L"WINDIR", system_root);
  std::vector<wchar_t> block;
  for (const auto& [name, value] : values) {
    const std::wstring entry = name + L"=" + value;
    block.insert(block.end(), entry.begin(), entry.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

struct RestrictedToken {
  HANDLE handle = nullptr;
  PSID sid = nullptr;
  RestrictedToken() = default;
  RestrictedToken(const RestrictedToken&) = delete;
  RestrictedToken& operator=(const RestrictedToken&) = delete;
  RestrictedToken(RestrictedToken&& other) noexcept : handle(other.handle), sid(other.sid) {
    other.handle = nullptr;
    other.sid = nullptr;
  }
  ~RestrictedToken() {
    if (handle) CloseHandle(handle);
    if (sid) LocalFree(sid);
  }
};

PSID CreateRunRestrictedSid() {
  SID_IDENTIFIER_AUTHORITY authority{{0x53, 0x46, 0x57, 0x52, 0x4b, 0x31}};  // SFW-RK1 private SID authority.
  PSID sid = LocalAlloc(LMEM_FIXED, SECURITY_MAX_SID_SIZE);
  if (!sid) throw std::runtime_error("could not allocate child restricting SID");
  GUID run{};
  if (CoCreateGuid(&run) != S_OK || !InitializeSid(sid, &authority, 3)) {
    LocalFree(sid);
    throw std::runtime_error("could not initialize child restricting SID");
  }
  *GetSidSubAuthority(sid, 0) = run.Data1;
  *GetSidSubAuthority(sid, 1) = run.Data2 | (static_cast<DWORD>(run.Data3) << 16);
  *GetSidSubAuthority(sid, 2) = static_cast<DWORD>(run.Data4[0]) << 24 |
                                  static_cast<DWORD>(run.Data4[1]) << 16 |
                                  static_cast<DWORD>(run.Data4[2]) << 8 |
                                  static_cast<DWORD>(run.Data4[3]);
  return sid;
}

void AddRestrictedSidAccess(const std::wstring& directory_path, PSID sid, DWORD permissions,
                            bool inherit) {
  if (!IsOrdinaryLocalPath(directory_path)) throw std::runtime_error("restricted access path must be an ordinary local Windows path");
  HANDLE directory = CreateFileW(directory_path.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (directory == INVALID_HANDLE_VALUE) throw std::runtime_error("could not open restricted access directory securely");
  BY_HANDLE_FILE_INFORMATION info{};
  const bool safe_directory = GetFileInformationByHandle(directory, &info) &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
      !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
  if (!safe_directory) {
    CloseHandle(directory);
    throw std::runtime_error("restricted access path is redirected or is not a directory");
  }
  PACL existing_dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD read_acl = GetSecurityInfo(directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                         nullptr, nullptr, &existing_dacl, nullptr, &descriptor);
  if (read_acl != ERROR_SUCCESS || !existing_dacl) {
    if (descriptor) LocalFree(descriptor);
    CloseHandle(directory);
    throw std::runtime_error("could not read run evidence permissions");
  }
  EXPLICIT_ACCESSW grant{};
  grant.grfAccessPermissions = permissions;
  grant.grfAccessMode = GRANT_ACCESS;
  grant.grfInheritance = inherit ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
  BuildTrusteeWithSidW(&grant.Trustee, sid);
  PACL updated_dacl = nullptr;
  const DWORD acl_result = SetEntriesInAclW(1, &grant, existing_dacl, &updated_dacl);
  if (acl_result != ERROR_SUCCESS) {
    LocalFree(descriptor);
    CloseHandle(directory);
    throw std::runtime_error("could not prepare run evidence permissions");
  }
  const DWORD set_acl = SetSecurityInfo(directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, updated_dacl, nullptr);
  LocalFree(updated_dacl);
  LocalFree(descriptor);
  CloseHandle(directory);
  if (set_acl != ERROR_SUCCESS) throw std::runtime_error("could not protect restricted directory permissions");
}

constexpr DWORD kRestrictedEvidenceWrite = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
                                          FILE_READ_EA | READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA |
                                          FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                                          FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                                          FILE_WRITE_EA | FILE_DELETE_CHILD;

void PrepareEvidenceDirectory(const std::wstring& evidence_dir) {
  if (!IsOrdinaryLocalPath(evidence_dir)) throw std::runtime_error("evidence path must be an ordinary local Windows path");
  if (!CreateDirectoryW(evidence_dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
    throw std::runtime_error("could not create run evidence directory");
  }
  HANDLE directory = CreateFileW(evidence_dir.c_str(), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (directory == INVALID_HANDLE_VALUE) throw std::runtime_error("could not open run evidence directory securely");
  BY_HANDLE_FILE_INFORMATION info{};
  const bool safe_directory = GetFileInformationByHandle(directory, &info) &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
      !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
  CloseHandle(directory);
  if (!safe_directory) throw std::runtime_error("run evidence path is redirected or is not a directory");
  WIN32_FIND_DATAW entry{};
  const std::wstring pattern = evidence_dir + L"\\*";
  HANDLE search = FindFirstFileW(pattern.c_str(), &entry);
  bool empty = search != INVALID_HANDLE_VALUE;
  if (search != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(entry.cFileName, L".") != 0 && wcscmp(entry.cFileName, L"..") != 0) {
        empty = false;
        break;
      }
    } while (FindNextFileW(search, &entry));
    FindClose(search);
  }
  if (!empty) throw std::runtime_error("run evidence directory must be empty before launch");
}

void SetPrivateRestrictedDefaultDacl(HANDLE source_token, HANDLE restricted_token, PSID run_sid) {
  DWORD user_bytes = 0;
  GetTokenInformation(source_token, TokenUser, nullptr, 0, &user_bytes);
  if (user_bytes < sizeof(TOKEN_USER)) throw std::runtime_error("could not inspect worker token owner");
  std::vector<BYTE> user_storage(user_bytes);
  auto* user = reinterpret_cast<TOKEN_USER*>(user_storage.data());
  DWORD returned = 0;
  if (!GetTokenInformation(source_token, TokenUser, user, user_bytes, &returned)) {
    throw std::runtime_error("could not inspect worker token owner");
  }
  EXPLICIT_ACCESSW grants[2]{};
  for (auto& grant : grants) {
    grant.grfAccessPermissions = GENERIC_ALL;
    grant.grfAccessMode = GRANT_ACCESS;
    grant.grfInheritance = NO_INHERITANCE;
  }
  BuildTrusteeWithSidW(&grants[0].Trustee, user->User.Sid);
  BuildTrusteeWithSidW(&grants[1].Trustee, run_sid);
  PACL private_dacl = nullptr;
  const DWORD acl_result = SetEntriesInAclW(2, grants, nullptr, &private_dacl);
  if (acl_result != ERROR_SUCCESS) throw std::runtime_error("could not prepare restricted child object permissions");
  TOKEN_DEFAULT_DACL token_default{private_dacl};
  const BOOL set = SetTokenInformation(restricted_token, TokenDefaultDacl, &token_default,
                                       sizeof(token_default));
  LocalFree(private_dacl);
  if (!set) throw std::runtime_error("could not restrict child-created kernel objects");
}

RestrictedToken CreateEvidenceRestrictedToken(const std::wstring& evidence_dir) {
  RestrictedToken restricted;
  restricted.sid = CreateRunRestrictedSid();
  PrepareEvidenceDirectory(evidence_dir);
  AddRestrictedSidAccess(evidence_dir, restricted.sid, kRestrictedEvidenceWrite, true);
  HANDLE current = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                       &current)) {
    throw std::runtime_error("could not open worker token for restricted launch");
  }
  std::array<BYTE, SECURITY_MAX_SID_SIZE> everyone_buffer{};
  DWORD everyone_size = static_cast<DWORD>(everyone_buffer.size());
  if (!CreateWellKnownSid(WinWorldSid, nullptr, everyone_buffer.data(), &everyone_size)) {
    CloseHandle(current);
    throw std::runtime_error("could not initialize public read restricting SID");
  }
  PSID restricted_code_buffer = nullptr;
  DWORD restricted_code_size = 0;
  CreateWellKnownSid(WinRestrictedCodeSid, nullptr, nullptr, &restricted_code_size);
  if (restricted_code_size == 0) {
    CloseHandle(current);
    throw std::runtime_error("could not size restricted-code SID");
  }
  std::vector<BYTE> restricted_code_storage(restricted_code_size);
  restricted_code_buffer = restricted_code_storage.data();
  if (!CreateWellKnownSid(WinRestrictedCodeSid, nullptr, restricted_code_buffer, &restricted_code_size)) {
    CloseHandle(current);
    throw std::runtime_error("could not initialize restricted-code SID");
  }
  const SID_AND_ATTRIBUTES restricting_sids[] = {
      {restricted.sid, 0},
      {restricted_code_buffer, 0},
      {everyone_buffer.data(), 0},
  };
  const BOOL created = CreateRestrictedToken(current, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr,
                                              3, restricting_sids, &restricted.handle);
  if (created) {
    try {
      SetPrivateRestrictedDefaultDacl(current, restricted.handle, restricted.sid);
    } catch (...) {
      CloseHandle(current);
      throw;
    }
  }
  CloseHandle(current);
  if (!created) throw std::runtime_error("could not create restricted worker token");
  return restricted;
}

struct OpenProof {
  HANDLE handle = INVALID_HANDLE_VALUE;
  ~OpenProof() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
  OpenProof() = default;
  OpenProof(const OpenProof&) = delete;
  OpenProof& operator=(const OpenProof&) = delete;
  OpenProof(OpenProof&& other) noexcept : handle(other.handle) { other.handle = INVALID_HANDLE_VALUE; }
};

bool HashMatches(HANDLE file, const std::wstring& expected) {
  if (expected.size() != 64) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0, result_size = 0;
  std::vector<UCHAR> object;
  std::array<UCHAR, 32> digest{};
  bool okay = false;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
  do {
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &result_size, 0) != 0) break;
    object.resize(object_size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) != 0) break;
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) break;
    std::array<UCHAR, 65536> bytes{};
    DWORD read = 0;
    bool failed = false;
    for (;;) {
      if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr)) {
        if (GetLastError() != ERROR_HANDLE_EOF) failed = true;
        break;
      }
      if (read == 0) break;
      if (BCryptHashData(hash, bytes.data(), read, 0) != 0) { failed = true; break; }
    }
    if (failed) break;
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) break;
    static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring actual;
    actual.reserve(64);
    for (UCHAR byte : digest) { actual.push_back(hex[byte >> 4]); actual.push_back(hex[byte & 0x0f]); }
    okay = Lower(actual) == Lower(expected);
  } while (false);
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return okay;
}

std::vector<OpenProof> VerifyProofs(Napi::Array proofs, const std::wstring& executable, const std::wstring& tool_dir) {
  if (proofs.Length() == 0 || proofs.Length() > 64) throw std::runtime_error("invalid file proof count");
  OpenProof executable_file;
  executable_file.handle = CreateFileW(executable.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (executable_file.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open requested executable");
  BY_HANDLE_FILE_INFORMATION executable_info{};
  if (!GetFileInformationByHandle(executable_file.handle, &executable_info) || (executable_info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
    throw std::runtime_error("requested executable is redirected or not a regular file");
  }
  const std::wstring canonical_executable = Lower(FinalPath(executable_file.handle));
  OpenProof tool_directory;
  tool_directory.handle = CreateFileW(tool_dir.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (tool_directory.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open verified tool directory");
  BY_HANDLE_FILE_INFORMATION tool_info{};
  if (!GetFileInformationByHandle(tool_directory.handle, &tool_info) || (tool_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(tool_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw std::runtime_error("tool directory is redirected or not a directory");
  const std::wstring canonical_tool_dir = Lower(FinalPath(tool_directory.handle));
  bool tool_directory_proven = false;
  bool executable_proven = false;
  std::vector<OpenProof> open;
  open.reserve(proofs.Length());
  for (uint32_t i = 0; i < proofs.Length(); ++i) {
    Napi::Value value = proofs.Get(i);
    if (!value.IsObject()) throw std::runtime_error("invalid file proof");
    Napi::Object proof = value.As<Napi::Object>();
    const std::wstring file_path = Wide(proof.Get("path"), "proof path");
    const std::wstring root_path = Wide(proof.Get("root"), "proof root");
    const std::wstring expected = Wide(proof.Get("sha256"), "proof hash");
    if (!IsOrdinaryLocalPath(file_path) || !IsOrdinaryLocalPath(root_path)) throw std::runtime_error("proof path is not an ordinary local Windows path");
    OpenProof root;
    root.handle = CreateFileW(root_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (root.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open trusted proof root");
    BY_HANDLE_FILE_INFORMATION root_info{};
    if (!GetFileInformationByHandle(root.handle, &root_info) || (root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw std::runtime_error("unsafe trusted proof root");
    const std::wstring canonical_root = Lower(FinalPath(root.handle));

    OpenProof file;
    file.handle = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open trusted proof file");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.handle, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) throw std::runtime_error("trusted proof is not a regular file");
    const std::wstring canonical_file = Lower(FinalPath(file.handle));
    std::wstring root_prefix = canonical_root;
    if (!root_prefix.empty() && root_prefix.back() != L'\\') root_prefix.push_back(L'\\');
    if (canonical_file.size() <= root_prefix.size() || canonical_file.compare(0, root_prefix.size(), root_prefix) != 0) throw std::runtime_error("trusted file escaped its root");
    if (!HashMatches(file.handle, expected)) throw std::runtime_error("trusted file hash changed before launch");
    if (canonical_file == canonical_executable) executable_proven = true;
    const size_t separator = canonical_file.find_last_of(L'\\');
    if (separator != std::wstring::npos && canonical_file.substr(0, separator) == canonical_tool_dir) tool_directory_proven = true;
    open.push_back(std::move(file));  // Deny write/delete sharing until CreateProcess has opened the image.
  }
  if (!executable_proven) throw std::runtime_error("requested executable has no matching verified file proof");
  if (!tool_directory_proven) throw std::runtime_error("DynamoRIO directory has no matching verified file proof");
  return open;
}

Napi::Value LaunchSuspended(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 1 || !info[0].IsObject()) throw std::runtime_error("launch specification required");
    Napi::Object spec = info[0].As<Napi::Object>();
    const std::wstring executable = Wide(spec.Get("executable"), "executable");
    const std::wstring working_dir = Wide(spec.Get("workingDir"), "workingDir");
    const std::wstring evidence_dir = Wide(spec.Get("evidenceDir"), "evidenceDir");
    if (!IsOrdinaryLocalPath(executable) || !IsOrdinaryLocalPath(working_dir)) throw std::runtime_error("launch paths must be ordinary local Windows paths");
    if (!IsOrdinaryLocalPath(evidence_dir)) throw std::runtime_error("evidence path must be an ordinary local Windows path");
    Napi::Array argv = spec.Get("argv").As<Napi::Array>();
    Napi::Array proofs = spec.Get("fileProofs").As<Napi::Array>();
    Napi::Object limits = spec.Get("limits").As<Napi::Object>();
    const double memory = limits.Get("max_memory_bytes").As<Napi::Number>().DoubleValue();
    const double cpu = limits.Get("max_cpu_percent").As<Napi::Number>().DoubleValue();
    if (!std::isfinite(memory) || !std::isfinite(cpu) || std::floor(memory) != memory || std::floor(cpu) != cpu ||
        memory < 16 * 1024 * 1024 || memory > 0x7fffffffffffffff || cpu < 1 || cpu > 100) throw std::runtime_error("resource limit outside native bounds");
    std::vector<std::wstring> arguments{executable};
    if (argv.Length() > 256) throw std::runtime_error("argument count exceeds native bound");
    for (uint32_t i = 0; i < argv.Length(); ++i) arguments.push_back(Wide(argv.Get(i), "argv entry"));
    std::wstring command = sumatrafuzz::supervisor::BuildWindowsCommandLine(arguments);
    if (command.size() > 32766) throw std::runtime_error("command line exceeds Windows limit");
    std::wstring tool_dir;
    std::wstring input_dir;
    std::wstring output_arg;
    for (size_t i = 0; i + 1 < arguments.size(); ++i) {
      if (arguments[i] == L"-D") { tool_dir = arguments[i + 1]; break; }
    }
    for (size_t i = 0; i + 1 < arguments.size(); ++i) {
      if (arguments[i] == L"-i") {
        if (!input_dir.empty()) throw std::runtime_error("duplicate WinAFL input directory argument");
        input_dir = arguments[i + 1];
      } else if (arguments[i] == L"-o") {
        if (!output_arg.empty()) throw std::runtime_error("duplicate WinAFL evidence directory argument");
        output_arg = arguments[i + 1];
      }
    }
    if (tool_dir.empty()) throw std::runtime_error("verified DynamoRIO tool directory is missing from argv");
    if (!IsOrdinaryLocalPath(tool_dir)) throw std::runtime_error("DynamoRIO tool directory is not an ordinary local Windows path");
    if (input_dir.empty() || !IsOrdinaryLocalPath(input_dir) || output_arg.empty() ||
        FullLocalPath(output_arg) != FullLocalPath(evidence_dir)) {
      throw std::runtime_error("WinAFL input and evidence paths are not bound to the verified launch");
    }
    const std::wstring full_evidence = FullLocalPath(evidence_dir);
    const size_t evidence_separator = full_evidence.find_last_of(L'\\');
    if (evidence_separator == std::wstring::npos ||
        full_evidence.substr(0, evidence_separator) != FullLocalPath(working_dir)) {
      throw std::runtime_error("evidence directory must be a direct child of the protected run root");
    }
    [[maybe_unused]] std::vector<OpenProof> opened_proofs = VerifyProofs(proofs, executable, tool_dir);
    RestrictedToken restricted = CreateEvidenceRestrictedToken(evidence_dir);
    std::vector<wchar_t> environment = BuildWorkerEnvironment(evidence_dir, tool_dir);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    HANDLE job_handle = CreateJobObjectW(nullptr, nullptr);
    if (!job_handle) throw std::runtime_error("CreateJobObjectW failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended{};
    extended.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY;
    extended.JobMemoryLimit = static_cast<SIZE_T>(memory);
    if (!SetInformationJobObject(job_handle, JobObjectExtendedLimitInformation, &extended, sizeof(extended))) { CloseHandle(job_handle); throw std::runtime_error("Job memory quota setup failed"); }
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu_limit{};
    cpu_limit.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu_limit.CpuRate = static_cast<DWORD>(cpu * 100.0);
    if (!SetInformationJobObject(job_handle, JobObjectCpuRateControlInformation, &cpu_limit, sizeof(cpu_limit))) { CloseHandle(job_handle); throw std::runtime_error("Job CPU quota setup failed"); }
    const DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    if (!CreateProcessAsUserW(restricted.handle, executable.c_str(), command.data(), nullptr, nullptr,
                              FALSE, flags, environment.data(), working_dir.c_str(), &startup, &process)) {
      CloseHandle(job_handle); throw std::runtime_error("CreateProcessAsUserW failed");
    }
    if (!AssignProcessToJobObject(job_handle, process.hProcess)) {
      TerminateProcess(process.hProcess, ERROR_ACCESS_DENIED); WaitForSingleObject(process.hProcess, 5000);
      CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job_handle);
      throw std::runtime_error("AssignProcessToJobObject failed; suspended child was terminated");
    }
    if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
      TerminateJobObject(job_handle, ERROR_OPERATION_ABORTED); WaitForSingleObject(process.hProcess, 5000);
      CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job_handle);
      throw std::runtime_error("ResumeThread failed; job was terminated");
    }
    CloseHandle(process.hThread);
    auto job = std::make_unique<Job>();
    job->job = job_handle;
    job->process = process.hProcess;
    job->process_id = process.dwProcessId;
    job->previous_sample_ms = GetTickCount64();
    const std::string id = IdString();
    g_jobs.emplace(id, std::move(job));
    Napi::Object result = Napi::Object::New(env);
    result.Set("id", id);
    result.Set("processId", process.dwProcessId);
    return result;
  } catch (const std::exception& error) { throw NativeError(env, error.what()); }
}

Job& GetJob(const Napi::Value& value) {
  if (!value.IsObject() || !value.As<Napi::Object>().Get("id").IsString()) throw std::runtime_error("invalid job handle");
  const std::string id = value.As<Napi::Object>().Get("id").As<Napi::String>().Utf8Value();
  auto found = g_jobs.find(id);
  if (found == g_jobs.end()) throw std::runtime_error("unknown or released job handle");
  return *found->second;
}

Napi::Value StopJob(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 2 || !info[1].IsNumber()) throw std::runtime_error("job handle and grace milliseconds required");
    Job& job = GetJob(info[0]);
    const uint32_t grace_ms = info[1].As<Napi::Number>().Uint32Value();
    if (grace_ms > 10000) throw std::runtime_error("grace interval exceeds ten seconds");
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (grace_ms) WaitForSingleObject(job.process, grace_ms);
    if (!QueryInformationJobObject(job.job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr)) throw std::runtime_error("could not inspect job before teardown");
    if (accounting.ActiveProcesses > 0) {
      if (!TerminateJobObject(job.job, ERROR_OPERATION_ABORTED)) throw std::runtime_error("could not terminate the complete process job");
    }
    const ULONGLONG deadline = GetTickCount64() + 30000;
    do {
      if (WaitForSingleObject(job.process, 10) == WAIT_FAILED) throw std::runtime_error("could not wait for root process teardown");
      if (!QueryInformationJobObject(job.job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr)) throw std::runtime_error("could not verify job teardown");
      if (accounting.ActiveProcesses == 0) break;
    } while (GetTickCount64() < deadline);
    Napi::Object receipt = Napi::Object::New(env);
    receipt.Set("jobId", info[0].As<Napi::Object>().Get("id"));
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    wchar_t timestamp[32]{};
    swprintf_s(timestamp, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond, utc.wMilliseconds);
    std::u16string timestamp_utf16;
    for (const wchar_t character : std::wstring(timestamp)) timestamp_utf16.push_back(static_cast<char16_t>(character));
    receipt.Set("stoppedAtUtc", Napi::String::New(env, timestamp_utf16));
    receipt.Set("remainingProcesses", accounting.ActiveProcesses);
    DWORD exit_code = 0;
    const bool root_exited = WaitForSingleObject(job.process, 0) == WAIT_OBJECT_0 && GetExitCodeProcess(job.process, &exit_code);
    receipt.Set("exitCode", root_exited ? Napi::Number::New(env, static_cast<double>(exit_code)) : env.Null());
    receipt.Set("stopReason", "requested");
    if (accounting.ActiveProcesses == 0) g_jobs.erase(info[0].As<Napi::Object>().Get("id").As<Napi::String>().Utf8Value());
    else throw std::runtime_error("job still has active processes after stop");
    return receipt;
  } catch (const std::exception& error) { throw NativeError(env, error.what()); }
}

Napi::Value SampleJob(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 1) throw std::runtime_error("job handle required");
    Job& job = GetJob(info[0]);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION memory{};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (!QueryInformationJobObject(job.job, JobObjectExtendedLimitInformation, &memory, sizeof(memory), nullptr) ||
        !QueryInformationJobObject(job.job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr)) throw std::runtime_error("job sample failed");
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG elapsed = std::max<ULONGLONG>(1, now - job.previous_sample_ms);
    const ULONGLONG cpu = static_cast<ULONGLONG>(accounting.TotalUserTime.QuadPart + accounting.TotalKernelTime.QuadPart);
    const DWORD processor_count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (processor_count == 0 || cpu < job.previous_cpu_100ns) throw std::runtime_error("invalid job CPU accounting sample");
    const double cpu_percent = static_cast<double>(cpu - job.previous_cpu_100ns) /
                               (elapsed * 10000.0 * static_cast<double>(processor_count)) * 100.0;
    job.previous_sample_ms = now;
    job.previous_cpu_100ns = cpu;
    Napi::Object sample = Napi::Object::New(env);
    sample.Set("cpu_percent", cpu_percent);
    sample.Set("memory_bytes", static_cast<double>(memory.PeakJobMemoryUsed));
    sample.Set("process_count", accounting.ActiveProcesses);
    return sample;
  } catch (const std::exception& error) { throw NativeError(env, error.what()); }
}

Napi::Value SampleVolumeUsage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 1) throw std::runtime_error("worker-volume directory required");
    const std::wstring directory = Wide(info[0], "worker-volume directory");
    if (!IsOrdinaryLocalPath(directory)) throw std::runtime_error("worker volume must be an ordinary local path");
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
      throw std::runtime_error("worker-volume directory is unavailable or redirected");
    }
    std::array<wchar_t, 32768> volume_path{};
    if (!GetVolumePathNameW(directory.c_str(), volume_path.data(), static_cast<DWORD>(volume_path.size()))) {
      throw std::runtime_error("could not resolve worker-volume identity");
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      // Mounted folders are reparse points by design. Permit one only when
      // this exact input is itself the volume root; junctions into a subtree
      // or another path remain rejected.
      std::wstring expected_root(directory);
      if (expected_root.back() != L'\\' && expected_root.back() != L'/') expected_root.push_back(L'\\');
      std::wstring resolved_root(volume_path.data());
      while (expected_root.size() > 3 && (expected_root.back() == L'\\' || expected_root.back() == L'/')) expected_root.pop_back();
      while (resolved_root.size() > 3 && (resolved_root.back() == L'\\' || resolved_root.back() == L'/')) resolved_root.pop_back();
      if (_wcsicmp(expected_root.c_str(), resolved_root.c_str()) != 0) {
        throw std::runtime_error("worker data path is redirected or is not a volume mount root");
      }
    }
    std::array<wchar_t, 128> volume_name{};
    if (!GetVolumeNameForVolumeMountPointW(volume_path.data(), volume_name.data(),
                                           static_cast<DWORD>(volume_name.size()))) {
      throw std::runtime_error("could not resolve worker-volume identity");
    }
    ULARGE_INTEGER available{}, user_total_available{}, volume_free{};
    if (!GetDiskFreeSpaceExW(directory.c_str(), &available, &user_total_available, &volume_free)) {
      throw std::runtime_error("could not sample worker-volume quota");
    }
    std::array<wchar_t, 32> filesystem{};
    if (!GetVolumeInformationW(volume_path.data(), nullptr, 0, nullptr, nullptr, nullptr,
                               filesystem.data(), static_cast<DWORD>(filesystem.size())) ||
        _wcsicmp(filesystem.data(), L"NTFS") != 0) {
      throw std::runtime_error("worker data volume must use NTFS");
    }
    constexpr ULONGLONG max_safe_integer = 9007199254740991ULL;
    // GetDiskFreeSpaceExW's second result is the total capacity available to
    // the calling service account; NTFS per-user quotas may cap it below the
    // physical volume size. Installer policy independently verifies the
    // service SID's enforced quota against this configured capacity.
    if (user_total_available.QuadPart == 0 || available.QuadPart > user_total_available.QuadPart ||
        user_total_available.QuadPart > max_safe_integer) {
      throw std::runtime_error("worker-volume quota is unavailable or exceeds supported bounds");
    }
    Napi::Object sample = Napi::Object::New(env);
    sample.Set("quota_bytes", static_cast<double>(user_total_available.QuadPart));
    sample.Set("available_bytes", static_cast<double>(available.QuadPart));
    sample.Set("used_bytes", static_cast<double>(user_total_available.QuadPart - available.QuadPart));
    const std::wstring volume_id(volume_name.data());
    sample.Set("volume_id", Napi::String::New(env, std::u16string(volume_id.begin(), volume_id.end())));
    return sample;
  } catch (const std::exception& error) { throw NativeError(env, error.what()); }
}

Napi::Value AssertWorkerServiceNetworkBinding(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 2) throw std::runtime_error("Worker network binding verification failed");
    const std::wstring adapter_value = Wide(info[0], "adapter GUID");
    const std::wstring address_value = Wide(info[1], "bind address");
    std::wstring canonical_guid = adapter_value;
    if (canonical_guid.size() == 38 && canonical_guid.front() == L'{' &&
        canonical_guid.back() == L'}') {
      canonical_guid = canonical_guid.substr(1, 36);
    }
    if (canonical_guid.size() != 36 || address_value.empty() || address_value.size() > 64 ||
        address_value.find(L'%') != std::wstring::npos) {
      throw std::runtime_error("Worker network binding verification failed");
    }
    for (size_t index = 0; index < canonical_guid.size(); ++index) {
      if (index == 8 || index == 13 || index == 18 || index == 23) {
        if (canonical_guid[index] != L'-')
          throw std::runtime_error("Worker network binding verification failed");
        continue;
      }
      const wchar_t c = canonical_guid[index];
      if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
            (c >= L'A' && c <= L'F'))) {
        throw std::runtime_error("Worker network binding verification failed");
      }
    }
    const std::wstring guid_text = L"{" + canonical_guid + L"}";
    GUID adapter_guid{};
    if (CLSIDFromString(guid_text.c_str(), &adapter_guid) != S_OK) {
      throw std::runtime_error("Worker network binding verification failed");
    }
    NET_LUID adapter_luid{};
    if (ConvertInterfaceGuidToLuid(&adapter_guid, &adapter_luid) != NO_ERROR) {
      throw std::runtime_error("Worker network binding verification failed");
    }
    MIB_IF_ROW2 adapter{};
    adapter.InterfaceLuid = adapter_luid;
    if (GetIfEntry2(&adapter) != NO_ERROR || adapter.OperStatus != IfOperStatusUp) {
      throw std::runtime_error("Worker network binding verification failed");
    }

    IN_ADDR expected_v4{};
    IN6_ADDR expected_v6{};
    ADDRESS_FAMILY family = AF_UNSPEC;
    if (InetPtonW(AF_INET, address_value.c_str(), &expected_v4) == 1) family = AF_INET;
    else if (InetPtonW(AF_INET6, address_value.c_str(), &expected_v6) == 1) family = AF_INET6;
    else throw std::runtime_error("Worker network binding verification failed");

    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &table) != NO_ERROR || !table) {
      throw std::runtime_error("Worker network binding verification failed");
    }
    struct AddressTableGuard {
      PMIB_UNICASTIPADDRESS_TABLE table;
      ~AddressTableGuard() { if (table) FreeMibTable(table); }
    } table_guard{table};

    bool exact_address_found = false;
    for (ULONG index = 0; index < table->NumEntries; ++index) {
      const MIB_UNICASTIPADDRESS_ROW& row = table->Table[index];
      if (row.InterfaceLuid.Value != adapter_luid.Value || row.DadState != IpDadStatePreferred ||
          row.Address.si_family != family) continue;
      if (family == AF_INET &&
          std::memcmp(&row.Address.Ipv4.sin_addr, &expected_v4, sizeof(expected_v4)) == 0) {
        exact_address_found = true;
        break;
      }
      if (family == AF_INET6 &&
          std::memcmp(&row.Address.Ipv6.sin6_addr, &expected_v6, sizeof(expected_v6)) == 0) {
        exact_address_found = true;
        break;
      }
    }
    if (!exact_address_found) throw std::runtime_error("Worker network binding verification failed");
    return env.Undefined();
  } catch (...) {
    throw NativeError(env, "Worker network binding verification failed");
  }
}

Napi::Value AssertWorkerServiceIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 0) throw std::runtime_error("worker service identity verification failed");

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      throw std::runtime_error("worker service identity verification failed");
    }
    struct TokenHandle {
      HANDLE value;
      ~TokenHandle() { if (value) CloseHandle(value); }
    } token_handle{token};

    DWORD user_bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &user_bytes);
    if (user_bytes == 0 || user_bytes > 1024 * 1024) {
      throw std::runtime_error("worker service identity verification failed");
    }
    std::vector<BYTE> user_storage(user_bytes);
    if (!GetTokenInformation(token, TokenUser, user_storage.data(), user_bytes, &user_bytes)) {
      throw std::runtime_error("worker service identity verification failed");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(user_storage.data());
    if (!IsValidSid(user->User.Sid)) {
      throw std::runtime_error("worker service identity verification failed");
    }

    DWORD group_bytes = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &group_bytes);
    if (group_bytes == 0 || group_bytes > 1024 * 1024) {
      throw std::runtime_error("worker service identity verification failed");
    }
    std::vector<BYTE> group_storage(group_bytes);
    if (!GetTokenInformation(token, TokenGroups, group_storage.data(), group_bytes, &group_bytes)) {
      throw std::runtime_error("worker service identity verification failed");
    }
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(group_storage.data());

    DWORD service_sid_bytes = 0;
    DWORD service_domain_chars = 0;
    SID_NAME_USE account_use{};
    LookupAccountNameW(nullptr, L"NT SERVICE\\SumatraFuzzWorker", nullptr, &service_sid_bytes,
                       nullptr, &service_domain_chars, &account_use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || service_sid_bytes == 0 ||
        service_sid_bytes > SECURITY_MAX_SID_SIZE || service_domain_chars > 32767) {
      throw std::runtime_error("worker service identity verification failed");
    }
    std::vector<BYTE> service_sid_storage(service_sid_bytes);
    std::vector<wchar_t> service_domain(service_domain_chars);
    if (!LookupAccountNameW(nullptr, L"NT SERVICE\\SumatraFuzzWorker", service_sid_storage.data(),
                            &service_sid_bytes, service_domain.data(), &service_domain_chars, &account_use) ||
        account_use != SidTypeUser) {
      throw std::runtime_error("worker service identity verification failed");
    }
    PSID service_sid = service_sid_storage.data();
    if (!IsValidSid(service_sid) || !EqualSid(user->User.Sid, service_sid)) {
      throw std::runtime_error("worker service identity verification failed");
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> system_sid_storage{};
    DWORD system_sid_bytes = static_cast<DWORD>(system_sid_storage.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid_storage.data(), &system_sid_bytes) ||
        EqualSid(user->User.Sid, system_sid_storage.data())) {
      throw std::runtime_error("worker service identity verification failed");
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> administrators_sid_storage{};
    DWORD administrators_sid_bytes = static_cast<DWORD>(administrators_sid_storage.size());
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators_sid_storage.data(),
                            &administrators_sid_bytes)) {
      throw std::runtime_error("worker service identity verification failed");
    }
    if (EqualSid(user->User.Sid, administrators_sid_storage.data())) {
      throw std::runtime_error("worker service identity verification failed");
    }
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
      if (IsValidSid(groups->Groups[i].Sid) &&
          EqualSid(groups->Groups[i].Sid, administrators_sid_storage.data())) {
        throw std::runtime_error("worker service identity verification failed");
      }
    }

    return env.Undefined();
  } catch (const std::exception&) {
    // Do not return SID, group, token, or operating-system details to JavaScript.
    throw NativeError(env, "worker service identity verification failed");
  }
}

Napi::Value ProtectSecret(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() != 1 || !info[0].IsBuffer()) throw Napi::TypeError::New(env, "secret must be a Buffer");
  auto input = info[0].As<Napi::Buffer<uint8_t>>();
  DATA_BLOB source{static_cast<DWORD>(input.Length()), input.Data()}, output{};
  if (!CryptProtectData(&source, L"SumatraFuzz worker secret", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) throw NativeError(env, "DPAPI protection failed");
  auto result = Napi::Buffer<uint8_t>::Copy(env, output.pbData, output.cbData);
  LocalFree(output.pbData);
  return result;
}

Napi::Value UnprotectSecret(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() != 1 || !info[0].IsBuffer()) throw Napi::TypeError::New(env, "ciphertext must be a Buffer");
  auto input = info[0].As<Napi::Buffer<uint8_t>>();
  DATA_BLOB source{static_cast<DWORD>(input.Length()), input.Data()}, output{};
  if (!CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) throw NativeError(env, "DPAPI unprotection failed");
  auto result = Napi::Buffer<uint8_t>::Copy(env, output.pbData, output.cbData);
  LocalFree(output.pbData);
  return result;
}

#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
#ifdef _WIN32
  exports.Set("launchSuspended", Napi::Function::New(env, LaunchSuspended));
  exports.Set("stopJob", Napi::Function::New(env, StopJob));
  exports.Set("sampleJob", Napi::Function::New(env, SampleJob));
  exports.Set("sampleVolumeUsage", Napi::Function::New(env, SampleVolumeUsage));
  exports.Set("assertWorkerServiceNetworkBinding", Napi::Function::New(env, AssertWorkerServiceNetworkBinding));
  exports.Set("assertWorkerServiceIdentity", Napi::Function::New(env, AssertWorkerServiceIdentity));
  exports.Set("protectSecret", Napi::Function::New(env, ProtectSecret));
  exports.Set("unprotectSecret", Napi::Function::New(env, UnprotectSecret));
#else
  exports.Set("launchSuspended", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("stopJob", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("sampleJob", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("sampleVolumeUsage", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("assertWorkerServiceNetworkBinding", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("assertWorkerServiceIdentity", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
#endif
  return exports;
}

}  // namespace

NODE_API_MODULE(worker_supervisor, Init)
