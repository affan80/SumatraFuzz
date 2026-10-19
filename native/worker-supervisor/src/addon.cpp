#include <napi.h>

#include "command_line.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <stdexcept>
#include <cwctype>
#include <cstdio>
#include <vector>

#ifdef _WIN32
#include <windows.h>
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

std::vector<OpenProof> VerifyProofs(Napi::Array proofs, const std::wstring& executable) {
  if (proofs.Length() == 0 || proofs.Length() > 64) throw std::runtime_error("invalid file proof count");
  OpenProof executable_file;
  executable_file.handle = CreateFileW(executable.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (executable_file.handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open requested executable");
  BY_HANDLE_FILE_INFORMATION executable_info{};
  if (!GetFileInformationByHandle(executable_file.handle, &executable_info) || (executable_info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
    throw std::runtime_error("requested executable is redirected or not a regular file");
  }
  const std::wstring canonical_executable = Lower(FinalPath(executable_file.handle));
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
    open.push_back(std::move(file));  // Deny write/delete sharing until CreateProcess has opened the image.
  }
  if (!executable_proven) throw std::runtime_error("requested executable has no matching verified file proof");
  return open;
}

Napi::Value LaunchSuspended(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    if (info.Length() != 1 || !info[0].IsObject()) throw std::runtime_error("launch specification required");
    Napi::Object spec = info[0].As<Napi::Object>();
    const std::wstring executable = Wide(spec.Get("executable"), "executable");
    const std::wstring working_dir = Wide(spec.Get("workingDir"), "workingDir");
    Napi::Array argv = spec.Get("argv").As<Napi::Array>();
    Napi::Array proofs = spec.Get("fileProofs").As<Napi::Array>();
    Napi::Object limits = spec.Get("limits").As<Napi::Object>();
    const double memory = limits.Get("max_memory_bytes").As<Napi::Number>().DoubleValue();
    const double cpu = limits.Get("max_cpu_percent").As<Napi::Number>().DoubleValue();
    if (!std::isfinite(memory) || !std::isfinite(cpu) || std::floor(memory) != memory || std::floor(cpu) != cpu ||
        memory < 16 * 1024 * 1024 || memory > 0x7fffffffffffffff || cpu < 1 || cpu > 100) throw std::runtime_error("resource limit outside native bounds");
    std::vector<OpenProof> opened_proofs = VerifyProofs(proofs, executable);

    std::vector<std::wstring> arguments{executable};
    if (argv.Length() > 256) throw std::runtime_error("argument count exceeds native bound");
    for (uint32_t i = 0; i < argv.Length(); ++i) arguments.push_back(Wide(argv.Get(i), "argv entry"));
    std::wstring command = sumatrafuzz::supervisor::BuildWindowsCommandLine(arguments);
    if (command.size() > 32766) throw std::runtime_error("command line exceeds Windows limit");
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
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, flags, nullptr, working_dir.c_str(), &startup, &process)) {
      CloseHandle(job_handle); throw std::runtime_error("CreateProcessW failed");
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
    receipt.Set("stoppedAtUtc", Napi::String::New(env, std::wstring(timestamp)));
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
  exports.Set("protectSecret", Napi::Function::New(env, ProtectSecret));
  exports.Set("unprotectSecret", Napi::Function::New(env, UnprotectSecret));
#else
  exports.Set("launchSuspended", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("stopJob", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
  exports.Set("sampleJob", Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value { throw Napi::Error::New(info.Env(), "Windows x64 supervisor is unsupported on this platform"); }));
#endif
  return exports;
}

}  // namespace

NODE_API_MODULE(worker_supervisor, Init)
