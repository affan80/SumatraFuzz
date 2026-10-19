#ifdef _WIN32
#include <windows.h>
#include <iterator>
#include <string>

int wmain(int argc, wchar_t** argv) {
  wchar_t secret[16]{};
  if (GetEnvironmentVariableW(L"SUMATRAFUZZ_TEST_SECRET", secret, static_cast<DWORD>(std::size(secret))) > 0) return 11;
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
