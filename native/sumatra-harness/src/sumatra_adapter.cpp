#if !defined(_WIN32) || !defined(_M_X64)
#error SumatraPDF filter integration is supported only for Windows x64 MSVC
#endif
#include "fuzz_contract.h"
#include "sumatra_runtime.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filter.h>
#include <propsys.h>
#include <shlwapi.h>
#include <filesystem>
#include <string>
#include <system_error>

static const CLSID kPinnedPdfFilterClsid = {
    0x55808ea8, 0x81fe, 0x43c6, {0xaa, 0xe8, 0x1d, 0x81, 0x49, 0xf9, 0x41, 0xd3}
};
using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

namespace {
template<typename T> struct ComRef {
    T* p = nullptr;
    ~ComRef() { if(p) p->Release(); }
    T** out() { return &p; }
    T* get() const { return p; }
};
struct ProcessRuntime {
    HMODULE pdf_filter = nullptr;
    IClassFactory* factory = nullptr;
    bool co_initialized = false;
    bool ready = false;
};
// WinAFL's persistent mode executes one thread, preparing this state in the
// CLI before entry into the exported fuzz_one_file. Never free the DLL within
// the target function, since repeated translation causes severe overhead.
ProcessRuntime runtime;

std::wstring to_wide_utf8(const char* input) {
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, nullptr, 0);
    if (length <= 0) return {};
    std::wstring wide(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, wide.data(), length) != length) return {};
    wide.pop_back();
    return wide;
}
} // namespace

void release_sumatra_runtime() noexcept {
    if (runtime.factory) {
        runtime.factory->Release();
        runtime.factory = nullptr;
    }
    if (runtime.pdf_filter) {
        FreeLibrary(runtime.pdf_filter);
        runtime.pdf_filter = nullptr;
    }
    if (runtime.co_initialized) {
        CoUninitialize();
        runtime.co_initialized = false;
    }
    runtime.ready = false;
}

bool prepare_sumatra_runtime() {
    if (runtime.ready) return true;
    // Caller and WinAFL instrumented target must run on the same thread.
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;
    runtime.co_initialized = SUCCEEDED(hr);

    wchar_t exe_path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        release_sumatra_runtime();
        return false;
    }
    const auto dll_path = std::filesystem::path(exe_path).parent_path() / L"PdfFilter.dll";
    std::error_code ec;
    if (!std::filesystem::is_regular_file(dll_path, ec) || ec) {
        release_sumatra_runtime();
        return false;
    }
    runtime.pdf_filter = LoadLibraryExW(dll_path.c_str(), nullptr,
                                      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!runtime.pdf_filter) {
        release_sumatra_runtime();
        return false;
    }
    auto make_factory = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(runtime.pdf_filter, "DllGetClassObject"));
    if (!make_factory || FAILED(make_factory(kPinnedPdfFilterClsid, IID_IClassFactory,
                                   reinterpret_cast<void**>(&runtime.factory))) || !runtime.factory) {
        release_sumatra_runtime();
        return false;
    }
    runtime.ready = true;
    return true;
}

extern "C" int sumatra_parse_pdf(const char* input_path) {
    if (!runtime.ready || !runtime.factory || !input_path || !*input_path) return 1;
    const std::wstring wide_path = to_wide_utf8(input_path);
    if (wide_path.empty()) return 1;

    ComRef<IFilter> filter;
    if (FAILED(runtime.factory->CreateInstance(nullptr, IID_IFilter,
                    reinterpret_cast<void**>(filter.out()))) || !filter.get()) return 1;
    ComRef<IInitializeWithStream> initializer;
    if (FAILED(filter.get()->QueryInterface(IID_IInitializeWithStream,
                    reinterpret_cast<void**>(initializer.out()))) || !initializer.get()) return 1;
    ComRef<IStream> stream;
    if (FAILED(SHCreateStreamOnFileEx(wide_path.c_str(), STGM_READ | STGM_SHARE_DENY_NONE,
                    FILE_ATTRIBUTE_NORMAL, FALSE, nullptr, stream.out())) || !stream.get()) return 1;
    if (FAILED(initializer.get()->Initialize(stream.get(), STGM_READ))) return 1;
    ULONG flags = 0;
    // Actual pinned SumatraPDF PdfFilter::OnInit => CreateEngineMupdfFromStream.
    // Each call creates and releases a fresh COM filter/stream/document.
    const HRESULT parse_result = filter.get()->Init(0, 0, nullptr, &flags);
    return SUCCEEDED(parse_result) ? 0 : 1;
}
