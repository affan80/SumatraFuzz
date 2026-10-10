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

// SumatraPDF 3.6.1rel, src/RegistrySearchFilter.h, kPdfFilterClsid.
// PdfFilter::OnInit() -> CreateEngineMupdfFromStream() -> EngineMupdf::Load.
static const CLSID kPinnedPdfFilterClsid = {
    0x55808ea8, 0x81fe, 0x43c6, {0xaa, 0xe8, 0x1d, 0x81, 0x49, 0xf9, 0x41, 0xd3}
};

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

namespace {
template <typename T> struct ComRef {
    T* p = nullptr;
    ~ComRef() { if (p) p->Release(); }
    T** out() { return &p; }
    T* get() const { return p; }
};

struct RuntimeState {
    HMODULE module = nullptr;
    DllGetClassObjectFn factory_fn = nullptr;
    bool owns_com_apartment = false;
};
thread_local RuntimeState runtime{};

std::wstring to_wide_utf8(const char* input) {
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, out.data(), n) != n) return {};
    out.pop_back();
    return out;
}
} // namespace

bool prepare_sumatra_runtime() {
    if (runtime.module && runtime.factory_fn) return true;
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(com) && com != RPC_E_CHANGED_MODE) return false;
    const bool owns_com = SUCCEEDED(com);

    wchar_t location[MAX_PATH] = {};
    const DWORD count = GetModuleFileNameW(nullptr, location, MAX_PATH);
    if (count == 0 || count >= MAX_PATH) {
        if (owns_com) CoUninitialize();
        return false;
    }
    const auto filter_path = std::filesystem::path(location).parent_path() / L"PdfFilter.dll";
    std::error_code ec;
    if (!std::filesystem::is_regular_file(filter_path, ec) || ec) {
        if (owns_com) CoUninitialize();
        return false;
    }
    HMODULE module = LoadLibraryExW(filter_path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!module) {
        if (owns_com) CoUninitialize();
        return false;
    }
    auto fn = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(module, "DllGetClassObject"));
    if (!fn) {
        FreeLibrary(module);
        if (owns_com) CoUninitialize();
        return false;
    }
    runtime = {module, fn, owns_com};
    return true;
}

void release_sumatra_runtime() noexcept {
    if (runtime.module) FreeLibrary(runtime.module);
    if (runtime.owns_com_apartment) CoUninitialize();
    runtime = {};
}

extern "C" int sumatra_parse_pdf(const char* input_path) {
    if (!input_path || !*input_path) return 1;
    const auto input = to_wide_utf8(input_path);
    if (input.empty()) return 1;

    // No registry registration and no generic system PDF filter fallback.
    // The deployed DLL MUST come from the verified pinned SumatraPDF build.
    if (!runtime.factory_fn) return 1;

    ComRef<IClassFactory> factory;
    if (FAILED(runtime.factory_fn(kPinnedPdfFilterClsid, IID_IClassFactory,
                          reinterpret_cast<void**>(factory.out()))) || !factory.get()) return 1;

    ComRef<IFilter> filter;
    if (FAILED(factory.get()->CreateInstance(nullptr, IID_IFilter,
                    reinterpret_cast<void**>(filter.out()))) || !filter.get()) return 1;

    ComRef<IInitializeWithStream> initializer;
    if (FAILED(filter.get()->QueryInterface(IID_IInitializeWithStream,
                    reinterpret_cast<void**>(initializer.out()))) || !initializer.get()) return 1;

    ComRef<IStream> stream;
    if (FAILED(SHCreateStreamOnFileEx(input.c_str(), STGM_READ | STGM_SHARE_DENY_NONE,
                    FILE_ATTRIBUTE_NORMAL, FALSE, nullptr, stream.out())) || !stream.get()) return 1;
    if (FAILED(initializer.get()->Initialize(stream.get(), STGM_READ))) return 1;

    ULONG flags = 0;
    // Critical call: real PdfFilter::OnInit() performs SumatraPDF document parsing.
    const HRESULT result = filter.get()->Init(0, 0, nullptr, &flags);
    // IFilter destructor releases EngineBase on every invocation.
    return SUCCEEDED(result) ? 0 : 1;
}
