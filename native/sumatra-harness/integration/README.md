# A3 — Genuine SumatraPDF 3.6.1 PDF parser integration

Upstream source tag: `3.6.1rel` at SHA `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.

This integration uses **SumatraPDF's own `PdfFilter.dll`**, not a separately compiled MuPDF target or a Windows system IFilter. The pinned source's `src/ifilter/PdfFilter.cpp::OnInit` calls `CreateEngineMupdfFromStream`; `src/EngineMupdf.cpp` opens the document using the integrated MuPDF library. The harness loads the PDF filter DLL from its *own executable directory*, acquires its COM class factory with `DllGetClassObject` and the **pinned CLSID**, passes each PDF as an `IStream`, and calls `IFilter::Init`. It releases filter, COM interfaces, stream, module and COM apartment per call.

## Build upstream on isolated Windows x64

1. Install VS2022 C++ Build Tools + Windows SDK, Git, PowerShell 7, CMake. Clone `https://github.com/sumatrapdfreader/sumatrapdf` and check out exactly `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.
2. Verify that pinned checkout includes third-party dependencies, generated source files, required build helpers, and `vs2022/SumatraPDF.sln` before building. Missing prerequisites are a **blocking failure**, not a reason to substitute a different parser.
3. Using VS2022 MSBuild, build `PdfFilter` project for `x64|Release` **at the pinned revision**; also build its dependencies.
4. Copy the exact `PdfFilter.dll` and all required side-by-side runtime dependencies from the build output to the directory containing the harness executable.
5. Build CMake with `-DSUMATRAFUZZ_REAL_ENGINE=ON` and run `ctest`. A real filter build and successful tests are required to claim A3 success. Absence of DLL means tests fail.
6. Run the executable `--selftest` on a valid PDF and `dumpbin /exports` against the built executable; record the SHA-256 of source checkout, filter and harness.

**Important:** This adapter depends on the pinned SumatraPDF `PdfFilter.dll` being loadable and compatible. It is not proof that the DLL was built until Windows output is collected. In-process instrumentation must later include whichever loaded DLL contains parser code. Verify with actual DynamoRIO module logs in A4.

### Library call chain
`fuzz_one_file(path)` → `sumatra_parse_pdf(path)` → `DllGetClassObject` → `IInitializeWithStream::Initialize` → `IFilter::Init` → `PdfFilter::OnInit` → `CreateEngineMupdfFromStream` → `EngineMupdf::Load`.

This is a source-integrated SumatraPDF codepath, not a mock. The PDF filter's supported operations and dependencies follow the upstream source and its GPLv3 licensing conditions.

### Verification gates
- A2 native contract tests: mock only.
- A3 real-engine tests: must run on Windows x64 against real `PdfFilter.dll`; fail closed otherwise.
- A4 DynamoRIO wrapper re-entry and actual coverage modules: **not yet verified**.
