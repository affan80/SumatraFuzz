# Task A3 — Genuine SumatraPDF integration verification

Status: **IMPLEMENTED FOR VALIDATION; NOT YET VERIFIED AGAINST A REAL PINNED DLL**.

The adapter loads its sibling `PdfFilter.dll` via `LoadLibraryExW`, resolves `DllGetClassObject`, uses the pinned `kPdfFilterClsid`, initializes `IInitializeWithStream` from the input file, then invokes `IFilter::Init`. In SumatraPDF source `3.6.1rel`, this calls `PdfFilter::OnInit`, which invokes the actual `CreateEngineMupdfFromStream`. Both the filter and stream are released every call.

Windows x64 build and genuine-parser tests are invoked with:

```powershell
pwsh -File scripts/windows/build-harness.ps1 -SumatraSource 'C:\src\sumatrapdf' -Configuration Release
```

Do not mark A3 **PASS** until MSBuild builds the real pinned DLL and `real_engine_tests` passes. No WinAFL/DynamoRIO coverage or crash claims are supported by this implementation alone. The test-only fake adapter remains only in `contract_tests.cpp`.
