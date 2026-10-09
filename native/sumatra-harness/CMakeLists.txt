cmake_minimum_required(VERSION 3.20)
project(sumatrafuzz_native_contract LANGUAGES CXX)
enable_testing()

add_library(fuzz_contract STATIC src/fuzz_contract.cpp)
target_include_directories(fuzz_contract PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(fuzz_contract PUBLIC cxx_std_17)

# This is a contract test only. The fake adapter must NEVER be linked to
# a release executable or used as evidence of actual SumatraPDF parsing.
add_executable(harness_contract_tests tests/contract_tests.cpp)
target_link_libraries(harness_contract_tests PRIVATE fuzz_contract)
add_test(NAME harness_contract_tests COMMAND harness_contract_tests)

# A3: real parser integration. No test-only fake adapter in this target.
# Explicit opt-in until a pinned upstream PdfFilter.dll is provided.
option(SUMATRAFUZZ_REAL_ENGINE "Build the genuine SumatraPDF PdfFilter-based harness" ON)
if(SUMATRAFUZZ_REAL_ENGINE)
  if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Real SumatraPDF integration requires Windows x64")
  endif()
  add_executable(sumatrafuzz-harness src/cli.cpp src/sumatra_adapter.cpp)
  target_link_libraries(sumatrafuzz-harness PRIVATE fuzz_contract shlwapi ole32 uuid)
  target_compile_features(sumatrafuzz-harness PRIVATE cxx_std_17)

  add_executable(real_engine_tests tests/real_engine_tests.cpp src/sumatra_adapter.cpp)
  target_link_libraries(real_engine_tests PRIVATE fuzz_contract shlwapi ole32 uuid)
  target_compile_features(real_engine_tests PRIVATE cxx_std_17)

  # DLL is never bundled or substituted; explicit path from an actual
  # upstream build must be provided on the real Windows integration runner.
  set(SUMATRAFUZZ_PDF_FILTER_DLL "" CACHE FILEPATH "Path to pinned upstream PdfFilter.dll")
  if(SUMATRAFUZZ_PDF_FILTER_DLL)
    if(NOT EXISTS "${SUMATRAFUZZ_PDF_FILTER_DLL}")
      message(FATAL_ERROR "Pinned PdfFilter.dll path does not exist")
    endif()
    add_custom_command(TARGET sumatrafuzz-harness POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${SUMATRAFUZZ_PDF_FILTER_DLL}" "$<TARGET_FILE_DIR:sumatrafuzz-harness>/PdfFilter.dll")
    add_custom_command(TARGET real_engine_tests POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${SUMATRAFUZZ_PDF_FILTER_DLL}" "$<TARGET_FILE_DIR:real_engine_tests>/PdfFilter.dll")
  endif()
  add_test(NAME real_engine_tests COMMAND real_engine_tests)
endif()
