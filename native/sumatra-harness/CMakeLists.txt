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
