#-------------------------------------------------------------------------------
# C/C++ used within Ockam
#-------------------------------------------------------------------------------

set(OCKAM_C_STANDARD 99)
set(OCKAM_CXX_STANDARD 17)

if(ockam_SOURCE_DIR)
  # ockam_SOURCE_DIR is set when building from implementations/c
  set(OCKAM_ROOT_DIR ${ockam_SOURCE_DIR})
else()
  # Otherwise, we can get the same thing by getting the
  # parent directory of this module's directory
  get_filename_component(OCKAM_ROOT_DIR "../" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_LIST_DIR}")
endif()

set(OCKAM_THIRD_PARTY_DIR "${OCKAM_ROOT_DIR}/third_party")

list(APPEND OCKAM_COMMON_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

ockam_select_compiler_opts(OCKAM_DEFAULT_COPTS
  CLANG
    "-Wno-strict-prototypes"
    "-Wno-shadow-uncaptured-local"
    "-Wno-gnu-zero-variadic-macro-arguments"
    "-Wno-shadow-field-in-constructor"
    "-Wno-unreachable-code-return"
    "-Wno-unused-private-field"
    "-Wno-missing-variable-declarations"
    "-Wno-gnu-label-as-value"
    "-Wno-unused-local-typedef"
    "-Wno-gnu-zero-variadic-macro-arguments"
  CLANG_OR_GCC
    "-Wno-unused-parameter"
    "-Wno-undef"
    "-fno-rtti"
  MSVC_OR_CLANG_CL
    "/DWIN32_LEAN_AND_MEAN"
    "/EHsc"
)
set(OCKAM_DEFAULT_LINKOPTS "")
set(OCKAM_TEST_COPTS "")

if(${OCKAM_ENABLE_TRACING})
  list(APPEND OCKAM_DEFAULT_COPTS
    "-DGLOBAL_WTF_ENABLE=1"
  )
endif()

#-------------------------------------------------------------------------------
# Compiler: Clang/LLVM
#-------------------------------------------------------------------------------

# TODO: Clang/LLVM options.

#-------------------------------------------------------------------------------
# Compiler: GCC
#-------------------------------------------------------------------------------

# TODO: GCC options.

#-------------------------------------------------------------------------------
# Compiler: MSVC
#-------------------------------------------------------------------------------

# TODO: MSVC options.

#-------------------------------------------------------------------------------
# Third party: benchmark
#-------------------------------------------------------------------------------

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

#-------------------------------------------------------------------------------
# Third party: cmocka
#-------------------------------------------------------------------------------

include(ockam_cmocka)
