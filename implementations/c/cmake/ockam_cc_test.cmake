include(CMakeParseArguments)

# ockam_cc_test()
#
# Parameters:
# NAME: name of target (see Usage below)
# SRCS: List of source files for the binary
# DEPS: List of other libraries to be linked in to the binary targets
# COPTS: List of private compile options
# DEFINES: List of public defines
# LINKOPTS: List of link options
#
# Note:
# By default, ockam_cc_test will always create a binary named ockam_${NAME}.
# This will also add it to ctest list as ockam_${NAME}.
#
# Usage:
# ockam_cc_library(
#   NAME
#     foo
#   HDRS
#     "foo.h"
#   SRCS
#     "foo.cc"
#   PUBLIC
# )
#
# ockam_cc_test(
#   NAME
#     foo_test
#   SRCS
#     "foo_test.cc"
#   DEPS
#     ockam::foo
# )
function(ockam_cc_test)
  if(NOT OCKAM_BUILD_TESTS)
    return()
  endif()

  cmake_parse_arguments(
    _RULE
    ""
    "NAME"
    "SRCS;COPTS;DEFINES;LINKOPTS;DEPS"
    ${ARGN}
  )

  ockam_package_ns(_PACKAGE_NS)
  # Replace dependencies passed by ::name with ::ockam::package::name
  list(TRANSFORM _RULE_DEPS REPLACE "^::" "${_PACKAGE_NS}::")

  # Prefix the library with the package name, so we get: ockam_package_name
  ockam_package_name(_PACKAGE_NAME)
  set(_NAME "${_PACKAGE_NAME}_${_RULE_NAME}")

  include(CTest)

  add_executable(${_NAME} "")
  target_sources(${_NAME}
    PRIVATE
      ${_RULE_SRCS}
  )
  target_include_directories(${_NAME}
    PUBLIC
      ${OCKAM_COMMON_INCLUDE_DIRS}
    PRIVATE
      ${CMOCKA_INCLUDE_DIRS}
  )
  target_compile_definitions(${_NAME}
    PUBLIC
      ${_RULE_DEFINES}
  )
  target_compile_options(${_NAME}
    PRIVATE
      ${_RULE_COPTS}
  )
  target_link_libraries(${_NAME}
    PUBLIC
      ${_RULE_DEPS}
      cmocka-static
    PRIVATE
      ${_RULE_LINKOPTS}
  )
  # Add all OCKAM targets to a folder in the IDE for organization.
  set_property(TARGET ${_NAME} PROPERTY FOLDER ${OCKAM_IDE_FOLDER}/test)

  set_property(TARGET ${_NAME} PROPERTY CXX_STANDARD ${OCKAM_CXX_STANDARD})
  set_property(TARGET ${_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
  set_property(TARGET ${_NAME} PROPERTY C_STANDARD ${OCKAM_C_STANDARD})
  set_property(TARGET ${_NAME} PROPERTY C_STANDARD_REQUIRED ON)

  add_test(NAME ${_NAME} COMMAND ${_NAME})
endfunction()
