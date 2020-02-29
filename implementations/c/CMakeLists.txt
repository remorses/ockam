cmake_minimum_required(VERSION 3.14)

# Set target platform and debug/release here


if (ENV{VERBOSE})
    set(CMAKE_INSTALL_MESSAGE ALWAYS)
else()
    set(CMAKE_INSTALL_MESSAGE LAZY)
endif()

# Load helper modules
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

project(ockam
    VERSION 0.1
)

set(CMAKE_EXPORT_COMPILE_COMMANDS OFF CACHE BOOL "")

# Set up paths for build outputs
set(OCKAM_C_BASE ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_BINARY_DIR {OCKAM_C_BASE}/_build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(OCKAM_IDE_FOLDER Ockam)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(OCKAM_BUILD_TESTS "Builds Ockam tests." OFF)

message(STATUS "CMake Version   : " "${CMAKE_SYSTEM_VERSION}")
message(STATUS "Compiler        : " "${CMAKE_C_COMPILER}")
message(STATUS "Target          : " "${CMAKE_C_COMPILER_TARGET}")
message(STATUS "Operating System: " "${CMAKE_SYSTEM}")
message(STATUS "Build Tests     : " "${OCKAM_BUILD_TESTS}")

include(ockam_macros)
include(ockam_copts)
include(ockam_cc_binary)
include(ockam_cc_library)
include(ockam_cc_test)
include(ockam_cc_alwayslink)

string(JOIN " " CMAKE_CXX_FLAGS ${OCKAM_DEFAULT_COPTS})

set(DEFAULT_CMAKE_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to ${DEFAULT_CMAKE_BUILD_TYPE}")
  set(CMAKE_BUILD_TYPE "${DEFAULT_CMAKE_BUILD_TYPE}" CACHE STRING "Build type (default ${DEFAULT_CMAKE_BUILD_TYPE})" FORCE)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

#!! include(external_cc_library)

# We don't want builds stomping all over the source directory
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR AND NOT MSVC_IDE)
  message(FATAL_ERROR "In-source builds are not allowed. "
"Please create a directory and run cmake "
"from there, passing the path to this source directory as the last argument. "
"This process created the file `CMakeCache.txt' and the directory "
"`CMakeFiles'. Please delete them.")
endif()


set_alwayslink_ockam_libs()

add_subdirectory(lib)
if (${OCKAM_BUILD_TESTS})
  enable_testing(lib)
  add_subdirectory(tests)
endif()

ockam_complete_binary_link_options()
