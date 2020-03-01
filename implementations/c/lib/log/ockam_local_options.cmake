#-------------------------------------------------------------------------------
# Options for building individual modules
#
# These options will be ignored if settings have already been defined
# higher in the build tree.
#
# This requires that environment variable OCKAM_C_BASE be set to
# <your_path>/ockam/implementations/c
#-------------------------------------------------------------------------------
if(NOT DEFINED OCKAM_C_BASE)
  set(OCKAM_C_BASE $ENV{OCKAM_C_BASE})
endif()
if(NOT DEFINED OCKAM_C_TARGET_PLATFORM)
  set(OCKAM_C_TARGET_PLATFORM "Darwin")
endif()
if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()
