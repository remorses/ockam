#-------------------------------------------------------------------------------
# Options for building individual modules
#
# These options will be ignored if OCKAM_C_BASE is already defined
#
# This requires that environment variable OCKAM_C_BASE be set to
# <your_path>/ockam/implementations/c
#-------------------------------------------------------------------------------
if( NOT DEFINED OCKAM_C_BASE )
  message(STATUS "Using ockam_local_options")
  set(CMAKE_BUILD_TYPE Release)
  set(OCKAM_C_BASE $ENV{OCKAM_C_BASE})
endif()
