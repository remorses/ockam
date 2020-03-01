cmake_minimum_required(VERSION 3.14)

include(${CMAKE_CURRENT_SOURCE_DIR}/ockam_local_options.cmake)
if(OCKAM_C_TARGET_PLATFORM STREQUAL "Pi")
  include(${OCKAM_C_BASE}/tools/cmake/toolchains/raspberry-pi.cmake)
endif()

project(ockam_log C)


###########################
# Set directory locations #
###########################

set(LOG_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(OCKAM_INC_DIR $ENV{OCKAM_C_BASE}/include)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OCKAM_C_BASE}/_build/${OCKAM_C_TARGET_PLATFORM}/lib/${CMAKE_BUILD_TYPE})

#################
# Build Options #
#################

# Log Build Options
#option(LOG_SYSLOG "LOG: syslog")
#option(LOG_PRINTF "LOG: printf")


####################
# Log Library Code #
####################

#if(LOG_SYSLOG)
#    add_definitions(-DLOG_SYSLOG)
#    set(LOG_SRC ${LOG_SRC_DIR}/syslog.c)
#endif()

#if(LOG_PRINTF)
#    add_definitions(-DLOG_PRINTF)
#    set(LOG_SRC ${LOG_SRC_DIR}/printf.c)
#endif()


###################
# Generate Build! #
###################

# Add the source files
add_library(ockam_log STATIC ${LOG_SRC_DIR}/printf.c ${LOG_SRC_DIR}/syslog.c)

# Set the include directories
target_include_directories(ockam_log PUBLIC ${OCKAM_INC_DIR})


# Set the target
set_property(TARGET ockam_log PROPERTY C_STANDARD 99)

install(TARGETS ockam_log DESTINATION archive)
