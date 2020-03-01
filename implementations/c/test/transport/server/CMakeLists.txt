cmake_minimum_required(VERSION 3.14)

include(${CMAKE_CURRENT_SOURCE_DIR}/ockam_local_options.cmake)
if(OCKAM_C_TARGET_PLATFORM STREQUAL "Pi")
  include(${OCKAM_C_BASE}/tools/cmake/toolchains/raspberry-pi.cmake)
endif()

message(STATUS "CMAKE_BUILD_TYPE         : " "${CMAKE_BUILD_TYPE}")
message(STATUS "OCKAM_C_TARGET_PLATFORM  : " "${OCKAM_C_TARGET_PLATFORM}")

project(transport_server_test)

# Set directory locations

set(TEST_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(OCKAM_SRC_DIR ${OCKAM_C_BASE}/source/ockam)
set(OCKAM_INC_DIR ${OCKAM_C_BASE}/include)

set(TRANSPORT_SRC_DIR ${OCKAM_SRC_DIR}/transport)
set(BINARY_DIR _build/$ENV{PLATFORM})

set(CMAKE_BINARY_DIR ${OCKAM_C_BASE}/_build/${OCKAM_C_TARGET_PLATFORM}/lib/${CMAKE_BUILD_TYPE})


#################
# Build Options #
#################

# Compiler Build Options
set(CMAKE_VERBOSE_MAKEFILE TRUE)

###########################
# Set include directories #
###########################

set(TEST_INC ${TEST_INC} ${OCKAM_INC_DIR})
set(TEST_INC ${TEST_INC} ${TEST_INC_DIR})

include_directories(${TEST_INC})

# Get the headers
#include_directories( "./include/"
#  ${OCKAM_INC_DIR}
#  $ENV{OCKAM_C_BASE}/source/ockam/transport/include/ )

####################
# Set source files #
####################

set(TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/transport_server_test.c
  ${OCKAM_SRC_DIR}/log/syslog.c)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${BINARY_DIR})

###########################
# Set the desired modules #
###########################

add_subdirectory(${TRANSPORT_SRC_DIR} ${BINARY_DIR})

#########################################
# Configure link libraries & executable #
#########################################

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/${BINARY_DIR})
add_executable(transport_server_test ${TEST_SRC})
target_link_libraries(transport_server_test ockam_transport)

install(TARGETS transport_server_test DESTINATION bin)
