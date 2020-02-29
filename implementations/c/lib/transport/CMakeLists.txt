cmake_minimum_required(VERSION 3.14)
project(ockam_transport C)

# Ockam Transport

###########################
# Set directory locations #
###########################

if( NOT DEFINED OCKAM_C_BASE )
  set(OCKAM_C_BASE $ENV{OCKAM_C_BASE})
endif()

set(OCKAM_INC_DIR ${OCKAM_C_BASE}/include)
set(TRANSPORT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(TRANSPORT_INC_DIR ${OCKAM_INC_DIR}
  ${TRANSPORT_SRC_DIR})

set(CMAKE_BINARY_DIR $ENV{OCKAM_C_BASE}/_build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OCKAM_C_BASE}/_build/lib)

#################
# Build Options #
#################


###################
# Generate Build! #
###################

# Add the source files
add_library(ockam_transport STATIC
  ${TRANSPORT_SRC_DIR}/transport.c
  ${TRANSPORT_SRC_DIR}/posix_socket.c
  ${TRANSPORT_SRC_DIR}/posix_tcp_connection.c)

# Set the target
set_property(TARGET ockam_transport PROPERTY C_STANDARD 99)

# Set the include directories
target_include_directories(ockam_transport PUBLIC ${TRANSPORT_INC_DIR})

install(TARGETS ockam_transport DESTINATION archive)
