list(APPEND OCKAM_COMMON_INCLUDE_DIRS
  "${OCKAM_THIRD_PARTY_DIR}/arm/mbed-crypto/include"
  "${OCKAM_THIRD_PARTY_DIR}/arm/mbed-crypto/3rdparty/everest/include"
)

set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
add_subdirectory(${OCKAM_THIRD_PARTY_DIR}/arm/mbed-crypto mbed-crypto)
