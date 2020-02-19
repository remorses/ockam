list(APPEND OCKAM_COMMON_INCLUDE_DIRS
  ${OCKAM_THIRD_PARTY_DIR}/infineon/optiga-trust-x/optiga/include
)

add_subdirectory(${OCKAM_THIRD_PARTY_DIR}/infineon optiga-trust-x)
