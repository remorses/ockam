if (NOT ${OCKAM_BUILD_TESTS})
  return()
endif()

include(FetchContent)

FetchContent_Declare(cmocka
  GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
  GIT_TAG cmocka-1.1.5
)

FetchContent_GetProperties(cmocka)
if(NOT cmocka_POPULATED)
  FetchContent_Populate(cmocka
    QUIET
    SOURCE_DIR "${OCKAM_THIRD_PARTY_DIR}/cmocka"
  )

  add_subdirectory(${cmocka_SOURCE_DIR} ${cmocka_BINARY_DIR})

  set(CMOCKA_INCLUDE_DIRS "${cmocka_SOURCE_DIR}/include")
endif()
