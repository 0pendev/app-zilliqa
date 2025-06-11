
include_guard()
cmake_minimum_required(VERSION 3.14)

if(${CMAKE_VERSION} VERSION_LESS 3.14)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(
  ZiliqaFuzzer
  VERSION 1.0
  DESCRIPTION "App Boilerplate ziliqa Fuzzer"
  LANGUAGES C)

set(DEFINES FUZZ)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
else()
  message(${BOLOS_SDK})
endif()

add_subdirectory(${BOLOS_SDK}/fuzzing ${CMAKE_CURRENT_BINARY_DIR}/ledger-secure-sdk EXCLUDE_FROM_ALL)

file(
  GLOB_RECURSE C_SOURCES
  "${CMAKE_SOURCE_DIR}/../src/*.c"
)
add_library(ziliqa ${C_SOURCES})

target_include_directories(ziliqa PUBLIC
  ${CMAKE_SOURCE_DIR}/../src
  ${CMAKE_SOURCE_DIR}/../src/apdu
  ${CMAKE_SOURCE_DIR}/../src/swap
  ${CMAKE_SOURCE_DIR}/../src/handler
  ${CMAKE_SOURCE_DIR}/../src/helper
  ${CMAKE_SOURCE_DIR}/../src/transaction
  ${CMAKE_SOURCE_DIR}/../src/ui
  ${CMAKE_SOURCE_DIR}/../src/ui/action
)
target_link_libraries(ziliqa PUBLIC
  secure_sdk
  bsd
)
target_compile_definitions(ziliqa PUBLIC
  ${DEFINES}
  FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
)
target_link_options(ziliqa PUBLIC ${LINK_FLAGS})
target_compile_options(ziliqa PUBLIC ${COMPILATION_FLAGS} -Wno-implicit-function-declaration -Wno-unused-but-set-variable -Wno-unused-parameter -g)

# fuzz_handlerfn
add_executable(fuzz_handlerfn
  "${CMAKE_SOURCE_DIR}/fuzz_handlerfn.c"
  "${CMAKE_SOURCE_DIR}/mock/mocks.c"
)

target_compile_definitions(fuzz_handlerfn PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
target_compile_options(fuzz_handlerfn PUBLIC ${COMPILATION_FLAGS})
target_link_options(fuzz_handlerfn PUBLIC -Wl,--undefined=lookupHandler ${LINK_FLAGS})
target_link_libraries(fuzz_handlerfn PUBLIC ziliqa mock)
