cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

project(a117_bgv_p8191_lt_gate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(A117_ACK_ISOLATED_BUILD "Acknowledge that the build directory is disposable and isolated" OFF)
option(A117_ACK_LOAD_LE_24 "Acknowledge that the measured one-minute load is <=24" OFF)
option(A117_ACK_ONE_JOB "Acknowledge that compilation will use exactly one job" OFF)

if(NOT A117_ACK_ISOLATED_BUILD OR NOT A117_ACK_LOAD_LE_24 OR NOT A117_ACK_ONE_JOB)
  message(FATAL_ERROR
    "A117 configure refused: pass all three explicit A117_ACK_* acknowledgements")
endif()

set(A117_COMPARISON_SOURCE_DIR "" CACHE PATH
    "Detached checkout of comparison-circuit-over-fq at the pinned commit")
if(NOT IS_DIRECTORY "${A117_COMPARISON_SOURCE_DIR}/code")
  message(FATAL_ERROR "A117_COMPARISON_SOURCE_DIR must contain the pinned code/ tree")
endif()

# These hashes bind the inputs even if the checkout's branch or metadata drifts.
file(SHA256 "${A117_COMPARISON_SOURCE_DIR}/code/comparator.cpp" A117_COMPARATOR_SHA256)
file(SHA256 "${A117_COMPARISON_SOURCE_DIR}/code/comparator.h" A117_COMPARATOR_H_SHA256)
file(SHA256 "${A117_COMPARISON_SOURCE_DIR}/code/tools.cpp" A117_TOOLS_SHA256)
file(SHA256 "${A117_COMPARISON_SOURCE_DIR}/code/tools.h" A117_TOOLS_H_SHA256)
if(NOT A117_COMPARATOR_SHA256 STREQUAL
   "fcf21ec5ca4b712e330d04566575299352608b13f7bdb26290cbc4b07f278d6d")
  message(FATAL_ERROR "Pinned upstream comparator.cpp hash mismatch")
endif()
if(NOT A117_COMPARATOR_H_SHA256 STREQUAL
   "f39a2544e7cfdb9eb6d0ff7f1a4f176d184767d19dd948ac273119674d47c226")
  message(FATAL_ERROR "Pinned upstream comparator.h hash mismatch")
endif()
if(NOT A117_TOOLS_SHA256 STREQUAL
   "7ffefa8782ae5b1ec4f241da26a9bb1dddf6e058846ac8637964ee42634fbf4e")
  message(FATAL_ERROR "Pinned upstream tools.cpp hash mismatch")
endif()
if(NOT A117_TOOLS_H_SHA256 STREQUAL
   "88c750444bccf93e2d8e02d4e42d0e263dac230d820f5f8e508ece43b68290cb")
  message(FATAL_ERROR "Pinned upstream tools.h hash mismatch")
endif()

# HElib v2.3.0's pinned source commit still exports package version 2.2.0.
find_package(helib 2.2.0 EXACT REQUIRED)
find_program(A117_PATCH_EXECUTABLE patch REQUIRED)

# Materialize the one-file adaptation in the disposable build tree. The
# detached upstream checkout remains byte-for-byte unchanged.
set(A117_PATCHED_COMPARATOR "${CMAKE_CURRENT_BINARY_DIR}/comparator_a117.cpp")
execute_process(
  COMMAND "${A117_PATCH_EXECUTABLE}" --batch --forward
          -o "${A117_PATCHED_COMPARATOR}"
          "${A117_COMPARISON_SOURCE_DIR}/code/comparator.cpp"
          "${CMAKE_CURRENT_SOURCE_DIR}/patches/0001-fast-create-poly.patch"
  RESULT_VARIABLE A117_PATCH_STATUS
  OUTPUT_VARIABLE A117_PATCH_STDOUT
  ERROR_VARIABLE A117_PATCH_STDERR)
if(NOT A117_PATCH_STATUS EQUAL 0)
  message(FATAL_ERROR
    "Could not materialize the pinned A117 comparator adaptation:\n"
    "${A117_PATCH_STDOUT}\n${A117_PATCH_STDERR}")
endif()

add_executable(a117_bgv_p8191_lt_gate
  src/main.cpp
  "${A117_PATCHED_COMPARATOR}"
  "${A117_COMPARISON_SOURCE_DIR}/code/tools.cpp")
target_include_directories(a117_bgv_p8191_lt_gate PRIVATE
  src
  "${A117_COMPARISON_SOURCE_DIR}/code")
target_link_libraries(a117_bgv_p8191_lt_gate PRIVATE helib)
target_compile_options(a117_bgv_p8191_lt_gate PRIVATE
  -Wall -Wextra -Wpedantic)
