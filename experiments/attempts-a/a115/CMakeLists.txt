cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

project(a115_bgv_context_envelope LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The official v2.3.0 tag still exports PACKAGE_VERSION=2.2.0 from its VERSION
# file. The exact source commit is pinned separately by the A115 gate.
find_package(helib 2.2.0 EXACT REQUIRED)

add_executable(a115_bgv_context_envelope src/main.cpp)
target_link_libraries(a115_bgv_context_envelope PRIVATE helib)
target_compile_options(a115_bgv_context_envelope PRIVATE -Wall -Wextra -Wpedantic)
