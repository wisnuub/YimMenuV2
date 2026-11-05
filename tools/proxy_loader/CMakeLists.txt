cmake_minimum_required(VERSION 3.20)
project(version_proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(version SHARED version.cpp)
set_target_properties(version PROPERTIES
    PREFIX ""
    OUTPUT_NAME "version"
    SUFFIX ".dll"
)
target_compile_definitions(version PRIVATE WIN32_LEAN_AND_MEAN)
if (MSVC)
    target_compile_options(version PRIVATE /W3 /O2)
    target_link_options(version PRIVATE /SUBSYSTEM:WINDOWS)
endif()
