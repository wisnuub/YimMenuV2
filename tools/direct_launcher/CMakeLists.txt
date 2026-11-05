cmake_minimum_required(VERSION 3.20)
project(direct_launcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(launcher launcher.cpp)
target_compile_definitions(launcher PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
if (MSVC)
    target_compile_options(launcher PRIVATE /W3 /O2)
    target_link_options(launcher PRIVATE /SUBSYSTEM:CONSOLE)
endif()
