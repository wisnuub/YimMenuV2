cmake_minimum_required(VERSION 3.20)
project(shepherd LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# shepherd.dll — the DLL injected into each process in the launch chain
add_library(shepherd SHARED shepherd.cpp)
set_target_properties(shepherd PROPERTIES PREFIX "" OUTPUT_NAME "shepherd" SUFFIX ".dll")
target_compile_definitions(shepherd PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_link_libraries(shepherd PRIVATE psapi advapi32)
if (MSVC)
    target_compile_options(shepherd PRIVATE /W3 /O2)
endif()

# watcher.exe — the initial injector that races against BEDaisy
add_executable(watcher watcher.cpp)
target_compile_definitions(watcher PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_link_libraries(watcher PRIVATE psapi advapi32)
if (MSVC)
    target_compile_options(watcher PRIVATE /W3 /O2)
    target_link_options(watcher PRIVATE /SUBSYSTEM:CONSOLE)
endif()
