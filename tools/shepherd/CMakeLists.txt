cmake_minimum_required(VERSION 3.20)
project(shepherd LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        v1.3.3
)
FetchContent_GetProperties(minhook)
if (NOT minhook_POPULATED)
    FetchContent_Populate(minhook)
endif()

set(MINHOOK_SOURCES
    ${minhook_SOURCE_DIR}/src/buffer.c
    ${minhook_SOURCE_DIR}/src/hook.c
    ${minhook_SOURCE_DIR}/src/trampoline.c
    ${minhook_SOURCE_DIR}/src/hde/hde32.c
    ${minhook_SOURCE_DIR}/src/hde/hde64.c
)
add_library(minhook_static STATIC ${MINHOOK_SOURCES})
target_include_directories(minhook_static PUBLIC ${minhook_SOURCE_DIR}/include)
if (MSVC)
    target_compile_options(minhook_static PRIVATE /W0)
endif()

# Decide the output suffix based on arch.
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "64")
else()
    set(ARCH_SUFFIX "32")
endif()

# shepherd DLL for the current arch (shepherd64.dll or shepherd32.dll).
add_library(shepherd SHARED shepherd.cpp)
set_target_properties(shepherd PROPERTIES
    PREFIX ""
    OUTPUT_NAME "shepherd${ARCH_SUFFIX}"
    SUFFIX ".dll"
)
target_compile_definitions(shepherd PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_link_libraries(shepherd PRIVATE psapi advapi32 minhook_static)
if (MSVC)
    target_compile_options(shepherd PRIVATE /W3 /O2)
endif()

# inject helper exe (inject64.exe or inject32.exe).
add_executable(inject inject.cpp)
set_target_properties(inject PROPERTIES OUTPUT_NAME "inject${ARCH_SUFFIX}")
target_compile_definitions(inject PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
if (MSVC)
    target_compile_options(inject PRIVATE /W3 /O2)
    target_link_options(inject PRIVATE /SUBSYSTEM:CONSOLE)
endif()

# Watcher: x64 only (PlayGTAV is x64). Only built in the x64 pass.
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(watcher watcher.cpp)
    target_compile_definitions(watcher PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
    target_link_libraries(watcher PRIVATE psapi advapi32)
    if (MSVC)
        target_compile_options(watcher PRIVATE /W3 /O2)
        target_link_options(watcher PRIVATE /SUBSYSTEM:CONSOLE)
    endif()
endif()
