cmake_minimum_required(VERSION 3.11)

project (PeFileImplementation)
file(GLOB SOURCES "src/*.cpp")

set(TARGET_NAME pefile)
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

add_executable (${TARGET_NAME} ${SOURCES})
target_include_directories(${TARGET_NAME} PRIVATE include)