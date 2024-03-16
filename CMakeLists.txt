cmake_minimum_required(VERSION 3.11)

project (PeFileImplementation)
file(GLOB SOURCES "src/*.cpp")

set(TARGET_NAME pefile)
add_executable (${TARGET_NAME} ${SOURCES}
        include/windows-constants.h)
target_include_directories(${TARGET_NAME} PRIVATE include)