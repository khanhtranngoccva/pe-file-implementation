cmake_minimum_required(VERSION 3.11)

set(TARGET_NAME PeFileImplementation)

file(GLOB SOURCES "src/*.cpp")
add_executable (PeFileImplementation ${SOURCES})

project (${TARGET_NAME})

target_include_directories(${TARGET_NAME} PRIVATE include)