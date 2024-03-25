cmake_minimum_required(VERSION 3.14)
project (PeFileImplementation)
set(CMAKE_CXX_STANDARD 17)

# fetch latest argparse
include(FetchContent)
FetchContent_Declare(
        argparse
        GIT_REPOSITORY https://github.com/p-ranav/argparse.git
)
FetchContent_MakeAvailable(argparse)

file(GLOB_RECURSE SHARED_LIBRARIES "src/lib/*.cpp")

add_executable (pefile ${SHARED_LIBRARIES} src/pefile.cpp)
target_link_libraries(pefile argparse)
target_include_directories(pefile PRIVATE include)

add_executable (pefile-infector ${SHARED_LIBRARIES} src/pefile-infector.cpp)
target_link_libraries(pefile-infector argparse)
target_include_directories(pefile-infector PRIVATE include)

add_executable (pefile-oep-stager ${SHARED_LIBRARIES} src/pefile-oep-stager.cpp)
target_link_libraries(pefile-oep-stager argparse)
target_include_directories(pefile-oep-stager PRIVATE include)

add_executable (payload payload/src/payload.cpp)
target_include_directories(payload PRIVATE payload)

add_executable (target src/target.cpp)