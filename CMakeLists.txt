cmake_minimum_required(VERSION 3.11)

project (PeFileImplementation)
file(GLOB_RECURSE SHARED_LIBRARIES "src/lib/*.cpp")

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

add_executable (pefile ${SHARED_LIBRARIES} src/pefile.cpp)
target_include_directories(pefile PRIVATE include)

add_executable (pefile-infector ${SHARED_LIBRARIES} src/pefile-infector.cpp)
target_include_directories(pefile-infector PRIVATE include)

add_executable (pefile-oep-stager ${SHARED_LIBRARIES} src/pefile-oep-stager.cpp)
target_include_directories(pefile-oep-stager PRIVATE include)

add_executable (payload payload/src/payload.cpp)
target_include_directories(payload PRIVATE payload)

add_executable (target src/target.cpp)