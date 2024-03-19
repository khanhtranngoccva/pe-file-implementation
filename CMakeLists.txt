cmake_minimum_required(VERSION 3.11)

project (PeFileImplementation)
file(GLOB_RECURSE SHARED_LIBRARIES "src/lib/*.cpp")

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

add_executable (pefile ${SHARED_LIBRARIES} src/pefile.cpp
        src/lib/pe/getters.cpp)
target_include_directories(pefile PRIVATE include)

add_executable (pefile-infector ${SHARED_LIBRARIES} src/pefile-infector.cpp)
target_include_directories(pefile-infector PRIVATE include)

add_executable (payload src/payload.cpp)
target_include_directories(payload PRIVATE include)
set_target_properties(payload PROPERTIES COMPILE_FLAGS "/c /FA /GS")