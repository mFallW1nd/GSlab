project(Hacker)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Hook/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Inject/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Utils/include)
add_subdirectory(Hook)
add_subdirectory(Inject)
add_subdirectory(Utils)

add_library( hacker SHARED Lib/src/libhacker/libhacker.cpp)

add_executable(Hacker Exec/src/hacker.cpp Inject/src/my_inject.cpp Inject/src/ptrace_inject.cpp Utils/src/utils.cpp)
find_library(log-lib log)
target_link_libraries(Hacker ${log-lib})