cmake_minimum_required(VERSION 3.13.4)
project(GSlab)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Hacker/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Victim/include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Output)

add_subdirectory(Hacker) # ()
add_subdirectory(Victim) # ()

add_custom_target( run_hacker
    ALL
    DEPENDS Hacker Victim
    COMMAND ./run_hacker.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)