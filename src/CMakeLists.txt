cmake_minimum_required(VERSION 3.10)
project(GatherScatterPrinter)

# Set CMake policies
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# List of valid build types
set(VALID_BUILD_TYPES Debug Release RelWithDebInfo MinSizeRel)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'Release' as no build type was specified")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Add warnings for debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wuninitialized -Wunused -Wshadow -Wconversion")
    message(STATUS "Building in debug mode")
endif()

# Check if the provided CMAKE_BUILD_TYPE is in the valid list
if(NOT CMAKE_BUILD_TYPE IN_LIST VALID_BUILD_TYPES)
    message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}. Valid options are: ${VALID_BUILD_TYPES}")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Find DynamoRIO
find_package(DynamoRIO REQUIRED)

set(LIBRARY_NAME "gatherscatter_printer")

# Add the source file to the build
add_library(${LIBRARY_NAME} MODULE
    gatherscatter_printer.c
)

# Configure DynamoRIO client
configure_DynamoRIO_client(${LIBRARY_NAME})
use_DynamoRIO_extension(${LIBRARY_NAME} drmgr)
use_DynamoRIO_extension(${LIBRARY_NAME} drreg)
use_DynamoRIO_extension(${LIBRARY_NAME} drutil)
use_DynamoRIO_extension(${LIBRARY_NAME} drx)

# Install the library
install(TARGETS ${LIBRARY_NAME}
    DESTINATION lib
)
