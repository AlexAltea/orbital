# Copyright 2020. Alexandro Sanchez Bach.

cmake_minimum_required(VERSION 3.12)

# Version
set(ORBITAL_VERSION_MAJOR 0)
set(ORBITAL_VERSION_MINOR 1)
set(ORBITAL_VERSION_PATCH 0)

# Directories
set(ORBITAL_DIR_ROOT       ${CMAKE_CURRENT_LIST_DIR})
set(ORBITAL_DIR_CMAKE      "${ORBITAL_DIR_ROOT}/cmake")
set(ORBITAL_DIR_EXTERNALS  "${ORBITAL_DIR_ROOT}/externals")
set(ORBITAL_DIR_SOURCES    "${ORBITAL_DIR_ROOT}/src")

# Project
project(orbital CXX)

# Dependencies
find_package(SDL2 REQUIRED)

# Sources
macro(ORBITAL_FILES_APPEND)
    file(GLOB FILES_APPEND CONFIGURE_DEPENDS ${ARGV})
    list(APPEND ORBITAL_SOURCES ${FILES_APPEND})
endmacro()
macro(ORBITAL_SOURCES_APPEND)
    ORBITAL_FILES_APPEND(${ARGV0}/*.h)
    ORBITAL_FILES_APPEND(${ARGV0}/*.cpp)
endmacro()

ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/analysis)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/analysis/orbis)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/hardware)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/hardware/aeolia)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/hardware/liverpool)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/software)
ORBITAL_SOURCES_APPEND(${ORBITAL_DIR_SOURCES}/orbital/software/sbl)

# Target
add_executable(orbital ${ORBITAL_SOURCES})
target_include_directories(orbital PUBLIC ${ORBITAL_DIR_EXTERNALS})
target_include_directories(orbital PUBLIC ${ORBITAL_DIR_SOURCES})
target_link_libraries(orbital PRIVATE SDL2::SDL2 SDL2::SDL2main)
include(${ORBITAL_DIR_EXTERNALS}/core.cmake)

# Properties
set_target_properties(orbital PROPERTIES CXX_STANDARD 20)
set_target_properties(orbital PROPERTIES CXX_STANDARD_REQUIRED ON)
set_target_properties(orbital PROPERTIES POSITION_INDEPENDENT_CODE 1)
