cmake_minimum_required(VERSION 2.8.12...3.10)

# Define the project
project(ctd CXX)

# Import our local cmake Modules (if any)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

# We require a compiler with support for at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# If build type is not specified, it defaults to Debug. Set build type explicitly
# with -DCMAKE_BUILD_TYPE=<type> where <type> is one of: Debug, Release or RelWithDebInfo
if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "Build type defaulting to Debug. Change to Relese or RelWithDebInfo with -DCMAKE_BUILD_TYPE=<choise>")
    set(CTD_TMP_BUILD_TYPE "Debug")
else()
   set(CTD_TMP_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
endif ()
set(CMAKE_BUILD_TYPE "${CTD_TMP_BUILD_TYPE}" CACHE STRING "Choose the type of build. Options are: Debug, Release or RelWithDebInfo" FORCE)

# We need the PkgConfig cmake module to be able to find libraries we depend on
find_package(PkgConfig REQUIRED)

# Use GNUInstallDirs to get standard install directories for include, lib, bin and so on
include(GNUInstallDirs)

# Create a uninstall target if it does not already exist. We need this before
# any add_subdirectory so that uninstall targets from them do not propagate here
if(NOT TARGET uninstall)
    configure_file("${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" @ONLY)
    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# Define a target for our program
add_executable(ctd src/ctd.cpp)

# Add compile and link options to our target. We differentiate between gcc and clang
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_VERSION VERSION_LESS "3.1")
        target_compile_options(ctd PRIVATE -std=gnu++${CMAKE_CXX_STANDARD})
    endif()
    target_compile_options(ctd PRIVATE -Wall)
    target_compile_options(ctd PRIVATE -Wextra)
    target_compile_options(ctd PRIVATE -pedantic)
    #target_compile_options(ctd PRIVATE -pg)
    #target_link_options(ctd PRIVATE -pg)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(CMAKE_VERSION VERSION_LESS "3.1")
        target_compile_options(ctd PRIVATE -std=gnu++${CMAKE_CXX_STANDARD})
    endif()
    target_compile_options(ctd PRIVATE -Wall)
    target_compile_options(ctd PRIVATE -Wextra)
    target_compile_options(ctd PRIVATE -Wpedantic)
else()
endif()

# Add support for installing our program
install(TARGETS ctd RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

# Create empty install_manifest.txt so that it does not get owned by root on sudo make install
execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")

# Dump our config for review
message(STATUS "The following build options will be used for ctd:")
message(STATUS "    CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
message(STATUS "    CMAKE_CXX_COMPILER_ID=${CMAKE_CXX_COMPILER_ID}")
message(STATUS "    CMAKE_CXX_COMPILER_VERSION=${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "    CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}")
message(STATUS "    CMAKE_INSTALL_FULL_INCLUDEDIR=${CMAKE_INSTALL_FULL_INCLUDEDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_LIBDIR=${CMAKE_INSTALL_FULL_LIBDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_BINDIR=${CMAKE_INSTALL_FULL_BINDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_SYSCONFDIR=${CMAKE_INSTALL_FULL_SYSCONFDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_DATAROOTDIR=${CMAKE_INSTALL_FULL_DATAROOTDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_LOCALSTATEDIR=${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")
message(STATUS "    CMAKE_INSTALL_FULL_DOCDIR=${CMAKE_INSTALL_FULL_DOCDIR}")
