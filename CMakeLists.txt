cmake_minimum_required(VERSION 3.6...3.10)

# Define the project
project(ctd CXX)

# Import our local cmake Modules (if any)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

# If build type is not specified, it defaults to Debug. Set build type explicitly
# with -DCMAKE_BUILD_TYPE=<type> where <type> is one of: Debug, Release or RelWithDebInfo
if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "Build type defaulting to Debug. Change to Relese or RelWithDebInfo with -DCMAKE_BUILD_TYPE=<choise>")
    set(CTD_TMP_BUILD_TYPE "Debug")
else()
    set(CTD_TMP_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
endif()
set(CMAKE_BUILD_TYPE "${CTD_TMP_BUILD_TYPE}" CACHE STRING "Choose the type of build. Options are: Debug, Release or RelWithDebInfo" FORCE)

# We use the PkgConfig cmake module to be able to find libraries we depend on
find_package(PkgConfig REQUIRED)

# We use GNUInstallDirs to get standard install directories for include, lib, bin and so on
include(GNUInstallDirs)

# Create a uninstall target if it does not already exist. We need this before
# any add_subdirectory so that uninstall targets from them do not propagate here
if(NOT TARGET uninstall)
    configure_file("${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" @ONLY)
    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# Define the target for our program
add_executable(ctd src/ctd.cpp src/config_parser.cpp)

# Add compile and link options to our target
target_compile_options(ctd PRIVATE -std=gnu++17)
target_compile_options(ctd PRIVATE -Wall)
target_compile_options(ctd PRIVATE -Wextra)
target_compile_options(ctd PRIVATE -pedantic)
#target_compile_options(ctd PRIVATE -pg)
#target_link_options(ctd PRIVATE -pg)

# We use threads
find_package(Threads REQUIRED)
target_link_libraries(ctd Threads::Threads)

# Add argparse submodule to the include paths (argparse is include only)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/argparse/include)

# Add spdlog submodule to the include paths (we use spdlog as include only)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/spdlog/include)

# Add cpp-httplig submodule to the include paths (cpp-httpdlib is include only)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/cpp-httplib)

# Add nlohmann/json submodule to the include paths (nlohmann/json is include only)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/json/include)

# Add ashtum/lazycsv submodule to the include paths (ashtum/lazycsv is include only)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/lazycsv/include)

# Add yaml-cpp as a static submodule (.a)
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE) # Needed to silence 3.4 version warning
add_subdirectory(yaml-cpp EXCLUDE_FROM_ALL)
target_include_directories(ctd PRIVATE ${PROJECT_SOURCE_DIR}/yaml-cpp/include)
target_link_libraries(ctd yaml-cpp)

set(CTD_USING_OPENSSL "No")
message(STATUS "Checking for openssl...")
pkg_check_modules(OPENSSL QUIET openssl)
if(OPENSSL_FOUND)
    message(STATUS "openssl version ${OPENSSL_VERSION} found.")
    if(OPENSSL_VERSION VERSION_LESS "3.0.0")
        message(STATUS "openssl version is to old. Version 3.0.0 or above is required. TLS support will not be compiled in.")
    else()
        message(STATUS "TLS support will be compiled in.")
        set(CTD_USING_OPENSSL "Yes")
        add_definitions(-DCPPHTTPLIB_OPENSSL_SUPPORT)
        target_include_directories(ctd PRIVATE ${OPENSSL_INCLUDE_DIRS})
        target_link_directories(ctd PRIVATE ${OPENSSL_LIBRARY_DIRS})
        target_link_libraries(ctd ${OPENSSL_LIBRARIES})
    endif()
else()
    message(STATUS "openssl not found. TLS support will not be compiled in.")
endif()

# Add support for installing our program
install(TARGETS ctd RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

# Create empty install_manifest.txt so that it does not get owned by root on sudo make install
execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")

# Dump our config for review
message(STATUS "The following build options will be used for ctd:")
message(STATUS "    CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
message(STATUS "    CTD_USING_OPENSSL=${CTD_USING_OPENSSL}")
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
