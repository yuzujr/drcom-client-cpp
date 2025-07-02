cmake_minimum_required(VERSION 3.16)
project(drcom-client-cpp)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include(GNUInstallDirs)
add_subdirectory(src)
add_subdirectory(mock_server)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config DESTINATION ${CMAKE_INSTALL_PREFIX})