cmake_minimum_required(VERSION 3.16)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" DRCOM_PROJECT_VERSION)
string(STRIP "${DRCOM_PROJECT_VERSION}" DRCOM_PROJECT_VERSION)

project(drcom-client-cpp VERSION ${DRCOM_PROJECT_VERSION})

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

# 设置自定义安装目录
set(DRCOM_INSTALL_DIR "drcom-client-cpp")

add_subdirectory(src)
add_subdirectory(mock_server)

# 安装配置文件到自定义目录
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config 
        DESTINATION ${DRCOM_INSTALL_DIR})

if(WIN32)
    install(FILES ${CMAKE_SOURCE_DIR}/scripts/windows-autostart.ps1
            DESTINATION ${DRCOM_INSTALL_DIR}/bin)
endif()

include(CTest)
if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(network_selection_tests tests/network_selection.cpp src/network.cpp)
    target_include_directories(network_selection_tests PRIVATE src/include)
    add_test(NAME network_selection COMMAND network_selection_tests)
endif()
