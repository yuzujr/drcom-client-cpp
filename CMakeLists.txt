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

# 设置自定义安装目录
set(DRCOM_INSTALL_DIR "drcom-client-cpp")

add_subdirectory(src)
add_subdirectory(mock_server)

# 安装配置文件到自定义目录
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config 
        DESTINATION ${DRCOM_INSTALL_DIR})