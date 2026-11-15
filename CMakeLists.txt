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
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Instrument the core and every executable, including integration tests.
set(DRCOM_SANITIZERS "" CACHE STRING "Compiler sanitizers, e.g. address,undefined or thread")
option(DRCOM_BUILD_FUZZERS "Build Clang libFuzzer configuration/crypto harnesses" OFF)
if(DRCOM_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "DRCOM_BUILD_FUZZERS requires Clang")
    endif()
    if(NOT DRCOM_SANITIZERS)
        set(DRCOM_SANITIZERS "address,undefined")
    endif()
endif()
if(DRCOM_SANITIZERS)
    if(MSVC OR NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "DRCOM_SANITIZERS requires GCC or Clang on a supported platform")
    endif()
    add_compile_options(-fsanitize=${DRCOM_SANITIZERS} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${DRCOM_SANITIZERS})
endif()

include(GNUInstallDirs)

add_subdirectory(src)
add_subdirectory(mock_server)

# 安装配置文件到自定义目录
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config 
        DESTINATION ${CMAKE_INSTALL_DATADIR}/drcom-client-cpp)

if(WIN32)
    install(FILES ${CMAKE_SOURCE_DIR}/scripts/windows-autostart.ps1
            DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(FILES README.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs DESTINATION ${CMAKE_INSTALL_DOCDIR})

include(CTest)
if(BUILD_TESTING)
    add_executable(protocol_vectors tests/protocol_vectors.cpp)
    target_link_libraries(protocol_vectors PRIVATE drcom_core)
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME protocol_oracle COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/protocol_oracle.py $<TARGET_FILE:protocol_vectors>)
        add_test(NAME fault_recovery COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/fault_recovery.py $<TARGET_FILE:drcom_client>)
        set_tests_properties(fault_recovery PROPERTIES TIMEOUT 60 LABELS integration)
    endif()
    if(UNIX)
        add_test(NAME runtime_control COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/runtime_control.py $<TARGET_FILE:drcom_client>
            $<TARGET_FILE:mock_drcom_server>)
        add_test(NAME delayed_keepalive COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/tests/delayed_keepalive.py $<TARGET_FILE:drcom_client>
            $<TARGET_FILE:mock_drcom_server>)
        set_tests_properties(runtime_control delayed_keepalive
            PROPERTIES TIMEOUT 90 LABELS integration)
    endif()
    add_executable(logging_tests tests/logging.cpp)
    target_link_libraries(logging_tests PRIVATE drcom_core)
    add_test(NAME logging COMMAND logging_tests)
    add_executable(runtime_status_tests tests/runtime_status.cpp)
    target_link_libraries(runtime_status_tests PRIVATE drcom_core)
    add_test(NAME runtime_status COMMAND runtime_status_tests)
    add_test(NAME runtime_soak COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tests/runtime_soak.py $<TARGET_FILE:drcom_client> --cycles 20)
    set_tests_properties(runtime_soak PROPERTIES TIMEOUT 90 LABELS integration)
    add_executable(config_tests tests/config.cpp)
    target_link_libraries(config_tests PRIVATE drcom_core)
    add_test(NAME configuration COMMAND config_tests)
endif()
if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(network_selection_tests tests/network_selection.cpp)
    target_link_libraries(network_selection_tests PRIVATE drcom_core)
    add_test(NAME network_selection COMMAND network_selection_tests)
endif()

if(DRCOM_BUILD_FUZZERS)
    target_compile_options(drcom_core PRIVATE -fsanitize=fuzzer-no-link)
    foreach(harness config crypto)
        add_executable(fuzz_${harness} tests/fuzz_${harness}.cpp)
        target_link_libraries(fuzz_${harness} PRIVATE drcom_core)
        target_compile_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()
