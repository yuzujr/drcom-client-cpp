file(GLOB_RECURSE SOURCE_FILES "*.cpp")

if(WIN32)
add_executable(drcom_client WIN32 ${SOURCE_FILES})
else()
add_executable(drcom_client ${SOURCE_FILES})
endif()

target_include_directories(drcom_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(drcom_client ws2_32)
endif()

install(TARGETS drcom_client
    RUNTIME DESTINATION ${DRCOM_INSTALL_DIR}/bin
)