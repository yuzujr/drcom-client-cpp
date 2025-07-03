file(GLOB_RECURSE SOURCE_FILES "*.cpp")

add_executable(drcom_client ${SOURCE_FILES})

target_include_directories(drcom_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

install(TARGETS drcom_client
    RUNTIME DESTINATION ${DRCOM_INSTALL_DIR}/bin
)