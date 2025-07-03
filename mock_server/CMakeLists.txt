add_executable(mock_drcom_server
    mock_drcom_server.cpp
)

if(WIN32)
    target_link_libraries(mock_drcom_server ws2_32)
endif()

install(TARGETS mock_drcom_server
    RUNTIME DESTINATION ${DRCOM_INSTALL_DIR}/bin
)
