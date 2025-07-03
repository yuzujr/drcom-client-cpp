add_executable(mock_drcom_server
    mock_drcom_server.cpp
)

install(TARGETS mock_drcom_server
    RUNTIME DESTINATION ${DRCOM_INSTALL_DIR}/bin
)
