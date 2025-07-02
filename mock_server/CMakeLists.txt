# 模拟drcom服务器
add_executable(mock_drcom_server
    mock_drcom_server.cpp
)

# 安装
install(TARGETS mock_drcom_server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
