#include <iostream>
#include <vector>
#include <cstring>
#include <random>

// 跨平台网络支持
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    
    // Windows 兼容性定义
    typedef int socklen_t;
    #define close(s) closesocket(s)
    #define ssize_t int
    
    // 初始化和清理 Winsock
    class WinsockInitializer {
    public:
        WinsockInitializer() {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                throw std::runtime_error("Failed to initialize Winsock");
            }
        }
        ~WinsockInitializer() {
            WSACleanup();
        }
    };
    
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class MockDrcomServer {
private:
#ifdef _WIN32
    SOCKET socket_fd_;
#else
    int socket_fd_;
#endif
    struct sockaddr_in server_addr_;
    struct sockaddr_in client_addr_;
    socklen_t client_addr_len_;
    bool running_;
    
    // 模拟的服务器状态
    std::vector<uint8_t> challenge_salt_;
    std::vector<uint8_t> server_token_;
    bool client_authenticated_;
    
#ifdef _WIN32
    WinsockInitializer winsock_init_;
#endif
    
public:
    MockDrcomServer(int port = 61440) : running_(false), client_authenticated_(false) {
        // 初始化随机数生成器
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        // 生成随机的challenge salt
        challenge_salt_.resize(4);
        for (int i = 0; i < 4; i++) {
            challenge_salt_[i] = dis(gen);
        }
        
        // 生成随机的server token
        server_token_.resize(4);
        for (int i = 0; i < 4; i++) {
            server_token_[i] = dis(gen);
        }
        
        // 创建UDP socket
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
        if (socket_fd_ == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }
#else
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }
#endif
        
        // 设置socket选项
        int opt = 1;
        setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        // 绑定地址
        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin_family = AF_INET;
        server_addr_.sin_addr.s_addr = INADDR_ANY;
        server_addr_.sin_port = htons(port);
        
        if (bind(socket_fd_, (struct sockaddr*)&server_addr_, sizeof(server_addr_)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to bind socket");
        }
        
        std::cout << "Mock DRCOM Server listening on port " << port << std::endl;
    }
    
    ~MockDrcomServer() {
        stop();
#ifdef _WIN32
        if (socket_fd_ != INVALID_SOCKET) {
            close(socket_fd_);
        }
#else
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
#endif
    }
    
    void start() {
        running_ = true;
        run();
    }
    
    void stop() {
        running_ = false;
    }
    
private:
    void run() {
        uint8_t buffer[1024];
        client_addr_len_ = sizeof(client_addr_);
        
        while (running_) {
            ssize_t received = recvfrom(socket_fd_, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                                      (struct sockaddr*)&client_addr_, &client_addr_len_);
            
            if (received > 0) {
#ifdef _WIN32
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr_.sin_addr, addr_str, INET_ADDRSTRLEN);
                std::cout << "Received packet from " << addr_str
#else
                std::cout << "Received packet from " << inet_ntoa(client_addr_.sin_addr)
#endif
                         << ":" << ntohs(client_addr_.sin_port) 
                         << " (" << received << " bytes)" << std::endl;
                
                printPacket(buffer, received);
                handlePacket(buffer, received);
            }
        }
    }
    
    void handlePacket(const uint8_t* data, size_t len) {
        if (len < 1) return;
        
        uint8_t packet_type = data[0];
        
        switch (packet_type) {
            case 0x01: // Challenge request
                handleChallengeRequest(data, len);
                break;
            case 0x03: // Login request
                handleLoginRequest(data, len);
                break;
            case 0x06: // Logout request
                handleLogoutRequest(data, len);
                break;
            case 0xff: // Keep-alive auth request
                handleKeepAliveAuthRequest(data, len);
                break;
            case 0x07: // Keep-alive heartbeat request
                handleKeepAliveHeartbeatRequest(data, len);
                break;
            default:
                std::cout << "Unknown packet type: 0x" << std::hex << (int)packet_type << std::endl;
                break;
        }
    }
    
    void handleChallengeRequest(const uint8_t* /*data*/, size_t /*len*/) {
        std::cout << "Handling Challenge Request" << std::endl;
        
        // 构建Challenge响应
        std::vector<uint8_t> response;
        response.push_back(0x02); // Challenge response type
        response.push_back(0x00); // Success code
        response.push_back(0x00); // Reserved
        response.push_back(0x00); // Reserved
        
        // 添加challenge salt
        response.insert(response.end(), challenge_salt_.begin(), challenge_salt_.end());
        
        // 填充到标准长度
        while (response.size() < 76) {
            response.push_back(0x00);
        }
        
        sendResponse(response);
    }
    
    void handleLoginRequest(const uint8_t* /*data*/, size_t /*len*/) {
        std::cout << "Handling Login Request" << std::endl;
        
        // 简单验证（实际应该验证用户名密码）
        client_authenticated_ = true;
        
        // 构建Login响应
        std::vector<uint8_t> response;
        response.push_back(0x04); // Login response type
        response.push_back(0x00); // Success code
        response.push_back(0x00); // Reserved
        response.push_back(0x00); // Reserved
        
        // 添加server token
        response.insert(response.end(), server_token_.begin(), server_token_.end());
        
        // 填充到至少39字节以满足客户端要求
        while (response.size() < 39) {
            response.push_back(0x00);
        }
        
        // 添加server drcom indicator (从字节23-38，共16字节)
        for (int i = 0; i < 16; i++) {
            response[23 + i] = 0x20 + i; // 一些测试数据
        }
        
        sendResponse(response);
        std::cout << "Client authenticated successfully!" << std::endl;
    }
    
    void handleLogoutRequest(const uint8_t* /*data*/, size_t /*len*/) {
        std::cout << "Handling Logout Request" << std::endl;
        
        client_authenticated_ = false;
        
        // 构建Logout响应
        std::vector<uint8_t> response;
        response.push_back(0x05); // Logout response type
        response.push_back(0x00); // Success code
        
        // 填充到标准长度
        while (response.size() < 16) {
            response.push_back(0x00);
        }
        
        sendResponse(response);
        std::cout << "Client logged out" << std::endl;
    }
    
    void handleKeepAliveAuthRequest(const uint8_t* data, size_t len) {
        std::cout << "Handling Keep-Alive Auth Request" << std::endl;
        
        if (!client_authenticated_) {
            std::cout << "Client not authenticated, ignoring keep-alive" << std::endl;
            return;
        }
        
        // 构建Keep-alive auth响应
        std::vector<uint8_t> response;
        response.push_back(0xff); // Keep-alive auth response type
        response.push_back(0x00); // Success code
        
        // 复制原始数据的部分内容作为响应
        if (len > 2) {
            response.insert(response.end(), data + 2, data + std::min(len, size_t(16)));
        }
        
        // 填充到标准长度
        while (response.size() < 16) {
            response.push_back(0x00);
        }
        
        sendResponse(response);
    }
    
    void handleKeepAliveHeartbeatRequest(const uint8_t* data, size_t len) {
        std::cout << "Handling Keep-Alive Heartbeat Request" << std::endl;
        
        if (!client_authenticated_) {
            std::cout << "Client not authenticated, ignoring heartbeat" << std::endl;
            return;
        }
        
        // 构建Keep-alive heartbeat响应
        std::vector<uint8_t> response;
        response.push_back(0x07); // Keep-alive heartbeat response type
        response.push_back(0x00); // Success code
        
        // 复制原始数据的部分内容作为响应
        if (len > 2) {
            response.insert(response.end(), data + 2, data + std::min(len, size_t(40)));
        }
        
        // 填充到标准长度
        while (response.size() < 40) {
            response.push_back(0x00);
        }
        
        sendResponse(response);
    }
    
    void sendResponse(const std::vector<uint8_t>& response) {
        ssize_t sent = sendto(socket_fd_, reinterpret_cast<const char*>(response.data()), response.size(), 0,
                            (struct sockaddr*)&client_addr_, client_addr_len_);
        
        if (sent > 0) {
            std::cout << "Sent response (" << sent << " bytes)" << std::endl;
            printPacket(response.data(), sent);
        } else {
            std::cout << "Failed to send response" << std::endl;
        }
    }
    
    void printPacket(const uint8_t* data, size_t len) {
        std::cout << "Packet data: ";
        for (size_t i = 0; i < len && i < 32; i++) {
#ifdef _WIN32
            printf("%02x ", (unsigned char)data[i]);
#else
            printf("%02x ", data[i]);
#endif
        }
        if (len > 32) {
            std::cout << "...";
        }
        std::cout << std::endl;
    }
};

int main(int argc, char* argv[]) {
    int port = 61440;
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }
    
    try {
        MockDrcomServer server(port);
        
        std::cout << "Starting Mock DRCOM Server..." << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
