#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using socket_t = SOCKET;
    constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    using socket_t = int;
    constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

namespace drcom {

/**
 * @brief Network address structure
 */
struct NetworkAddress {
    std::string ip;
    uint16_t port;
    
    NetworkAddress() = default;
    NetworkAddress(std::string ip_addr, uint16_t port_num) 
        : ip(std::move(ip_addr)), port(port_num) {}
};

/**
 * @brief Cross-platform UDP socket wrapper
 * 
 * This class provides a cross-platform abstraction over UDP sockets,
 * handling the differences between Windows Winsock and POSIX sockets.
 */
class UdpSocket {
public:
    UdpSocket();
    ~UdpSocket();
    
    // Non-copyable but movable
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;
    
    /**
     * @brief Bind socket to local address
     * @param address Local address to bind to
     * @return std::error_code indicating success or failure
     */
    std::error_code bind(const NetworkAddress& address);
    
    /**
     * @brief Connect to remote address
     * @param address Remote address to connect to
     * @return std::error_code indicating success or failure
     */
    std::error_code connect(const NetworkAddress& address);
    
    /**
     * @brief Send data to connected address
     * @param data Data to send
     * @return Number of bytes sent or error code
     */
    std::pair<size_t, std::error_code> send(const std::vector<uint8_t>& data);
    
    /**
     * @brief Send data to specific address
     * @param data Data to send
     * @param address Destination address
     * @return Number of bytes sent or error code
     */
    std::pair<size_t, std::error_code> sendTo(const std::vector<uint8_t>& data, 
                                             const NetworkAddress& address);
    
    /**
     * @brief Receive data from connected address
     * @param buffer Buffer to receive data into
     * @param max_size Maximum bytes to receive
     * @return Number of bytes received or error code
     */
    std::pair<size_t, std::error_code> receive(std::vector<uint8_t>& buffer, 
                                              size_t max_size = 1024);
    
    /**
     * @brief Receive data from any address
     * @param buffer Buffer to receive data into
     * @param from_address Address of sender (output parameter)
     * @param max_size Maximum bytes to receive
     * @return Number of bytes received or error code
     */
    std::pair<size_t, std::error_code> receiveFrom(std::vector<uint8_t>& buffer,
                                                  NetworkAddress& from_address,
                                                  size_t max_size = 1024);
    
    /**
     * @brief Set socket timeout
     * @param timeout_ms Timeout in milliseconds
     * @return std::error_code indicating success or failure
     */
    std::error_code setTimeout(int timeout_ms);
    
    /**
     * @brief Close the socket
     */
    void close();
    
    /**
     * @brief Check if socket is valid
     */
    bool isValid() const { return socket_ != INVALID_SOCKET_VALUE; }
    
private:
    socket_t socket_{INVALID_SOCKET_VALUE};
    bool is_connected_{false};
    NetworkAddress connected_address_;
    
    void cleanup();
    std::error_code getLastError() const;
    
    // Platform-specific address conversion
    sockaddr_in toSockAddr(const NetworkAddress& address) const;
    NetworkAddress fromSockAddr(const sockaddr_in& addr) const;
};

/**
 * @brief Network initialization helper
 * 
 * Handles platform-specific network subsystem initialization
 * (e.g., WSAStartup on Windows)
 */
class NetworkInitializer {
public:
    NetworkInitializer();
    ~NetworkInitializer();
    
    bool isInitialized() const { return initialized_; }
    std::error_code getLastError() const { return last_error_; }
    
private:
    bool initialized_{false};
    std::error_code last_error_;
    
#ifdef _WIN32
    WSADATA wsa_data_;
#endif
};

/**
 * @brief RAII network manager
 * 
 * Singleton that manages network subsystem lifecycle
 */
class NetworkManager {
public:
    static NetworkManager& getInstance();
    
    bool isInitialized() const { return initializer_.isInitialized(); }
    std::error_code getLastError() const { return initializer_.getLastError(); }
    
private:
    NetworkManager() = default;
    NetworkInitializer initializer_;
};

} // namespace drcom

#endif // NETWORK_H