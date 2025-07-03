#include "drcom/network.h"

#include <cstring>

namespace drcom {

NetworkInitializer::NetworkInitializer() {
#ifdef _WIN32
    WORD wVersionRequested = MAKEWORD(2, 2);
    int result = WSAStartup(wVersionRequested, &wsa_data_);
    if (result != 0) {
        last_error_ = std::make_error_code(std::errc::network_down);
        initialized_ = false;
    } else {
        initialized_ = true;
    }
#else
    initialized_ = true;
#endif
}

NetworkInitializer::~NetworkInitializer() {
#ifdef _WIN32
    if (initialized_) {
        WSACleanup();
    }
#endif
}

NetworkManager& NetworkManager::getInstance() {
    static NetworkManager instance;
    return instance;
}

UdpSocket::UdpSocket() {
    // Ensure network is initialized
    auto& manager = NetworkManager::getInstance();
    if (!manager.isInitialized()) {
        return;
    }
    
    socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

UdpSocket::~UdpSocket() {
    close();
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : socket_(other.socket_)
    , is_connected_(other.is_connected_)
    , connected_address_(std::move(other.connected_address_)) {
    other.socket_ = INVALID_SOCKET_VALUE;
    other.is_connected_ = false;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        socket_ = other.socket_;
        is_connected_ = other.is_connected_;
        connected_address_ = std::move(other.connected_address_);
        other.socket_ = INVALID_SOCKET_VALUE;
        other.is_connected_ = false;
    }
    return *this;
}

std::error_code UdpSocket::bind(const NetworkAddress& address) {
    if (!isValid()) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    
    sockaddr_in addr = toSockAddr(address);
    if (::bind(socket_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        return getLastError();
    }
    
    return {};
}

std::error_code UdpSocket::connect(const NetworkAddress& address) {
    if (!isValid()) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    
    sockaddr_in addr = toSockAddr(address);
    if (::connect(socket_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        return getLastError();
    }
    
    connected_address_ = address;
    is_connected_ = true;
    return {};
}

std::pair<size_t, std::error_code> UdpSocket::send(const std::vector<uint8_t>& data) {
    if (!isValid() || !is_connected_) {
        return {0, std::make_error_code(std::errc::not_connected)};
    }
    
#ifdef _WIN32
    int result = ::send(socket_, reinterpret_cast<const char*>(data.data()), 
                       static_cast<int>(data.size()), 0);
#else
    ssize_t result = ::send(socket_, data.data(), data.size(), 0);
#endif
    
    if (result < 0) {
        return {0, getLastError()};
    }
    
    return {static_cast<size_t>(result), {}};
}

std::pair<size_t, std::error_code> UdpSocket::sendTo(const std::vector<uint8_t>& data, 
                                                    const NetworkAddress& address) {
    if (!isValid()) {
        return {0, std::make_error_code(std::errc::bad_file_descriptor)};
    }
    
    sockaddr_in addr = toSockAddr(address);
    
#ifdef _WIN32
    int result = ::sendto(socket_, reinterpret_cast<const char*>(data.data()), 
                         static_cast<int>(data.size()), 0,
                         reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
#else
    ssize_t result = ::sendto(socket_, data.data(), data.size(), 0,
                             reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
#endif
    
    if (result < 0) {
        return {0, getLastError()};
    }
    
    return {static_cast<size_t>(result), {}};
}

std::pair<size_t, std::error_code> UdpSocket::receive(std::vector<uint8_t>& buffer, 
                                                     size_t max_size) {
    if (!isValid()) {
        return {0, std::make_error_code(std::errc::bad_file_descriptor)};
    }
    
    buffer.resize(max_size);
    
#ifdef _WIN32
    int result = ::recv(socket_, reinterpret_cast<char*>(buffer.data()), 
                       static_cast<int>(max_size), 0);
#else
    ssize_t result = ::recv(socket_, buffer.data(), max_size, 0);
#endif
    
    if (result < 0) {
        buffer.clear();
        return {0, getLastError()};
    }
    
    buffer.resize(static_cast<size_t>(result));
    return {static_cast<size_t>(result), {}};
}

std::pair<size_t, std::error_code> UdpSocket::receiveFrom(std::vector<uint8_t>& buffer,
                                                         NetworkAddress& from_address,
                                                         size_t max_size) {
    if (!isValid()) {
        return {0, std::make_error_code(std::errc::bad_file_descriptor)};
    }
    
    buffer.resize(max_size);
    sockaddr_in from_addr{};
    
#ifdef _WIN32
    int addr_len = sizeof(from_addr);
    int result = ::recvfrom(socket_, reinterpret_cast<char*>(buffer.data()),
                           static_cast<int>(max_size), 0,
                           reinterpret_cast<sockaddr*>(&from_addr), &addr_len);
#else
    socklen_t addr_len = sizeof(from_addr);
    ssize_t result = ::recvfrom(socket_, buffer.data(), max_size, 0,
                               reinterpret_cast<sockaddr*>(&from_addr), &addr_len);
#endif
    
    if (result < 0) {
        buffer.clear();
        return {0, getLastError()};
    }
    
    buffer.resize(static_cast<size_t>(result));
    from_address = fromSockAddr(from_addr);
    return {static_cast<size_t>(result), {}};
}

std::error_code UdpSocket::setTimeout(int timeout_ms) {
    if (!isValid()) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    
#ifdef _WIN32
    DWORD timeout = static_cast<DWORD>(timeout_ms);
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, 
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
        return getLastError();
    }
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return getLastError();
    }
#endif
    
    return {};
}

void UdpSocket::close() {
    if (isValid()) {
#ifdef _WIN32
        ::closesocket(socket_);
#else
        ::close(socket_);
#endif
        socket_ = INVALID_SOCKET_VALUE;
        is_connected_ = false;
    }
}

std::error_code UdpSocket::getLastError() const {
#ifdef _WIN32
    int error = WSAGetLastError();
    return std::error_code(error, std::system_category());
#else
    return std::error_code(errno, std::system_category());
#endif
}

sockaddr_in UdpSocket::toSockAddr(const NetworkAddress& address) const {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(address.port);
    
    if (address.ip == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
#ifdef _WIN32
        inet_pton(AF_INET, address.ip.c_str(), &addr.sin_addr);
#else
        inet_pton(AF_INET, address.ip.c_str(), &addr.sin_addr);
#endif
    }
    
    return addr;
}

NetworkAddress UdpSocket::fromSockAddr(const sockaddr_in& addr) const {
    NetworkAddress address;
    address.port = ntohs(addr.sin_port);
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    address.ip = ip_str;
    
    return address;
}

} // namespace drcom
