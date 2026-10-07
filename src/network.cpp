#include "drcom/network.h"

#include <algorithm>
#include <cstring>
#include <bit>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#ifdef __linux__
#include <net/if_arp.h>
#include <sys/ioctl.h>
#endif
#endif

namespace drcom {

std::vector<NetworkInterface> listNetworkInterfaces() {
    std::vector<NetworkInterface> interfaces;

#ifdef _WIN32
    ULONG buffer_size = 0;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST |
                                      GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER,
                              nullptr, nullptr, &buffer_size) != ERROR_BUFFER_OVERFLOW) {
        return interfaces;
    }

    std::vector<unsigned char> buffer(buffer_size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST |
                                      GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER,
                              nullptr, adapters, &buffer_size) != NO_ERROR) {
        return interfaces;
    }

    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
        const bool up = adapter->OperStatus == IfOperStatusUp;
        const bool loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        for (auto* address = adapter->FirstUnicastAddress;
             address != nullptr; address = address->Next) {
            if (!address->Address.lpSockaddr ||
                address->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }

            const auto* addr = reinterpret_cast<const sockaddr_in*>(
                address->Address.lpSockaddr);
            char ip[INET_ADDRSTRLEN]{};
            if (!inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip))) {
                continue;
            }

            NetworkInterface network_interface;
            network_interface.name = adapter->AdapterName ? adapter->AdapterName : "";
            network_interface.ipv4 = ip;
            network_interface.is_up = up;
            network_interface.is_loopback = loopback;
            network_interface.is_physical = adapter->IfType == IF_TYPE_ETHERNET_CSMACD ||
                                    adapter->IfType == IF_TYPE_IEEE80211;
            if (adapter->PhysicalAddressLength >= network_interface.mac.size()) {
                std::copy_n(adapter->PhysicalAddress,
                            network_interface.mac.size(), network_interface.mac.begin());
                network_interface.has_mac = true;
            }
            interfaces.push_back(std::move(network_interface));
        }
    }
#else
    struct ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) != 0) {
        return interfaces;
    }

#ifdef __linux__
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
#endif

    for (auto* address = addresses; address != nullptr; address = address->ifa_next) {
        if (!address->ifa_name || !address->ifa_addr ||
            address->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        char ip[INET_ADDRSTRLEN]{};
        const auto* addr = reinterpret_cast<const sockaddr_in*>(address->ifa_addr);
        if (!inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip))) {
            continue;
        }

        NetworkInterface network_interface;
        network_interface.name = address->ifa_name;
        network_interface.ipv4 = ip;
        network_interface.is_up = (address->ifa_flags & IFF_UP) != 0;
        network_interface.is_loopback = (address->ifa_flags & IFF_LOOPBACK) != 0;

#ifdef __linux__
        std::error_code device_error;
        network_interface.is_physical = std::filesystem::exists(
            std::filesystem::path("/sys/class/net") / network_interface.name / "device",
            device_error);
        if (socket_fd >= 0) {
            struct ifreq request{};
            std::strncpy(request.ifr_name, address->ifa_name,
                         sizeof(request.ifr_name) - 1);
            if (ioctl(socket_fd, SIOCGIFHWADDR, &request) == 0 &&
                request.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
                std::copy_n(reinterpret_cast<const uint8_t*>(request.ifr_hwaddr.sa_data),
                            network_interface.mac.size(), network_interface.mac.begin());
                network_interface.has_mac = std::any_of(network_interface.mac.begin(),
                                                network_interface.mac.end(),
                                                [](uint8_t value) { return value != 0; });
            }
        }
#elif defined(__APPLE__)
        for (auto* link = addresses; link != nullptr; link = link->ifa_next) {
            if (!link->ifa_name || std::strcmp(link->ifa_name, address->ifa_name) != 0 ||
                !link->ifa_addr || link->ifa_addr->sa_family != AF_LINK) {
                continue;
            }
            const auto* sockaddr = reinterpret_cast<const sockaddr_dl*>(link->ifa_addr);
            network_interface.is_physical = sockaddr->sdl_type == IFT_ETHER;
            if (sockaddr->sdl_alen >= network_interface.mac.size()) {
                std::copy_n(reinterpret_cast<const uint8_t*>(LLADDR(sockaddr)),
                            network_interface.mac.size(), network_interface.mac.begin());
                network_interface.has_mac = true;
            }
            break;
        }
#endif
        interfaces.push_back(std::move(network_interface));
    }

#ifdef __linux__
    if (socket_fd >= 0) {
        ::close(socket_fd);
    }
#endif
    freeifaddrs(addresses);
#endif

    return interfaces;
}

#ifdef __linux__
std::optional<NetworkInterface> selectInterfaceForRoutes(
    const std::vector<NetworkInterface>& interfaces,
    const std::string& destination, std::istream& routes) {
    in_addr address{};
    if (inet_pton(AF_INET, destination.c_str(), &address) != 1) return std::nullopt;
    std::optional<NetworkInterface> selected;
    int best_prefix = -1;
    unsigned long best_metric = std::numeric_limits<unsigned long>::max();
    std::string line;
    while (std::getline(routes, line)) {
        std::istringstream row(line);
        std::string name;
        unsigned long network, gateway, flags, refs, uses, metric, mask;
        if (!(row >> name >> std::hex >> network >> gateway >> flags >>
              std::dec >> refs >> uses >> metric >> std::hex >> mask)) continue;
        if (!(flags & 1) || (flags & 0x200) ||
            (address.s_addr & mask) != network) continue;
        const auto network_interface = std::find_if(interfaces.begin(), interfaces.end(),
            [&](const auto& item) {
                return item.name == name && item.is_up && item.is_physical && item.has_mac;
            });
        if (network_interface == interfaces.end()) continue;
        const int prefix = std::popcount(static_cast<uint32_t>(mask));
        if (prefix > best_prefix || (prefix == best_prefix && metric < best_metric)) {
            selected = *network_interface;
            best_prefix = prefix;
            best_metric = metric;
        }
    }
    return selected;
}
#endif

std::optional<NetworkInterface> selectNetworkInterface(
    const NetworkAddress& server, const std::string& bind_ip) {
    const auto interfaces = listNetworkInterfaces();
    if (!bind_ip.empty() && bind_ip != "0.0.0.0") {
        for (const auto& item : interfaces) {
            if (item.is_up && item.ipv4 == bind_ip) return item;
        }
        return std::nullopt;
    }
    if (server.ip.rfind("127.", 0) == 0) {
        for (const auto& item : interfaces) {
            if (item.is_up && item.is_loopback) return item;
        }
        return std::nullopt;
    }
#ifdef __linux__
    // Main-table physical routes avoid choosing a TUN policy route merely
    // because a VPN exists. Actual server availability is tested by login.
    std::ifstream routes("/proc/net/route");
    return selectInterfaceForRoutes(interfaces, server.ip, routes);
#else
    UdpSocket probe;
    if (!probe.connect(server)) {
        const auto source = probe.localAddress();
        for (const auto& item : interfaces) {
            if (source && item.ipv4 == *source && item.is_up &&
                item.is_physical && item.has_mac) return item;
        }
    }
    // With a virtual route, use a physical adapter only if unambiguous.
    std::optional<NetworkInterface> selected;
    for (const auto& item : interfaces) {
        if (!item.is_up || !item.is_physical || !item.has_mac) continue;
        if (selected) return std::nullopt;
        selected = item;
    }
    return selected;
#endif
}

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

std::optional<std::string> UdpSocket::localAddress() const {
    if (!isValid() || !is_connected_) return std::nullopt;
    sockaddr_in local{};
#ifdef _WIN32
    int length = sizeof(local);
#else
    socklen_t length = sizeof(local);
#endif
    if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&local), &length) != 0 ||
        local.sin_addr.s_addr == INADDR_ANY) {
        return std::nullopt;
    }
    char buffer[INET_ADDRSTRLEN]{};
    if (!inet_ntop(AF_INET, &local.sin_addr, buffer, sizeof(buffer))) {
        return std::nullopt;
    }
    return std::string(buffer);
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
