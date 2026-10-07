#include "drcom/network.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <chrono>

std::string route(const std::string& name, const char* network,
                  const char* mask, unsigned metric, unsigned flags = 1) {
    in_addr net{}, subnet{};
    inet_pton(AF_INET, network, &net);
    inet_pton(AF_INET, mask, &subnet);
    std::ostringstream out;
    out << name << ' ' << std::hex << net.s_addr << " 0 " << flags
        << " 0 0 " << std::dec << metric << ' ' << std::hex << subnet.s_addr << '\n';
    return out.str();
}
int main() {
    std::vector<drcom::NetworkInterface> interfaces;
    for (const auto& name : {"wifi", "wired", "Meta"}) {
        drcom::NetworkInterface item;
        item.name = name;
        item.ipv4 = "10.0.0.1";
        item.has_mac = item.is_up = true;
        item.is_physical = item.name != "Meta";
        interfaces.push_back(item);
    }
    const auto check = [&](const std::string& rows, const std::string& expected) {
        std::istringstream stream("Iface Destination Gateway Flags RefCnt Use Metric Mask\n" + rows);
        auto selected = drcom::selectInterfaceForRoutes(interfaces, "10.100.61.3", stream);
        if ((selected ? selected->name : "") != expected)
            throw std::runtime_error("Unexpected selected interface: " + expected);
    };
    const auto wifi = route("wifi", "0.0.0.0", "0.0.0.0", 600);
    const auto wired = route("wired", "0.0.0.0", "0.0.0.0", 100);
    check(wifi + wired, "wired");
    check(wired + wifi, "wired");
    check(wifi + wired + route("Meta", "10.100.61.3", "255.255.255.255", 0), "wired");
    check(wifi + wired + route("wifi", "10.100.0.0", "255.255.0.0", 900), "wifi");
    check(wifi + wired + route("wifi", "192.168.0.0", "255.255.0.0", 0), "wired");
    check(route("wired", "0.0.0.0", "0.0.0.0", 0, 0), "");
    check(route("wired", "0.0.0.0", "0.0.0.0", 0, 0x201), "");
    check("garbage\n", "");
    interfaces[1].is_up = false;
    check(wifi + wired, "wifi");
    interfaces[0].has_mac = false;
    check(wifi + wired, "");
    auto& manager = drcom::NetworkManager::getInstance();
    if (!manager.isInitialized()) throw std::runtime_error("Network init failed");
    drcom::UdpSocket socket;
    if (socket.bind({"127.0.0.1", 0})) throw std::runtime_error("Bind failed");
    std::vector<uint8_t> buffer;
    auto start = std::chrono::steady_clock::now();
    const auto [size, error] = socket.receiveInterruptibly(buffer, 15000, [&] {
        return std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(50);
    });
    if (error != std::errc::operation_canceled || size != 0 ||
        std::chrono::steady_clock::now() - start > std::chrono::seconds(1))
        throw std::runtime_error("Receive was not promptly cancelled");
    start = std::chrono::steady_clock::now();
    const auto timeout = socket.receiveInterruptibly(buffer, 250, {});
    if (timeout.second != std::errc::timed_out ||
        std::chrono::steady_clock::now() - start < std::chrono::milliseconds(200))
        throw std::runtime_error("Receive deadline changed");
    std::cout << "10 route selection cases, cancellation and deadline passed\n";
}
