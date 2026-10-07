#include "drcom/network.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

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
    std::cout << "10 route selection cases passed\n";
}
