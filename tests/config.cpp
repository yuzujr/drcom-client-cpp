#include "drcom/config.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
int main() {
    const auto root = std::filesystem::temp_directory_path() /
        ("drcom-config-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{root};
    const auto file = root / "test.conf";
    const std::string base = "username=test\npassword=secret\nip=127.0.0.1\nserver_ip=127.0.0.1\nclient_port=61442\n";
    auto write = [&](const std::string& text) { std::ofstream(file, std::ios::binary) << text; };
    drcom::Config config;
    for (const auto& text : {
         "server_port=65537", "server_port=61441junk", "server_port=-1", "server_port=+1",
         "server_port=0", "server_port=99999999999999999999999999999", "server_port=",
         "server_port=61441\nmac=gg:gg:gg:gg:gg:gg", "server_port=61441\nmac=00:11-22:33:44:55",
         "server_port=61441\nmac=0:11:22:33:44:55", "server_port=61441\ndebug=tru",
         "server_port=61441\nheartbeat_interval=4294967296", "server_port=61441\nauth_interval=0",
         "server_port=61441\nauto_identify=true", "server_port=61441\n[Unknown]",
         "server_port=61441\nusername=other", "server_port=61441\npassword=\"unterminated",
         "server_port=61441\nmissing_equals"}) {
        write(base + text + "\n");
        require(!config.loadFromFile(file.string()), std::string("Accepted invalid input: ") + text);
        require(config.lastError().find(file.string() + ":") == 0, "Missing source location");
        require(config.lastError().find("secret") == std::string::npos, "Error disclosed password");
    }
    write("username=" + std::string(37, 'u') + "\npassword=secret\nip=127.0.0.1\nserver_ip=127.0.0.1\nclient_port=61442\nserver_port=61441\n");
    require(!config.loadFromFile(file.string()), "Accepted oversized username");
    for (const auto& ip : {"256.0.0.1", "127.00.0.1", "127.1", "127.0.0.1.2", "127.0.0.x"}) {
        write("username=test\npassword=secret\nip=" + std::string(ip) + "\nserver_ip=127.0.0.1\nclient_port=61442\nserver_port=61441\n");
        require(!config.loadFromFile(file.string()), "Accepted invalid IPv4 address");
    }
    for (const auto& mac : {"001122aAbBcC", "00:11:22:aa:bb:cc", "00-11-22-AA-BB-CC"}) {
        write("\xef\xbb\xbf  # comment\r\n[User]\r\n" + base + "server_port=65535\nmac=" + mac + "\ndebug=YES\npassword_duplicate_is_unknown=hidden\n");
        require(!config.loadFromFile(file.string()), "Accepted unknown key");
        write("\xef\xbb\xbf  # comment\r\n[User]\r\n" + base + "server_port=65535\nmac=" + mac + "\ndebug=YES\n");
        require(config.loadFromFile(file.string()), config.lastError());
        require(config.getUserConfig().mac[5] == 0xcc && config.getClientConfig().debug_enabled, "Parsing changed valid values");
    }
    write(base + "server_port=1\nheartbeat_interval=4294967295\n");
    require(config.loadFromFile(file.string()), config.lastError());
    require(!config.getClientConfig().debug_enabled && config.getUserConfig().mac[5] == 0, "Reload retained old values");
    write(base + "server_port=65537\n");
    require(!config.loadFromFile(file.string()) && config.getServerConfig().port == 1, "Failed load changed active configuration");
    auto user = config.getUserConfig();
    user.password = " leading=embedded\" trailing ";
    config.setUserConfig(user);
    const auto saved = root / "saved.conf";
    require(config.saveToFile(saved.string()), "Save failed");
    drcom::Config restored;
    require(restored.loadFromFile(saved.string()), restored.lastError());
    require(restored.getUserConfig().password == user.password, "Quoted password did not round-trip");
    require(restored.getServerConfig().port == 1, "Save/load changed port");
    require(!restored.loadFromFile((root / "missing.conf").string()), "Missing file accepted");
    std::cout << "Configuration boundaries, diagnostics and transactional reload passed\n";
}
