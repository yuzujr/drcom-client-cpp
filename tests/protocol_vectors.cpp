#include "drcom/protocol.h"
#include "drcom/crypto.h"
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace drcom;
template<class Bytes> void print(const std::string& name, const Bytes& data) {
    std::cout << name << ' ';
    for (auto byte : data) std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
    std::cout << std::dec << '\n';
}
int main(int argc, char**) {
    if (argc > 1) {
        std::string hex;
        while (std::getline(std::cin, hex)) {
            // Offset the input deliberately: the public hash API accepts unaligned bytes.
            std::vector<uint8_t> data(1, 0);
            for (size_t i = 0; i < hex.size(); i += 2) data.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
            const auto* input = data.data() + 1;
            const auto size = data.size() - 1;
            print("md5", crypto::MD5::hash(input, size));
            print("checksum", crypto::Checksum::calculate(input, size, 8));
            print("crc", crypto::CRC::calculate(input, size, 8));
            print("rotate", crypto::ROR::encrypt(input, size));
        }
        return 0;
    }
    Config config;
    config.setUserConfig({"test_user", "test_pass", "10.20.30.40", {0, 0x11, 0x22, 0xaa, 0xbb, 0xcc}, "test-host", "test-os", "1.2.3.4", "5.6.7.8"});
    config.setServerConfig({"127.0.0.1", 61441});
    auto client = config.getClientConfig(); client.port = 61442; config.setClientConfig(client);
    protocol::Session session;
    session.login_salt = {1, 2, 3, 4}; session.logout_salt = {5, 6, 7, 8};
    session.heartbeat_server_token = {0x11, 0x12, 0x13, 0x14};
    for (size_t i = 0; i < 16; ++i) session.server_drcom_indicator[i] = static_cast<uint8_t>(0x20 + i);
    print("challenge_login", protocol::buildChallengePacket(config, true, {0x12, 0x34}));
    print("challenge_logout", protocol::buildChallengePacket(config, false, {0x12, 0x34}));
    for (const size_t size : {1, 4, 5, 16, 17, 64}) {
        auto user = config.getUserConfig(); user.password = std::string(size, 'p'); config.setUserConfig(user);
        print("login_" + std::to_string(size), protocol::buildLoginPacket(config, session));
    }
    session.md5_password = crypto::DrcomCrypto::generateMD5A(session.login_salt, config.getUserConfig().password);
    print("logout", protocol::buildLogoutPacket(config, session));
    print("auth", protocol::buildKeepAliveAuthPacket(session, 0x12345678));
    for (uint64_t count : {0, 21, 255, 256})
        print("heartbeat_" + std::to_string(count), protocol::buildKeepAliveHeartbeatPacket(config, session,
            count, count == 0, count == 21, {0x55, 0x66, 0x77, 0x88}));
}
