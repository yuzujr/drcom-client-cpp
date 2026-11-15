#ifndef DRCOM_PROTOCOL_H
#define DRCOM_PROTOCOL_H
#include "drcom/config.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace drcom::protocol {
// Session data belongs to one client; encoding never reads clocks, sockets or globals.
struct Session {
    std::array<uint8_t, 4> login_salt{};
    std::array<uint8_t, 4> logout_salt{};
    std::array<uint8_t, 16> md5_password{};
    std::array<uint8_t, 16> server_drcom_indicator{};
    std::array<uint8_t, 4> heartbeat_server_token{};
};
std::array<uint8_t, 4> parseIPv4(const std::string& ip);
std::vector<uint8_t> buildChallengePacket(const Config& config, bool is_login,
                                        std::array<uint8_t, 2> nonce);
std::vector<uint8_t> buildLoginPacket(const Config& config, const Session& session);
std::vector<uint8_t> buildLogoutPacket(const Config& config, const Session& session);
std::vector<uint8_t> buildKeepAliveAuthPacket(const Session& session, uint64_t timestamp);
std::vector<uint8_t> buildKeepAliveHeartbeatPacket(const Config& config, const Session& session,
    uint64_t counter, bool is_first, bool is_extra, std::array<uint8_t, 4> nonce);
} // namespace drcom::protocol
#endif
