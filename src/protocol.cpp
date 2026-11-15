#include "drcom/protocol.h"
#include "drcom/crypto.h"
#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace drcom::protocol {
std::array<uint8_t, 4> parseIPv4(const std::string& ip) {
    std::array<uint8_t, 4> result{};
    size_t start = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        const auto dot = ip.find('.', start);
        if ((dot == std::string::npos) != (i == 3)) throw std::invalid_argument("Invalid IPv4 address");
        const auto end = dot == std::string::npos ? ip.size() : dot;
        unsigned value{};
        const auto [last, error] = std::from_chars(ip.data() + start, ip.data() + end, value);
        if (start == end || (end - start > 1 && ip[start] == '0') ||
            error != std::errc{} || last != ip.data() + end || value > 255)
            throw std::invalid_argument("Invalid IPv4 address");
        result[i] = static_cast<uint8_t>(value);
        start = end + 1;
    }
    return result;
}

std::vector<uint8_t> buildChallengePacket(const Config& config, bool is_login, std::array<uint8_t, 2> nonce) {
    std::vector<uint8_t> packet(20);
    packet[0] = 0x01;
    packet[1] = is_login ? 0x02 : 0x03;
    packet[2] = nonce[0];
    packet[3] = nonce[1];
    // Add auth version
    auto& protocol = config.getProtocolConfig();
    packet[4] = protocol.auth_version[0];
    packet[5] = protocol.auth_version[1];
    return packet;
}

std::vector<uint8_t> buildLoginPacket(const Config& config, const Session& session) {
    const auto& user_config = config.getUserConfig();
    const auto& protocol_config = config.getProtocolConfig();
    
    if (!config.validate()) throw std::invalid_argument(config.lastError());

    // Calculate dynamic packet size
    const size_t packet_size = 334 + ((user_config.password.length() - 1) / 4) * 4;
    std::vector<uint8_t> packet(packet_size, 0);
    
    // Header: 0x03 0x01 0x00 username_len+20
    packet[0] = 0x03;
    packet[1] = 0x01;
    packet[2] = 0x00;
    packet[3] = static_cast<uint8_t>(user_config.username.length() + 20);
    
    // Build MD5 digest A for password: md5(0x03 0x01 [salt] [password])
    std::vector<uint8_t> md5a_plain;
    md5a_plain.push_back(0x03);
    md5a_plain.push_back(0x01);
    md5a_plain.insert(md5a_plain.end(), session.login_salt.begin(), session.login_salt.end());
    md5a_plain.insert(md5a_plain.end(), user_config.password.begin(), user_config.password.end());
    
    auto md5a = crypto::MD5::hash(md5a_plain);
    std::copy(md5a.begin(), md5a.end(), packet.begin() + 4);
    
    // Username (36 bytes)
    const size_t username_copy_len = std::min(user_config.username.length(), static_cast<size_t>(36));
    std::copy(user_config.username.begin(), 
              user_config.username.begin() + username_copy_len, 
              packet.begin() + 20);
    
    // Control check status and adapter num
    packet[56] = protocol_config.control_check_status;
    packet[57] = protocol_config.adapter_num;
    
    // MAC XOR MD5A (6 bytes)
    for (size_t i = 0; i < 6; ++i) {
        packet[58 + i] = user_config.mac[i] ^ md5a[i];
    }
    
    // Build MD5 digest B: md5(0x01 [password] [salt] 0x00 0x00 0x00 0x00)
    std::vector<uint8_t> md5b_plain;
    md5b_plain.push_back(0x01);
    md5b_plain.insert(md5b_plain.end(), user_config.password.begin(), user_config.password.end());
    md5b_plain.insert(md5b_plain.end(), session.login_salt.begin(), session.login_salt.end());
    md5b_plain.insert(md5b_plain.end(), 4, 0x00);  // 4 zero bytes
    
    auto md5b = crypto::MD5::hash(md5b_plain);
    std::copy(md5b.begin(), md5b.end(), packet.begin() + 64);
    
    // IP indicator
    packet[80] = 0x01;
    
    // Client IP (4 bytes)
    auto ip_bytes = parseIPv4(user_config.ip);
    std::copy(ip_bytes.begin(), ip_bytes.end(), packet.begin() + 81);
    
    // Calculate MD5 digest C: md5([first 97 bytes] 0x14 0x00 0x07 0x0b)
    std::vector<uint8_t> md5c_plain(packet.begin(), packet.begin() + 97);
    md5c_plain.insert(md5c_plain.end(), {0x14, 0x00, 0x07, 0x0b});
    
    auto md5c = crypto::MD5::hash(md5c_plain);
    std::copy(md5c.begin(), md5c.begin() + 8, packet.begin() + 97);
    
    // IP dog (1 byte) + 4 zero bytes padding already initialized
    packet[105] = protocol_config.ip_dog;
    
    // Hostname (32 bytes max)
    const size_t hostname_len = std::min(user_config.hostname.length(), static_cast<size_t>(32));
    std::copy(user_config.hostname.begin(), 
              user_config.hostname.begin() + hostname_len, 
              packet.begin() + 110);
    
    // Primary DNS (4 bytes)
    auto dns_bytes = parseIPv4(user_config.primary_dns);
    std::copy(dns_bytes.begin(), dns_bytes.end(), packet.begin() + 142);
    
    // DHCP server (4 bytes)  
    auto dhcp_bytes = parseIPv4(user_config.dhcp_server);
    std::copy(dhcp_bytes.begin(), dhcp_bytes.end(), packet.begin() + 146);
    
    // Zero padding until 181 (already initialized)
    
    // Unknown byte 0x01
    packet[181] = 0x01;
    
    // DrCOM indicator (8 bytes)
    const uint8_t drcom_indicator[] = {0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07};
    std::copy(drcom_indicator, drcom_indicator + 8, packet.begin() + 182);
    
    // Auth version (2 bytes)
    packet[190] = protocol_config.auth_version[0];
    packet[191] = protocol_config.auth_version[1];
    
    // OS info (54 bytes max, zero padded)
    const size_t os_info_len = std::min(user_config.os_info.length(), static_cast<size_t>(54));
    std::copy(user_config.os_info.begin(), 
              user_config.os_info.begin() + os_info_len, 
              packet.begin() + 192);
    
    // Preserve the existing zero-filled tail. Changes here require independent
    // wire evidence from a compatible server; see docs/protocol.md.
    
    return packet;
}

std::vector<uint8_t> buildLogoutPacket(const Config& config, const Session& session) {
    std::vector<uint8_t> packet(80, 0);
    const auto& user_config = config.getUserConfig();
    
    // Header: 0x06 0x01 0x00 username_len+20
    packet[0] = 0x06;
    packet[1] = 0x01;
    packet[2] = 0x00;
    packet[3] = static_cast<uint8_t>(user_config.username.length() + 20);
    
    // MD5 password (16 bytes at offset 4-19)
    std::copy(session.md5_password.begin(), session.md5_password.end(), packet.begin() + 4);
    
    // Username (36 bytes at offset 20-55)
    const size_t username_copy_len = std::min(user_config.username.length(), static_cast<size_t>(36));
    std::copy(user_config.username.begin(), 
              user_config.username.begin() + username_copy_len, 
              packet.begin() + 20);
    
    // Control check status and adapter num
    const auto& protocol_config = config.getProtocolConfig();
    packet[56] = protocol_config.control_check_status;
    packet[57] = protocol_config.adapter_num;
    
    // MAC XOR MD5 password (6 bytes at offset 58-63)
    for (size_t i = 0; i < 6; ++i) {
        packet[58 + i] = user_config.mac[i] ^ session.md5_password[i];
    }
    
    // Logout salt (4 bytes at offset 64-67) if available
    if (!std::all_of(session.logout_salt.begin(), session.logout_salt.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(session.logout_salt.begin(), session.logout_salt.end(), packet.begin() + 64);
    }
    
    // Remaining bytes 68-79 are zero-padded (already initialized)
    
    return packet;
}

std::vector<uint8_t> buildKeepAliveAuthPacket(const Session& session, uint64_t timestamp) {
    std::vector<uint8_t> packet(38, 0);
    
    // Header: 0xff + MD5 password (16 bytes)
    packet[0] = 0xff;
    std::copy(session.md5_password.begin(), session.md5_password.end(), packet.begin() + 1);
    
    // Zero padding bytes at offset 17-19 (3 bytes, already initialized)
    
    // Server DRCOM indicator (16 bytes at offset 20-35)
    if (!std::all_of(session.server_drcom_indicator.begin(), session.server_drcom_indicator.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(session.server_drcom_indicator.begin(), session.server_drcom_indicator.end(), 
                  packet.begin() + 20);
    }
    
    // Timestamp (2 bytes at offset 36-37)
    auto time_now = timestamp;
    packet[36] = static_cast<uint8_t>(time_now % (2 << 7));
    time_now /= (2 << 7);
    packet[37] = static_cast<uint8_t>(time_now % (2 << 7));
    
    return packet;
}

std::vector<uint8_t> buildKeepAliveHeartbeatPacket(const Config& config, const Session& session, uint64_t counter, bool is_first, bool is_extra, std::array<uint8_t, 4> nonce) {
    std::vector<uint8_t> packet(40, 0);
    const auto& protocol_config = config.getProtocolConfig();
    
    // Header: 0x07 + heartbeat counter (1 byte)
    packet[0] = 0x07;
    packet[1] = static_cast<uint8_t>(counter & 0xff);
    
    // Fixed bytes sequence: 0x28 0x00 0x0b (3 bytes at offset 2-4)
    packet[2] = 0x28;
    packet[3] = 0x00;
    packet[4] = 0x0b;
    
    // Fixed byte: 0x01 (1 byte at offset 5)
    packet[5] = 0x01;
    
    // Heartbeat version (2 bytes at offset 6-7)
    if (is_first) {
        packet[6] = protocol_config.first_heartbeat_version[0];
        packet[7] = protocol_config.first_heartbeat_version[1]; 
    } else if (is_extra) {
        packet[6] = protocol_config.extra_heartbeat_version[0];
        packet[7] = protocol_config.extra_heartbeat_version[1];
    } else {
        packet[6] = protocol_config.keep_alive_version[0];
        packet[7] = protocol_config.keep_alive_version[1];
    }
    
    // Random number (4 bytes at offset 8-11)
    packet[8] = nonce[0];
    packet[9] = nonce[1];
    packet[10] = nonce[2];
    packet[11] = nonce[3];
    
    // Zero padding at offset 12-15 (already initialized)
    
    // Server token (4 bytes at offset 16-19) if available
    if (!std::all_of(session.heartbeat_server_token.begin(), session.heartbeat_server_token.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(session.heartbeat_server_token.begin(), session.heartbeat_server_token.end(), 
                  packet.begin() + 16);
    }
    
    // CRC checksum at offset 20-23 (4 bytes)
    // Calculate CRC over first 20 bytes
    auto crc_bytes = crypto::CRC::calculate(std::vector<uint8_t>(packet.begin(), packet.begin() + 20), 4);
    std::copy(crc_bytes.begin(), crc_bytes.end(), packet.begin() + 20);
    
    // Client IP at offset 24-27
    const auto& user_config = config.getUserConfig();
    auto ip_bytes = parseIPv4(user_config.ip);
    std::copy(ip_bytes.begin(), ip_bytes.end(), packet.begin() + 24);
    
    // Zero padding for remaining bytes 28-39 (already initialized)
    
    return packet;
}

} // namespace drcom::protocol
