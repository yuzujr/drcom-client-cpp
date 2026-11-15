#include "drcom/config.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <unordered_map>

namespace {
std::string trimCopy(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    return value.substr(begin, value.find_last_not_of(" \t\r\n") - begin + 1);
}
template<class T> bool parseNumber(const std::string& text, T& result, int base = 10) {
    unsigned long long number{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number, base);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() ||
        number > std::numeric_limits<T>::max()) return false;
    result = static_cast<T>(number);
    return true;
}
bool parseBoolean(std::string text, bool& result) {
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (text == "true" || text == "1" || text == "yes" || text == "on") result = true;
    else if (text == "false" || text == "0" || text == "no" || text == "off") result = false;
    else return false;
    return true;
}
bool parseMac(const std::string& text, std::array<uint8_t, 6>& result) {
    const bool compact = text.size() == 12;
    if (!compact && (text.size() != 17 || (text[2] != ':' && text[2] != '-'))) return false;
    std::array<uint8_t, 6> parsed{};
    for (size_t i = 0; i < parsed.size(); ++i) {
        const size_t offset = i * (compact ? 2 : 3);
        if (!compact && i && text[offset - 1] != text[2]) return false;
        if (!parseNumber(text.substr(offset, 2), parsed[i], 16)) return false;
    }
    result = parsed;
    return true;
}
} // namespace

namespace drcom {
Config& Config::getInstance() {
    static Config instance;
    return instance;
}

bool Config::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) { last_error_ = filename + ": cannot open configuration file"; return false; }
    Config candidate;
    std::unordered_map<std::string, size_t> locations;
    std::string line;
    size_t line_number = 0;
    const auto fail = [&](const std::string& key, const std::string& message) {
        last_error_ = filename + ":" + std::to_string(line_number) + ": " +
                      (key.empty() ? "" : key + ": ") + message;
        return false;
    };
    while (std::getline(file, line)) {
        ++line_number;
        if (line_number == 1 && line.starts_with("\xef\xbb\xbf")) line.erase(0, 3);
        line = trimCopy(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.find('\0') != std::string::npos) return fail("", "NUL byte is not allowed");
        if (line == "[User]" || line == "[Server]" || line == "[Client]") continue;
        const auto equals = line.find('=');
        if (equals == std::string::npos) return fail("", "expected key=value or a known section");
        const std::string key = trimCopy(line.substr(0, equals));
        std::string value = trimCopy(line.substr(equals + 1));
        if (key.empty()) return fail("", "empty configuration key");
        if (!locations.emplace(key, line_number).second) return fail(key, "duplicate configuration key");
        if (!value.empty() && value.front() == '"') {
            if (value.size() < 2 || value.back() != '"') return fail(key, "unterminated quoted value");
            value = value.substr(1, value.size() - 2);
        }
        auto& user = candidate.user_config_;
        auto& server = candidate.server_config_;
        auto& client = candidate.client_config_;
        auto& protocol = candidate.protocol_config_;
        if (key == "username") user.username = value;
        else if (key == "password") user.password = value;
        else if (key == "ip") user.ip = value;
        else if (key == "hostname") user.hostname = value;
        else if (key == "os_info") user.os_info = value;
        else if (key == "server_ip") server.ip = value;
        else if (key == "client_ip") client.ip = value;
        else if (key == "primary_dns") user.primary_dns = value;
        else if (key == "dhcp_server") user.dhcp_server = value;
        else if (key == "mac") {
            if (!parseMac(value, user.mac)) return fail(key, "expected 12 hex digits or six hex pairs separated by ':' or '-'");
        } else if (key == "server_port" || key == "client_port") {
            auto& port = key == "server_port" ? server.port : client.port;
            if (!parseNumber(value, port) || !port) return fail(key, "expected an integer from 1 to 65535");
        } else if (key == "debug" || key == "auto_reconnect" || key == "auto_identity") {
            auto& flag = key == "debug" ? client.debug_enabled :
                         key == "auto_reconnect" ? client.auto_reconnect : client.auto_identity;
            if (!parseBoolean(value, flag)) return fail(key, "expected true/false, yes/no, on/off, or 1/0");
        } else if (key == "reconnect_interval" || key == "auth_interval" || key == "heartbeat_interval") {
            auto& interval = key == "reconnect_interval" ? client.reconnect_interval :
                             key == "auth_interval" ? protocol.auth_interval : protocol.heartbeat_interval;
            if (!parseNumber(value, interval) || !interval)
                return fail(key, "expected an integer from 1 to 4294967295 seconds");
        } else return fail(key, "unknown configuration key");
    }
    if (file.bad()) return fail("", "error reading configuration file");
    if (!candidate.validate()) {
        const auto key = candidate.lastError().substr(0, candidate.lastError().find(':'));
        const auto found = locations.find(key);
        last_error_ = filename + (found == locations.end() ? "" : ":" + std::to_string(found->second)) +
                      ": " + candidate.lastError();
        return false;
    }
    *this = std::move(candidate); // Failed loads never partially replace the active configuration.
    return true;
}

bool Config::saveToFile(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# DRCOM Client Configuration\n";
    file << "# Generated automatically\n\n";
    
    file << "[User]\n";
    file << "username=\"" << user_config_.username << "\"\n";
    file << "password=\"" << user_config_.password << "\"\n";
    file << "ip=\"" << user_config_.ip << "\"\n";
    file << "hostname=\"" << user_config_.hostname << "\"\n";
    file << "os_info=\"" << user_config_.os_info << "\"\n";
    file << "primary_dns=\"" << user_config_.primary_dns << "\"\n";
    file << "dhcp_server=\"" << user_config_.dhcp_server << "\"\n";
    
    // Format MAC address
    file << "mac=";
    for (size_t i = 0; i < user_config_.mac.size(); ++i) {
        if (i > 0) file << ":";
        file << std::hex << std::setfill('0') << std::setw(2) 
             << static_cast<int>(user_config_.mac[i]);
    }
    file << std::dec << "\n\n";
    
    file << "[Server]\n";
    file << "server_ip=" << server_config_.ip << "\n";
    file << "server_port=" << server_config_.port << "\n\n";
    
    file << "[Client]\n";
    file << "client_ip=" << client_config_.ip << "\n";
    file << "client_port=" << client_config_.port << "\n";
    file << "debug=" << (client_config_.debug_enabled ? "true" : "false") << "\n";
    file << "auto_reconnect=" << (client_config_.auto_reconnect ? "true" : "false") << "\n";
    file << "auto_identity=" << (client_config_.auto_identity ? "true" : "false") << "\n";
    file << "reconnect_interval=" << client_config_.reconnect_interval << "\n";
    file << "auth_interval=" << protocol_config_.auth_interval << "\n";
    file << "heartbeat_interval=" << protocol_config_.heartbeat_interval << "\n";
    
    file.close();
    return static_cast<bool>(file);
}

bool Config::validate() const {
    last_error_.clear();
    const auto fail = [&](const std::string& key, const std::string& message) {
        last_error_ = key + ": " + message;
        return false;
    };
    if (user_config_.username.empty() || user_config_.username.size() > 36)
        return fail("username", "must contain 1 to 36 bytes");
    for (const auto* value : {&user_config_.username, &user_config_.password, &user_config_.hostname, &user_config_.os_info}) {
        if (value->find_first_of(std::string("\r\n\0", 3)) != std::string::npos)
            return fail("user", "text fields cannot contain newline or NUL bytes");
    }
    if (user_config_.password.empty()) return fail("password", "must not be empty");
    // Keep the encoded login datagram within the maximum IPv4 UDP payload.
    if ((user_config_.password.size() - 1) / 4 > (65507 - 334) / 4)
        return fail("password", "encoded login packet exceeds the UDP payload limit");
    if (user_config_.hostname.size() > 32) return fail("hostname", "must not exceed 32 bytes");
    if (user_config_.os_info.size() > 54) return fail("os_info", "must not exceed 54 bytes");
    for (const auto& [key, value] : {std::pair{"ip", user_config_.ip},
         {"server_ip", server_config_.ip}, {"client_ip", client_config_.ip},
         {"primary_dns", user_config_.primary_dns}, {"dhcp_server", user_config_.dhcp_server}}) {
        if (!(key == std::string("client_ip") && value.empty()) && !isValidIPAddress(value)) return fail(key, "expected an IPv4 address with four decimal octets");
    }
    if (!server_config_.port) return fail("server_port", "must be specified and nonzero");
    if (!client_config_.port) return fail("client_port", "must be specified and nonzero");
    if (!client_config_.reconnect_interval) return fail("reconnect_interval", "must be nonzero");
    if (!protocol_config_.auth_interval) return fail("auth_interval", "must be nonzero");
    if (!protocol_config_.heartbeat_interval) return fail("heartbeat_interval", "must be nonzero");
    return true;
}

bool Config::isValidIPAddress(const std::string& ip) const {
    size_t start = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const auto end = ip.find('.', start);
        if ((end == std::string::npos) != (i == 3)) return false;
        const auto octet = ip.substr(start, end == std::string::npos ? end : end - start);
        uint8_t parsed{};
        // inet_pton and the packet encoder must agree; reject ambiguous leading zeros.
        if ((octet.size() > 1 && octet[0] == '0') || !parseNumber(octet, parsed)) return false;
        start = end + 1;
    }
    return true;
}
} // namespace drcom
