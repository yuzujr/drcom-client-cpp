#include "drcom/config.h"

#include <fstream>
#include <iostream>
#include <regex>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace {

std::string trimCopy(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }

    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

bool parseBoolean(const std::string& value) {
    std::string normalized = trimCopy(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return normalized == "true" || normalized == "1" || normalized == "yes" ||
           normalized == "on";
}

}  // namespace

namespace drcom {

Config& Config::getInstance() {
    static Config instance;
    return instance;
}

bool Config::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Parse key=value pairs
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // Trim whitespace
        key = trimCopy(key);
        value = trimCopy(value);
        if (key.empty()) {
            continue;
        }
        
        // Remove quotes if present
        if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }
        
        // Set configuration values
        if (key == "username") {
            user_config_.username = value;
        } else if (key == "password") {
            user_config_.password = value;
        } else if (key == "ip") {
            user_config_.ip = value;
        } else if (key == "hostname") {
            user_config_.hostname = value;
        } else if (key == "os_info") {
            user_config_.os_info = value;
        } else if (key == "server_ip") {
            server_config_.ip = value;
        } else if (key == "server_port") {
            try {
                server_config_.port = static_cast<uint16_t>(std::stoul(value));
            } catch (...) {
                // Ignore invalid port values
            }
        } else if (key == "client_ip") {
            client_config_.ip = value;
        } else if (key == "client_port") {
            try {
                client_config_.port = static_cast<uint16_t>(std::stoul(value));
            } catch (...) {
                // Ignore invalid port values
            }
        } else if (key == "debug") {
            client_config_.debug_enabled = parseBoolean(value);
        } else if (key == "auto_reconnect") {
            client_config_.auto_reconnect = parseBoolean(value);
        } else if (key == "reconnect_interval") {
            try {
                client_config_.reconnect_interval = static_cast<uint32_t>(std::stoul(value));
            } catch (...) {
                // Ignore invalid values, keep default
            }
        } else if (key == "auth_interval") {
            try {
                protocol_config_.auth_interval = static_cast<uint32_t>(std::stoul(value));
            } catch (...) {
                // Ignore invalid values, keep default
            }
        } else if (key == "heartbeat_interval") {
            try {
                protocol_config_.heartbeat_interval = static_cast<uint32_t>(std::stoul(value));
            } catch (...) {
                // Ignore invalid values, keep default
            }
        } else if (key == "mac") {
            // Parse MAC address in format "00:11:22:33:44:55" or "00-11-22-33-44-55"
            parseMacAddress(value, user_config_.mac);
        } else if (key == "primary_dns") {
            user_config_.primary_dns = value;
        } else if (key == "dhcp_server") {
            user_config_.dhcp_server = value;
        }
    }
    
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
    file << "username=" << user_config_.username << "\n";
    file << "password=" << user_config_.password << "\n";
    file << "ip=" << user_config_.ip << "\n";
    file << "hostname=" << user_config_.hostname << "\n";
    file << "os_info=" << user_config_.os_info << "\n";
    file << "primary_dns=" << user_config_.primary_dns << "\n";
    file << "dhcp_server=" << user_config_.dhcp_server << "\n";
    
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
    file << "reconnect_interval=" << client_config_.reconnect_interval << "\n";
    file << "auth_interval=" << protocol_config_.auth_interval << "\n";
    file << "heartbeat_interval=" << protocol_config_.heartbeat_interval << "\n";
    
    return true;
}

bool Config::validate() const {
    // Validate username
    if (user_config_.username.empty()) {
        return false;
    }
    
    // Validate password
    if (user_config_.password.empty()) {
        return false;
    }
    
    // Validate IP address format
    if (!isValidIPAddress(user_config_.ip)) {
        return false;
    }
    
    if (!isValidIPAddress(server_config_.ip)) {
        return false;
    }

    if (!client_config_.ip.empty() && !isValidIPAddress(client_config_.ip)) {
        return false;
    }

    if (!user_config_.primary_dns.empty() && !isValidIPAddress(user_config_.primary_dns)) {
        return false;
    }

    if (!user_config_.dhcp_server.empty() && !isValidIPAddress(user_config_.dhcp_server)) {
        return false;
    }
    
    // Validate ports
    if (server_config_.port == 0 || client_config_.port == 0) {
        return false;
    }

    if (client_config_.reconnect_interval == 0) {
        return false;
    }

    if (protocol_config_.auth_interval == 0 || protocol_config_.heartbeat_interval == 0) {
        return false;
    }
    
    return true;
}

bool Config::isValidIPAddress(const std::string& ip) const {
    std::regex ip_regex(
        R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    return std::regex_match(ip, ip_regex);
}

void Config::parseMacAddress(const std::string& mac_str, std::array<uint8_t, 6>& mac) const {
    std::string clean_mac = mac_str;
    
    // Remove separators
    clean_mac.erase(std::remove(clean_mac.begin(), clean_mac.end(), ':'), clean_mac.end());
    clean_mac.erase(std::remove(clean_mac.begin(), clean_mac.end(), '-'), clean_mac.end());
    
    if (clean_mac.length() != 12) {
        return; // Invalid MAC address
    }
    
    for (size_t i = 0; i < 6; ++i) {
        std::string byte_str = clean_mac.substr(i * 2, 2);
        try {
            mac[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (...) {
            mac[i] = 0; // Default to 0 on error
        }
    }
}

} // namespace drcom
