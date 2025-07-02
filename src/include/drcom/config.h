#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <cstdint>
#include <array>

namespace drcom {

/**
 * @brief Configuration management class using singleton pattern
 * 
 * This class manages all configuration parameters for the DRCOM client.
 * It supports loading from configuration files and provides type-safe access.
 */
class Config {
public:
    static Config& getInstance();
    
    // User configuration
    struct UserConfig {
        std::string username{"xiaoming22"};
        std::string password{"xiaoming123456"};
        std::string ip{"192.168.1.100"};
        std::array<uint8_t, 6> mac{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
        std::string hostname{"drcom-client"};
        std::string os_info{"Windows 10"};
        std::string primary_dns{"0.0.0.0"};
        std::string dhcp_server{"0.0.0.0"};
    };
    
    // Server configuration
    struct ServerConfig {
        std::string ip{"10.100.61.3"};
        uint16_t port{61440};
    };
    
    // Client configuration  
    struct ClientConfig {
        std::string ip{"0.0.0.0"};  // bind to any interface
        uint16_t port{61440};
        bool debug_enabled{true};
    };
    
    // Protocol configuration
    struct ProtocolConfig {
        std::array<uint8_t, 2> auth_version{{0x68, 0x00}};
        std::array<uint8_t, 2> keep_alive_version{{0xdc, 0x02}};
        std::array<uint8_t, 2> first_heartbeat_version{{0x0f, 0x27}};
        std::array<uint8_t, 2> extra_heartbeat_version{{0xdb, 0x02}};
        uint8_t control_check_status{0x00};
        uint8_t adapter_num{0x00};
        uint8_t ip_dog{0x01};
        
        // Keep-alive intervals in seconds
        uint32_t auth_interval{20};      // Auth every 20 seconds
        uint32_t heartbeat_interval{12}; // Heartbeat every 12 seconds
    };
    
    // Buffer sizes
    struct BufferSizes {
        static constexpr size_t BUFFER = 512;
        static constexpr size_t SALT = 4;
        static constexpr size_t MD5_PASSWORD = 16;
        static constexpr size_t KEEP_ALIVE_AUTH = 38;
        static constexpr size_t KEEP_ALIVE_HEARTBEAT = 40;
        static constexpr size_t SERVER_DRCOM_INDICATOR = 16;
        static constexpr size_t HEARTBEAT_SERVER_TOKEN = 4;
        static constexpr size_t CHALLENGE = 20;
        static constexpr size_t LOGOUT = 80;
    };
    
    // Getters
    const UserConfig& getUserConfig() const { return user_config_; }
    const ServerConfig& getServerConfig() const { return server_config_; }
    const ClientConfig& getClientConfig() const { return client_config_; }
    const ProtocolConfig& getProtocolConfig() const { return protocol_config_; }
    
    // Setters
    void setUserConfig(const UserConfig& config) { user_config_ = config; }
    void setServerConfig(const ServerConfig& config) { server_config_ = config; }
    void setClientConfig(const ClientConfig& config) { client_config_ = config; }
    void setProtocolConfig(const ProtocolConfig& config) { protocol_config_ = config; }
    
    // Configuration file operations
    bool loadFromFile(const std::string& filename);
    bool saveToFile(const std::string& filename) const;
    
    // Validation
    bool validate() const;
    
private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    UserConfig user_config_;
    ServerConfig server_config_;
    ClientConfig client_config_;
    ProtocolConfig protocol_config_;
    
    // Helper methods
    bool isValidIPAddress(const std::string& ip) const;
    void parseMacAddress(const std::string& mac_str, std::array<uint8_t, 6>& mac) const;
};

} // namespace drcom

#endif // CONFIG_H