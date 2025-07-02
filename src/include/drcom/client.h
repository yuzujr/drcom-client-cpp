#ifndef CLIENT_H
#define CLIENT_H

#include <memory>
#include <thread>
#include <atomic>
#include <future>
#include <chrono>
#include <functional>
#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <mutex>
#include <list>

namespace drcom {

// Forward declarations
class Config;
class Logger;
class UdpSocket;

namespace crypto {
    class MD5;
}

/**
 * @brief DRCOM client states
 */
enum class ClientState {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    AUTHENTICATED,
    KEEPALIVE,
    DISCONNECTING,
    ERROR
};

/**
 * @brief Convert ClientState enum to string
 */
const char* clientStateToString(ClientState state);

/**
 * @brief Event types for client notifications
 */
enum class ClientEvent {
    STATE_CHANGED,
    AUTH_SUCCESS,
    AUTH_FAILED,
    KEEPALIVE_SUCCESS,
    KEEPALIVE_FAILED,
    NETWORK_ERROR,
    SERVER_DISCONNECT
};

/**
 * @brief Client event callback type
 */
using ClientEventCallback = std::function<void(ClientEvent, const std::string&)>;

/**
 * @brief Main DRCOM client implementation
 * 
 * This class provides the core DRCOM protocol implementation with modern C++
 * features like RAII, async operations, and event-driven architecture.
 */
class DrcomClient {
public:
    DrcomClient();
    ~DrcomClient();
    
    // Non-copyable, non-movable (due to complex state)
    DrcomClient(const DrcomClient&) = delete;
    DrcomClient& operator=(const DrcomClient&) = delete;
    DrcomClient(DrcomClient&&) = delete;
    DrcomClient& operator=(DrcomClient&&) = delete;
    
    /**
     * @brief Connect to DRCOM server
     * @return Future that resolves when connection attempt completes
     */
    std::future<bool> connectAsync();
    
    /**
     * @brief Disconnect from DRCOM server
     * @return Future that resolves when disconnection completes
     */
    std::future<bool> disconnectAsync();
    
    /**
     * @brief Synchronous connect (blocks until complete)
     */
    bool connect();
    
    /**
     * @brief Synchronous disconnect (blocks until complete)
     */
    bool disconnect();
    
    /**
     * @brief Get current client state
     */
    ClientState getState() const { return state_.load(); }
    
    /**
     * @brief Check if client is connected and authenticated
     */
    bool isConnected() const { return state_.load() == ClientState::AUTHENTICATED || 
                                      state_.load() == ClientState::KEEPALIVE; }
    
    /**
     * @brief Set event callback for notifications
     */
    void setEventCallback(ClientEventCallback callback) { event_callback_ = std::move(callback); }
    
    /**
     * @brief Get connection statistics
     */
    struct Statistics {
        uint64_t auth_packets_sent{0};
        uint64_t auth_packets_received{0};
        uint64_t heartbeat_packets_sent{0};
        uint64_t heartbeat_packets_received{0};
        uint64_t bytes_sent{0};
        uint64_t bytes_received{0};
        std::chrono::system_clock::time_point last_heartbeat;
        std::chrono::system_clock::time_point connected_since;
    };
    
    const Statistics& getStatistics() const { return stats_; }
    
    /**
     * @brief Force keepalive packet transmission
     */
    void sendKeepalive();
    
private:
    // Configuration and dependencies
    Config& config_;
    Logger& logger_;
    std::unique_ptr<UdpSocket> socket_;
    
    // State management
    std::atomic<ClientState> state_{ClientState::DISCONNECTED};
    ClientEventCallback event_callback_;
    Statistics stats_;
    
    // Protocol state
    std::array<uint8_t, 4> login_salt_{{0}};
    std::array<uint8_t, 4> logout_salt_{{0}};
    std::array<uint8_t, 16> md5_password_{{0}};  // MD5 digest
    std::array<uint8_t, 16> server_drcom_indicator_{{0}};
    std::array<uint8_t, 4> heartbeat_server_token_{{0}};
    uint64_t heartbeat_counter_{0};
    uint64_t auth_counter_{0};
    
    // Threading
    std::thread keepalive_auth_thread_;
    std::thread keepalive_heartbeat_thread_;
    std::thread resend_monitor_thread_;
    std::atomic<bool> stop_threads_{false};
    std::condition_variable stop_cv_;
    std::mutex stop_mutex_;
    
    // Packet tracking for resend mechanism
    struct PacketTracker {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point timestamp;
        int retry_count{0};
    };
    
    std::list<PacketTracker> pending_packets_;
    std::mutex packet_tracker_mutex_;
    
    // Legacy packet trackers (for statistics)
    struct LegacyPacketTracker {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point send_time;
        uint64_t send_count{0};
        uint64_t receive_count{0};
        std::mutex mutex;
    };
    
    LegacyPacketTracker auth_tracker_;
    LegacyPacketTracker heartbeat_tracker_;
    
    // Internal methods
    void setState(ClientState new_state);
    void notifyEvent(ClientEvent event, const std::string& message = "");
    
    // Protocol implementation
    bool performChallenge(bool is_login = true);
    bool performLogin();
    bool performLogout();
    
    // Keep-alive mechanisms
    void keepaliveAuthWorker();
    void keepaliveHeartbeatWorker();
    void resendMonitorWorker();
    
    bool sendKeepAliveAuth();
    bool sendKeepAliveHeartbeat();
    bool sendExtraHeartbeat();
    
    // Packet builders
    std::vector<uint8_t> buildChallengePacket(bool is_login = true);
    std::vector<uint8_t> buildLoginPacket();
    std::vector<uint8_t> buildLogoutPacket();
    std::vector<uint8_t> buildKeepAliveAuthPacket();
    std::vector<uint8_t> buildKeepAliveHeartbeatPacket(bool is_first = false, bool is_extra = false);
    
    // Packet handlers
    bool handleChallengeResponse(const std::vector<uint8_t>& data, bool is_login = true);
    bool handleLoginResponse(const std::vector<uint8_t>& data);
    bool handleLogoutResponse(const std::vector<uint8_t>& data);
    bool handleKeepAliveAuthResponse(const std::vector<uint8_t>& data);
    bool handleKeepAliveHeartbeatResponse(const std::vector<uint8_t>& data);
    
    // Utility methods
    void stopAllThreads();
    void startKeepaliveThreads();
    bool sendAndReceive(const std::vector<uint8_t>& send_data, 
                       std::vector<uint8_t>& receive_data, 
                       int timeout_ms = 15000);
    
    // Interruptible sleep for threads
    bool interruptibleSleep(std::chrono::seconds duration);

    // IP address parsing
    std::array<uint8_t, 4> parseIPAddress(const std::string& ip);
    
    // MAC address parsing  
    std::array<uint8_t, 6> parseMAC(const std::string& mac);
};

/**
 * @brief DRCOM client factory
 */
class DrcomClientFactory {
public:
    /**
     * @brief Create a new DRCOM client instance
     */
    static std::unique_ptr<DrcomClient> create();
};

} // namespace drcom

#endif // CLIENT_H