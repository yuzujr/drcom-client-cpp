#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#endif

#include "drcom/client.h"
#include "drcom/config.h"
#include "drcom/logger.h"
#include "drcom/network.h"
#include "drcom/crypto.h"

#include <algorithm>
#include <thread>
#include <chrono>
#include <mutex>
#include <ctime>
#include <random>

namespace drcom {
namespace {
constexpr int kKeepaliveTimeoutMs = 500;
constexpr int kDisconnectTimeoutMs = 500;

uint8_t randomByte() {
    thread_local std::mt19937 generator([] {
        std::random_device device;
        std::seed_seq seed{device(), device(), device(), device()};
        return std::mt19937(seed);
    }());
    thread_local std::uniform_int_distribution<int> distribution(0, 0xff);

    return static_cast<uint8_t>(distribution(generator));
}
}  // namespace

// ================= Helper Functions =================
const char* clientStateToString(ClientState state) {
    switch (state) {
        case ClientState::DISCONNECTED:   return "DISCONNECTED";
        case ClientState::CONNECTING:     return "CONNECTING";
        case ClientState::AUTHENTICATING: return "AUTHENTICATING";
        case ClientState::AUTHENTICATED:  return "AUTHENTICATED";
        case ClientState::KEEPALIVE:      return "KEEPALIVE";
        case ClientState::DISCONNECTING:  return "DISCONNECTING";
        case ClientState::CLIENT_ERROR:   return "ERROR";
        default:                          return "UNKNOWN";
    }
}

const char* disconnectReasonToString(DisconnectReason reason) {
    switch (reason) {
        case DisconnectReason::NONE: return "NONE";
        case DisconnectReason::NETWORK_ERROR: return "NETWORK_ERROR";
        case DisconnectReason::AUTH_FAILURE: return "AUTH_FAILURE";
        case DisconnectReason::KEEPALIVE_FAILURE: return "KEEPALIVE_FAILURE";
        case DisconnectReason::SERVER_DISCONNECT: return "SERVER_DISCONNECT";
        case DisconnectReason::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
        default: return "UNKNOWN";
    }
}

// ================= DrcomClient Implementation =================
DrcomClient::DrcomClient() 
    : config_(Config::getInstance())
    , logger_(Logger::getInstance())
    , socket_(std::make_unique<UdpSocket>()) {
    
    logger_.debug("DrcomClient created");
}

DrcomClient::~DrcomClient() {
    if (isConnected()) {
        disconnect();
    }
    stopAllThreads();
    logger_.debug("DrcomClient destroyed");
}

DrcomClient::Statistics DrcomClient::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

DisconnectReason DrcomClient::getLastDisconnectReason() const {
    std::lock_guard<std::mutex> lock(disconnect_status_mutex_);
    return last_disconnect_reason_;
}

std::string DrcomClient::getLastDisconnectMessage() const {
    std::lock_guard<std::mutex> lock(disconnect_status_mutex_);
    return last_disconnect_message_;
}

bool DrcomClient::shouldReconnect() const {
    switch (getLastDisconnectReason()) {
        case DisconnectReason::NETWORK_ERROR:
        case DisconnectReason::KEEPALIVE_FAILURE:
        case DisconnectReason::SERVER_DISCONNECT:
            return true;
        case DisconnectReason::NONE:
        case DisconnectReason::AUTH_FAILURE:
        case DisconnectReason::PROTOCOL_ERROR:
            return false;
        default:
            return false;
    }
}

std::future<bool> DrcomClient::connectAsync() {
    return std::async(std::launch::async, [this]() {
        return connect();
    });
}

std::future<bool> DrcomClient::disconnectAsync() {
    return std::async(std::launch::async, [this]() {
        return disconnect();
    });
}

bool DrcomClient::connect() {
    clearDisconnectStatus();
    setState(ClientState::CONNECTING);
    
    try {
        // Initialize network if needed
        if (!NetworkManager::getInstance().isInitialized()) {
            const std::string message = "Network initialization failed";
            logger_.error(message);
            setDisconnectStatus(DisconnectReason::NETWORK_ERROR, message);
            notifyEvent(ClientEvent::NETWORK_ERROR, message);
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        // Bind to local address
        NetworkAddress local_addr{config_.getClientConfig().ip, config_.getClientConfig().port};
        auto bind_result = socket_->bind(local_addr);
        if (bind_result) {
            logger_.error("Failed to bind to local address: {}", bind_result.message());
            setDisconnectStatus(DisconnectReason::NETWORK_ERROR, bind_result.message());
            notifyEvent(ClientEvent::NETWORK_ERROR, bind_result.message());
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        // Connect to server
        NetworkAddress server_addr{config_.getServerConfig().ip, config_.getServerConfig().port};
        auto connect_result = socket_->connect(server_addr);
        if (connect_result) {
            logger_.error("Failed to connect to server: {}", connect_result.message());
            setDisconnectStatus(DisconnectReason::NETWORK_ERROR, connect_result.message());
            notifyEvent(ClientEvent::NETWORK_ERROR, connect_result.message());
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        setState(ClientState::AUTHENTICATING);
        
        // Perform challenge and login
        std::string error_message;
        DisconnectReason disconnect_reason = DisconnectReason::NONE;
        if (!performChallenge(true, 15000, &error_message, &disconnect_reason)) {
            logger_.error("Challenge failed: {}", error_message);
            setDisconnectStatus(disconnect_reason, error_message);
            notifyEvent(disconnect_reason == DisconnectReason::NETWORK_ERROR
                             ? ClientEvent::NETWORK_ERROR
                             : ClientEvent::AUTH_FAILED,
                         error_message);
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        if (!performLogin(&error_message, &disconnect_reason)) {
            logger_.error("Login failed: {}", error_message);
            setDisconnectStatus(disconnect_reason, error_message);
            notifyEvent(disconnect_reason == DisconnectReason::NETWORK_ERROR
                             ? ClientEvent::NETWORK_ERROR
                             : ClientEvent::AUTH_FAILED,
                         error_message);
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        setState(ClientState::AUTHENTICATED);
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.connected_since = std::chrono::system_clock::now();
        }
        
        // Start the keep-alive scheduler
        startKeepaliveThread();
        
        setState(ClientState::KEEPALIVE);
        notifyEvent(ClientEvent::AUTH_SUCCESS, "Successfully authenticated");
        
        return true;
        
    } catch (const std::exception& e) {
        logger_.error("Exception during connection: {}", e.what());
        setDisconnectStatus(DisconnectReason::NETWORK_ERROR, e.what());
        setState(ClientState::CLIENT_ERROR);
        notifyEvent(ClientEvent::NETWORK_ERROR, e.what());
        return false;
    }
}

bool DrcomClient::disconnect() {
    if (!isConnected()) {
        return true;
    }
    
    setState(ClientState::DISCONNECTING);
    
    try {
        // Stop keep-alive threads
        stopAllThreads();
        
        // Perform logout sequence
        if (!performChallenge(false, kDisconnectTimeoutMs)) {
            logger_.warn("Logout challenge failed");
        }
        
        if (!performLogout(kDisconnectTimeoutMs)) {
            logger_.warn("Logout failed");
        }
        
        // Close socket
        socket_->close();
        clearDisconnectStatus();
        
        setState(ClientState::DISCONNECTED);
        logger_.info("Disconnected successfully");
        
        return true;
        
    } catch (const std::exception& e) {
        logger_.error("Exception during disconnection: {}", e.what());
        setDisconnectStatus(DisconnectReason::NETWORK_ERROR, e.what());
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
}

void DrcomClient::sendKeepalive() {
    if (isConnected()) {
        sendKeepAliveAuth();
        sendKeepAliveHeartbeat();
    }
}

void DrcomClient::setState(ClientState new_state) {
    auto old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        notifyEvent(ClientEvent::STATE_CHANGED, std::format("State changed from {} to {}", 
            clientStateToString(old_state), clientStateToString(new_state)));
    }
}

void DrcomClient::notifyEvent(ClientEvent event, const std::string& message) {
    if (event_callback_) {
        event_callback_(event, message);
    }
}

void DrcomClient::clearDisconnectStatus() {
    std::lock_guard<std::mutex> lock(disconnect_status_mutex_);
    last_disconnect_reason_ = DisconnectReason::NONE;
    last_disconnect_message_.clear();
}

void DrcomClient::setDisconnectStatus(DisconnectReason reason, std::string message) {
    std::lock_guard<std::mutex> lock(disconnect_status_mutex_);
    last_disconnect_reason_ = reason;
    last_disconnect_message_ = std::move(message);
}

// Simplified protocol implementation (placeholder)
bool DrcomClient::performChallenge(bool is_login, int timeout_ms,
                                   std::string* error_message,
                                   DisconnectReason* disconnect_reason) {
    logger_.debug("Performing challenge (login={})", is_login);
    
    auto challenge_packet = buildChallengePacket(is_login);
    logger_.logChallengeSend(challenge_packet);
    std::vector<uint8_t> response;
    
    std::string transport_error;
    if (!sendAndReceive(challenge_packet, response, timeout_ms, &transport_error)) {
        if (error_message) {
            *error_message = std::format("Challenge request failed: {}", transport_error);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::NETWORK_ERROR;
        }
        return false;
    }
    
    return handleChallengeResponse(response, is_login, error_message, disconnect_reason);
}

bool DrcomClient::performLogin(std::string* error_message,
                               DisconnectReason* disconnect_reason) {
    logger_.debug("Performing login");
    
    auto login_packet = buildLoginPacket();
    logger_.logAuthSend(login_packet);
    std::vector<uint8_t> response;
    
    std::string transport_error;
    if (!sendAndReceive(login_packet, response, 15000, &transport_error)) {
        if (error_message) {
            *error_message = std::format("Login request failed: {}", transport_error);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::NETWORK_ERROR;
        }
        return false;
    }
    
    return handleLoginResponse(response, error_message, disconnect_reason);
}

bool DrcomClient::performLogout(int timeout_ms, std::string* error_message,
                                DisconnectReason* disconnect_reason) {
    logger_.debug("Performing logout");
    
    auto logout_packet = buildLogoutPacket();
    logger_.logLogoutSend(logout_packet);
    std::vector<uint8_t> response;
    
    std::string transport_error;
    if (!sendAndReceive(logout_packet, response, timeout_ms, &transport_error)) {
        if (error_message) {
            *error_message = std::format("Logout request failed: {}", transport_error);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::NETWORK_ERROR;
        }
        return false;
    }
    
    return handleLogoutResponse(response, error_message, disconnect_reason);
}

void DrcomClient::startKeepaliveThread() {
    stop_threads_ = false;
    
    keepalive_thread_ = std::thread(&DrcomClient::keepaliveWorker, this);
}

void DrcomClient::stopAllThreads() {
    stop_threads_ = true;
    
    // Notify all waiting threads
    stop_cv_.notify_all();
    
    if (keepalive_thread_.joinable()) {
        keepalive_thread_.join();
    }
}

bool DrcomClient::interruptibleWaitUntil(std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(stop_mutex_);
    return !stop_cv_.wait_until(lock, deadline, [this] { return stop_threads_.load(); });
}

void DrcomClient::keepaliveWorker() {
    const auto auth_interval =
        std::chrono::seconds(config_.getProtocolConfig().auth_interval);
    const auto heartbeat_interval =
        std::chrono::seconds(config_.getProtocolConfig().heartbeat_interval);

    auto next_auth = std::chrono::steady_clock::now();
    auto next_heartbeat = next_auth;

    while (!stop_threads_ && isConnected()) {
        auto now = std::chrono::steady_clock::now();
        bool did_work = false;

        if (now >= next_auth) {
            if (!sendKeepAliveAuth()) {
                break;
            }
            next_auth = std::chrono::steady_clock::now() + auth_interval;
            did_work = true;
        }

        if (!stop_threads_ && isConnected() && std::chrono::steady_clock::now() >= next_heartbeat) {
            if (!sendKeepAliveHeartbeat()) {
                break;
            }
            next_heartbeat = std::chrono::steady_clock::now() + heartbeat_interval;
            did_work = true;
        }

        if (did_work) {
            continue;
        }

        const auto next_deadline = std::min(next_auth, next_heartbeat);
        if (!interruptibleWaitUntil(next_deadline)) {
            break;
        }
    }
}

bool DrcomClient::sendKeepAliveAuth() {
    logger_.debug("Sending keep-alive auth");
    
    auto packet = buildKeepAliveAuthPacket();
    logger_.logKeepAliveSend(packet);
    std::vector<uint8_t> response;
    
    std::string error_message;
    if (!sendAndReceive(packet, response, kKeepaliveTimeoutMs, &error_message)) {
        const auto message = std::format("Keep-alive auth failed: {}", error_message);
        logger_.error(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveAuthResponse(response, &error_message, &disconnect_reason);
    if (!success) {
        logger_.error(error_message);
        setDisconnectStatus(disconnect_reason, error_message);
        notifyEvent(disconnect_reason == DisconnectReason::SERVER_DISCONNECT
                         ? ClientEvent::SERVER_DISCONNECT
                         : ClientEvent::KEEPALIVE_FAILED,
                     error_message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }

    auth_counter_++;
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.auth_packets_sent++;
    
    return true;
}

bool DrcomClient::sendKeepAliveHeartbeat() {
    logger_.debug("Sending keep-alive heartbeat");
    
    bool is_first = (heartbeat_counter_ == 0);
    bool is_extra = (heartbeat_counter_ % 21 == 0 && heartbeat_counter_ > 0);
    
    auto packet = buildKeepAliveHeartbeatPacket(is_first, is_extra);
    logger_.logHeartbeatSend(packet);
    std::vector<uint8_t> response;
    
    std::string error_message;
    if (!sendAndReceive(packet, response, kKeepaliveTimeoutMs, &error_message)) {
        const auto message = std::format("Keep-alive heartbeat failed: {}", error_message);
        logger_.error(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveHeartbeatResponse(response, &error_message,
                                                    &disconnect_reason);
    if (!success) {
        logger_.error(error_message);
        setDisconnectStatus(disconnect_reason, error_message);
        notifyEvent(disconnect_reason == DisconnectReason::SERVER_DISCONNECT
                         ? ClientEvent::SERVER_DISCONNECT
                         : ClientEvent::KEEPALIVE_FAILED,
                     error_message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }

    heartbeat_counter_++;
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.heartbeat_packets_sent++;
        stats_.last_heartbeat = std::chrono::system_clock::now();
    }
    
    // Send extra heartbeat if needed
    if (is_extra && !sendExtraHeartbeat()) {
        return false;
    }
    
    return true;
}

bool DrcomClient::sendExtraHeartbeat() {
    logger_.debug("Sending extra heartbeat");
    
    auto packet = buildKeepAliveHeartbeatPacket(false, true);
    logger_.logHeartbeatSend(packet);
    std::vector<uint8_t> response;
    
    std::string error_message;
    if (!sendAndReceive(packet, response, kKeepaliveTimeoutMs, &error_message)) {
        const auto message = std::format("Extra heartbeat failed: {}", error_message);
        logger_.error(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveHeartbeatResponse(response, &error_message,
                                                    &disconnect_reason);
    if (!success) {
        logger_.error(error_message);
        setDisconnectStatus(disconnect_reason, error_message);
        notifyEvent(disconnect_reason == DisconnectReason::SERVER_DISCONNECT
                         ? ClientEvent::SERVER_DISCONNECT
                         : ClientEvent::KEEPALIVE_FAILED,
                     error_message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }

    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.heartbeat_packets_sent++;
    stats_.last_heartbeat = std::chrono::system_clock::now();

    return true;
}

// Placeholder packet builders
std::vector<uint8_t> DrcomClient::buildChallengePacket(bool is_login) {
    std::vector<uint8_t> packet(20);
    packet[0] = 0x01;
    packet[1] = is_login ? 0x02 : 0x03;
    packet[2] = randomByte();
    packet[3] = randomByte();
    // Add auth version
    auto& protocol = config_.getProtocolConfig();
    packet[4] = protocol.auth_version[0];
    packet[5] = protocol.auth_version[1];
    return packet;
}

std::vector<uint8_t> DrcomClient::buildLoginPacket() {
    const auto& user_config = config_.getUserConfig();
    const auto& protocol_config = config_.getProtocolConfig();
    
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
    md5a_plain.insert(md5a_plain.end(), login_salt_.begin(), login_salt_.end());
    md5a_plain.insert(md5a_plain.end(), user_config.password.begin(), user_config.password.end());
    
    auto md5a = crypto::MD5::hash(md5a_plain);
    std::copy(md5a.begin(), md5a.end(), packet.begin() + 4);
    std::copy(md5a.begin(), md5a.end(), md5_password_.begin());
    
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
    md5b_plain.insert(md5b_plain.end(), login_salt_.begin(), login_salt_.end());
    md5b_plain.insert(md5b_plain.end(), 4, 0x00);  // 4 zero bytes
    
    auto md5b = crypto::MD5::hash(md5b_plain);
    std::copy(md5b.begin(), md5b.end(), packet.begin() + 64);
    
    // IP indicator
    packet[80] = 0x01;
    
    // Client IP (4 bytes)
    auto ip_bytes = parseIPAddress(user_config.ip);
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
    auto dns_bytes = parseIPAddress(user_config.primary_dns);
    std::copy(dns_bytes.begin(), dns_bytes.end(), packet.begin() + 142);
    
    // DHCP server (4 bytes)  
    auto dhcp_bytes = parseIPAddress(user_config.dhcp_server);
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
    
    // Remaining fields are zero-padded and handled by protocol-specific logic
    // Password length calculation and additional fields at offset 246+ 
    
    return packet;
}

std::vector<uint8_t> DrcomClient::buildLogoutPacket() {
    std::vector<uint8_t> packet(80, 0);
    const auto& user_config = config_.getUserConfig();
    
    // Header: 0x06 0x01 0x00 username_len+20
    packet[0] = 0x06;
    packet[1] = 0x01;
    packet[2] = 0x00;
    packet[3] = static_cast<uint8_t>(user_config.username.length() + 20);
    
    // MD5 password (16 bytes at offset 4-19)
    std::copy(md5_password_.begin(), md5_password_.end(), packet.begin() + 4);
    
    // Username (36 bytes at offset 20-55)
    const size_t username_copy_len = std::min(user_config.username.length(), static_cast<size_t>(36));
    std::copy(user_config.username.begin(), 
              user_config.username.begin() + username_copy_len, 
              packet.begin() + 20);
    
    // Control check status and adapter num
    const auto& protocol_config = config_.getProtocolConfig();
    packet[56] = protocol_config.control_check_status;
    packet[57] = protocol_config.adapter_num;
    
    // MAC XOR MD5 password (6 bytes at offset 58-63)
    for (size_t i = 0; i < 6; ++i) {
        packet[58 + i] = user_config.mac[i] ^ md5_password_[i];
    }
    
    // Logout salt (4 bytes at offset 64-67) if available
    if (!std::all_of(logout_salt_.begin(), logout_salt_.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(logout_salt_.begin(), logout_salt_.end(), packet.begin() + 64);
    }
    
    // Remaining bytes 68-79 are zero-padded (already initialized)
    
    return packet;
}

std::vector<uint8_t> DrcomClient::buildKeepAliveAuthPacket() {
    std::vector<uint8_t> packet(38, 0);
    
    // Header: 0xff + MD5 password (16 bytes)
    packet[0] = 0xff;
    std::copy(md5_password_.begin(), md5_password_.end(), packet.begin() + 1);
    
    // Zero padding bytes at offset 17-19 (3 bytes, already initialized)
    
    // Server DRCOM indicator (16 bytes at offset 20-35)
    if (!std::all_of(server_drcom_indicator_.begin(), server_drcom_indicator_.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(server_drcom_indicator_.begin(), server_drcom_indicator_.end(), 
                  packet.begin() + 20);
    }
    
    // Timestamp (2 bytes at offset 36-37)
    time_t time_now = time(NULL);
    packet[36] = static_cast<uint8_t>(time_now % (2 << 7));
    time_now /= (2 << 7);
    packet[37] = static_cast<uint8_t>(time_now % (2 << 7));
    
    return packet;
}

std::vector<uint8_t> DrcomClient::buildKeepAliveHeartbeatPacket(bool is_first, bool is_extra) {
    std::vector<uint8_t> packet(40, 0);
    const auto& protocol_config = config_.getProtocolConfig();
    
    // Header: 0x07 + heartbeat counter (1 byte)
    packet[0] = 0x07;
    packet[1] = static_cast<uint8_t>(heartbeat_counter_ & 0xff);
    
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
    packet[8] = randomByte();
    packet[9] = randomByte();
    packet[10] = randomByte();
    packet[11] = randomByte();
    
    // Zero padding at offset 12-15 (already initialized)
    
    // Server token (4 bytes at offset 16-19) if available
    if (!std::all_of(heartbeat_server_token_.begin(), heartbeat_server_token_.end(), 
                     [](uint8_t b) { return b == 0; })) {
        std::copy(heartbeat_server_token_.begin(), heartbeat_server_token_.end(), 
                  packet.begin() + 16);
    }
    
    // CRC checksum at offset 20-23 (4 bytes)
    // Calculate CRC over first 20 bytes
    auto crc_bytes = crypto::CRC::calculate(std::vector<uint8_t>(packet.begin(), packet.begin() + 20), 4);
    std::copy(crc_bytes.begin(), crc_bytes.end(), packet.begin() + 20);
    
    // Client IP at offset 24-27
    const auto& user_config = config_.getUserConfig();
    auto ip_bytes = parseIPAddress(user_config.ip);
    std::copy(ip_bytes.begin(), ip_bytes.end(), packet.begin() + 24);
    
    // Zero padding for remaining bytes 28-39 (already initialized)
    
    return packet;
}

// Placeholder packet handlers
bool DrcomClient::handleChallengeResponse(const std::vector<uint8_t>& data, bool is_login,
                                          std::string* error_message,
                                          DisconnectReason* disconnect_reason) {
    if (data.size() < 8) {
        if (error_message) {
            *error_message = std::format("Challenge response too short: {} bytes", data.size());
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[0] != 0x02) {
        if (error_message) {
            *error_message = std::format("Unexpected challenge response type: 0x{:02x}", data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[1] != 0x00) {
        if (error_message) {
            *error_message = std::format("Challenge rejected with status 0x{:02x}", data[1]);
        }
        if (disconnect_reason) {
            *disconnect_reason = is_login ? DisconnectReason::AUTH_FAILURE
                                          : DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    // Extract salt
    if (is_login) {
        std::copy(data.begin() + 4, data.begin() + 8, login_salt_.begin());
        logger_.logChallengeReceive(data);
    } else {
        std::copy(data.begin() + 4, data.begin() + 8, logout_salt_.begin());
    }

    return true;
}

bool DrcomClient::handleLoginResponse(const std::vector<uint8_t>& data,
                                      std::string* error_message,
                                      DisconnectReason* disconnect_reason) {
    logger_.logAuthReceive(data);

    if (data.size() < 39) {
        if (error_message) {
            *error_message = std::format("Login response too short: {} bytes", data.size());
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[0] != 0x04) {
        if (error_message) {
            *error_message = std::format("Unexpected login response type: 0x{:02x}", data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[1] != 0x00) {
        if (error_message) {
            *error_message = std::format("Authentication rejected with status 0x{:02x}", data[1]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::AUTH_FAILURE;
        }
        return false;
    }
    
    // Extract server indicators
    std::copy(data.begin() + 23, data.begin() + 39, server_drcom_indicator_.begin());
    return true;
}

bool DrcomClient::handleLogoutResponse(const std::vector<uint8_t>& data,
                                       std::string* error_message,
                                       DisconnectReason* disconnect_reason) {
    logger_.logLogoutReceive(data);

    if (data.size() < 2) {
        if (error_message) {
            *error_message = std::format("Logout response too short: {} bytes", data.size());
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[0] != 0x05) {
        if (error_message) {
            *error_message = std::format("Unexpected logout response type: 0x{:02x}", data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[1] != 0x00) {
        if (error_message) {
            *error_message = std::format("Logout rejected with status 0x{:02x}", data[1]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    return true;
}

bool DrcomClient::handleKeepAliveAuthResponse(const std::vector<uint8_t>& data,
                                              std::string* error_message,
                                              DisconnectReason* disconnect_reason) {
    logger_.logKeepAliveReceive(data);

    if (data.size() < 2) {
        if (error_message) {
            *error_message = std::format("Keep-alive auth response too short: {} bytes",
                                         data.size());
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[0] != 0xff) {
        if (error_message) {
            *error_message = std::format("Unexpected keep-alive auth response type: 0x{:02x}",
                                         data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::SERVER_DISCONNECT;
        }
        return false;
    }

    if (data[1] != 0x00) {
        if (error_message) {
            *error_message = std::format("Keep-alive auth rejected with status 0x{:02x}",
                                         data[1]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::SERVER_DISCONNECT;
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.auth_packets_received++;
    return true;
}

bool DrcomClient::handleKeepAliveHeartbeatResponse(const std::vector<uint8_t>& data,
                                                   std::string* error_message,
                                                   DisconnectReason* disconnect_reason) {
    logger_.logHeartbeatReceive(data);

    if (data.size() < 20) {
        if (error_message) {
            *error_message = std::format("Heartbeat response too short: {} bytes", data.size());
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        }
        return false;
    }

    if (data[0] != 0x07) {
        if (error_message) {
            *error_message = std::format("Unexpected heartbeat response type: 0x{:02x}", data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::SERVER_DISCONNECT;
        }
        return false;
    }

    if (data[1] != 0x00) {
        if (error_message) {
            *error_message = std::format("Heartbeat rejected with status 0x{:02x}", data[1]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::SERVER_DISCONNECT;
        }
        return false;
    }

    std::copy(data.begin() + 16, data.begin() + 20, heartbeat_server_token_.begin());
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.heartbeat_packets_received++;
    return true;
}

bool DrcomClient::sendAndReceive(const std::vector<uint8_t>& send_data, 
                                std::vector<uint8_t>& receive_data, 
                                int timeout_ms,
                                std::string* error_message) {
    if (!socket_->isValid()) {
        if (error_message) {
            *error_message = "Socket is not valid";
        }
        return false;
    }

    std::lock_guard<std::mutex> io_lock(socket_io_mutex_);
    
    // Set timeout
    auto timeout_error = socket_->setTimeout(timeout_ms);
    if (timeout_error) {
        logger_.error("Failed to set socket timeout: {}", timeout_error.message());
        if (error_message) {
            *error_message = std::format("Failed to set socket timeout: {}",
                                         timeout_error.message());
        }
        return false;
    }
    
    // Send data
    auto [sent, send_error] = socket_->send(send_data);
    if (send_error) {
        logger_.error("Send failed: {}", send_error.message());
        if (error_message) {
            *error_message = std::format("Send failed: {}", send_error.message());
        }
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_sent += sent;
    }
    
    // Receive response
    auto [received, recv_error] = socket_->receive(receive_data);
    if (recv_error) {
        logger_.error("Receive failed: {}", recv_error.message());
        if (error_message) {
            *error_message = std::format("Receive failed: {}", recv_error.message());
        }
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_received += received;
    }
    return true;
}

std::array<uint8_t, 4> DrcomClient::parseIPAddress(const std::string& ip) {
    std::array<uint8_t, 4> result{};
    
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        size_t end = ip.find('.', start);
        if (end == std::string::npos && i < 3) break;
        if (end == std::string::npos) end = ip.length();
        
        std::string octet = ip.substr(start, end - start);
        result[i] = static_cast<uint8_t>(std::stoi(octet));
        start = end + 1;
    }
    
    return result;
}

std::array<uint8_t, 6> DrcomClient::parseMAC(const std::string& mac) {
    std::array<uint8_t, 6> result{};
    
    if (mac.length() >= 6) {
        // Handle binary MAC format (6 bytes)
        for (size_t i = 0; i < 6; ++i) {
            result[i] = static_cast<uint8_t>(mac[i]);
        }
    } else {
        // Handle string MAC format like "00:11:22:33:44:55"
        size_t start = 0;
        for (int i = 0; i < 6; ++i) {
            size_t end = mac.find(':', start);
            if (end == std::string::npos && i < 5) break;
            if (end == std::string::npos) end = mac.length();
            
            std::string octet = mac.substr(start, end - start);
            result[i] = static_cast<uint8_t>(std::stoi(octet, nullptr, 16));
            start = end + 1;
        }
    }
    
    return result;
}

// ================= DrcomClientFactory =================
std::unique_ptr<DrcomClient> DrcomClientFactory::create() {
    return std::make_unique<DrcomClient>();
}

} // namespace drcom
