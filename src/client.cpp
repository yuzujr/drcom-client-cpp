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
constexpr int kKeepaliveTimeoutMs = 2000;
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

std::string receiveErrorMessage(const std::error_code& error) {
    if (error == std::make_error_code(std::errc::timed_out)) {
        return "Connection timed out";
    }
    return error.message();
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
DrcomClient::DrcomClient() : DrcomClient(Config::getInstance()) {}

DrcomClient::DrcomClient(Config& config)
    : config_(config)
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
        case DisconnectReason::PROTOCOL_ERROR:
            return true;
        case DisconnectReason::NONE:
        case DisconnectReason::AUTH_FAILURE:
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
            logger_.debug(message);
            setDisconnectStatus(DisconnectReason::NETWORK_ERROR, message);
            notifyEvent(ClientEvent::NETWORK_ERROR, message);
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        // Bind to local address
        NetworkAddress local_addr{config_.getClientConfig().ip, config_.getClientConfig().port};
        auto bind_result = socket_->bind(local_addr);
        if (bind_result) {
            logger_.debug("Failed to bind to local address: {}", bind_result.message());
            setDisconnectStatus(DisconnectReason::NETWORK_ERROR, bind_result.message());
            notifyEvent(ClientEvent::NETWORK_ERROR, bind_result.message());
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        // Connect to server
        NetworkAddress server_addr{config_.getServerConfig().ip, config_.getServerConfig().port};
        auto connect_result = socket_->connect(server_addr);
        if (connect_result) {
            logger_.debug("Failed to connect to server: {}", connect_result.message());
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
            logger_.debug("Challenge failed: {}", error_message);
            setDisconnectStatus(disconnect_reason, error_message);
            notifyEvent(disconnect_reason == DisconnectReason::NETWORK_ERROR
                             ? ClientEvent::NETWORK_ERROR
                             : ClientEvent::AUTH_FAILED,
                         error_message);
            setState(ClientState::CLIENT_ERROR);
            return false;
        }
        
        if (!performLogin(&error_message, &disconnect_reason)) {
            logger_.debug("Login failed: {}", error_message);
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
        
        // Publish success before the worker can report a maintenance failure.
        setState(ClientState::KEEPALIVE);
        notifyEvent(ClientEvent::AUTH_SUCCESS, "Successfully authenticated");
        startKeepaliveThread();
        
        return true;
        
    } catch (const std::exception& e) {
        logger_.debug("Exception during connection: {}", e.what());
        setDisconnectStatus(DisconnectReason::NETWORK_ERROR, e.what());
        setState(ClientState::CLIENT_ERROR);
        notifyEvent(ClientEvent::NETWORK_ERROR, e.what());
        return false;
    }
}

void DrcomClient::stop() {
    stopAllThreads();
    socket_->close();
    clearDisconnectStatus();
    setState(ClientState::DISCONNECTED);
}

bool DrcomClient::disconnect() {
    if (!isConnected()) {
        return true;
    }
    
    setState(ClientState::DISCONNECTING);
    
    try {
        // Stop keep-alive threads
        stopAllThreads();
        
        // Cancellation is for ongoing authentication, not explicit logout.
        cancellation_callback_ = {};
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
        if (sendKeepAliveAuth()) sendKeepAliveHeartbeat();
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

// Protocol exchanges
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
    std::lock_guard<std::mutex> exchange_lock(keepalive_exchange_mutex_);
    if (!isConnected() || stop_threads_) return false;
    logger_.debug("Sending keep-alive auth");
    
    auto packet = buildKeepAliveAuthPacket();
    logger_.logKeepAliveSend(packet);
    std::vector<uint8_t> response;
    
    std::string error_message;
    if (!sendAndReceive(packet, response, kKeepaliveTimeoutMs, &error_message)) {
        const auto message = std::format("Keep-alive auth failed: {}", error_message);
        logger_.debug(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveAuthResponse(response, &error_message, &disconnect_reason);
    if (!success) {
        logger_.debug(error_message);
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
    std::lock_guard<std::mutex> exchange_lock(keepalive_exchange_mutex_);
    if (!isConnected() || stop_threads_) return false;
    logger_.debug("Sending keep-alive heartbeat");
    
    bool is_first = (heartbeat_counter_ == 0);
    bool is_extra = (heartbeat_counter_ % 21 == 0 && heartbeat_counter_ > 0);
    
    auto packet = buildKeepAliveHeartbeatPacket(is_first, is_extra);
    logger_.logHeartbeatSend(packet);
    std::vector<uint8_t> response;
    
    std::string error_message;
    if (!sendAndReceive(packet, response, kKeepaliveTimeoutMs, &error_message)) {
        const auto message = std::format("Keep-alive heartbeat failed: {}", error_message);
        logger_.debug(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveHeartbeatResponse(response, &error_message,
                                                    &disconnect_reason);
    if (!success) {
        logger_.debug(error_message);
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
        logger_.debug(message);
        setDisconnectStatus(DisconnectReason::KEEPALIVE_FAILURE, message);
        notifyEvent(ClientEvent::KEEPALIVE_FAILED, message);
        setState(ClientState::CLIENT_ERROR);
        return false;
    }
    
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    bool success = handleKeepAliveHeartbeatResponse(response, &error_message,
                                                    &disconnect_reason);
    if (!success) {
        logger_.debug(error_message);
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
    return protocol::buildChallengePacket(config_, is_login, {randomByte(), randomByte()});
}
std::vector<uint8_t> DrcomClient::buildLoginPacket() {
    auto packet = protocol::buildLoginPacket(config_, session_);
    std::copy_n(packet.begin() + 4, 16, session_.md5_password.begin());
    return packet;
}
std::vector<uint8_t> DrcomClient::buildLogoutPacket() {
    return protocol::buildLogoutPacket(config_, session_);
}
std::vector<uint8_t> DrcomClient::buildKeepAliveAuthPacket() {
    return protocol::buildKeepAliveAuthPacket(session_, static_cast<uint64_t>(std::time(nullptr)));
}
std::vector<uint8_t> DrcomClient::buildKeepAliveHeartbeatPacket(bool is_first, bool is_extra) {
    return protocol::buildKeepAliveHeartbeatPacket(config_, session_, heartbeat_counter_,
        is_first, is_extra, {randomByte(), randomByte(), randomByte(), randomByte()});
}

// Response validation
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

    const uint8_t expected_subtype = is_login ? 0x02 : 0x03;
    if (data[1] != 0x00 && data[1] != expected_subtype) {
        logger_.debug("Unexpected challenge subtype/reserved byte: 0x{:02x}", data[1]);
    }

    // Extract salt
    if (is_login) {
        std::copy(data.begin() + 4, data.begin() + 8, session_.login_salt.begin());
        logger_.logChallengeReceive(data);
    } else {
        std::copy(data.begin() + 4, data.begin() + 8, session_.logout_salt.begin());
    }

    return true;
}

bool DrcomClient::handleLoginResponse(const std::vector<uint8_t>& data,
                                      std::string* error_message,
                                      DisconnectReason* disconnect_reason) {
    logger_.logAuthReceive(data);

    if (data.size() < 2) {
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
    
    if (data.size() < 39) {
        if (error_message) *error_message = "Successful login response too short";
        if (disconnect_reason) *disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
        return false;
    }
    // Extract server indicators
    std::copy(data.begin() + 23, data.begin() + 39, session_.server_drcom_indicator.begin());
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

    if (data[0] != 0xff && data[0] != 0x07) {
        if (error_message) {
            *error_message = std::format("Unexpected keep-alive auth response type: 0x{:02x}",
                                         data[0]);
        }
        if (disconnect_reason) {
            *disconnect_reason = DisconnectReason::SERVER_DISCONNECT;
        }
        return false;
    }

    if (data.size() >= 20) {
        std::copy(data.begin() + 16, data.begin() + 20, session_.heartbeat_server_token.begin());
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

    std::copy(data.begin() + 16, data.begin() + 20, session_.heartbeat_server_token.begin());
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
    
    if (cancellation_callback_ && cancellation_callback_()) {
        if (error_message) *error_message = "Operation cancelled";
        return false;
    }
    // Set timeout
    auto timeout_error = socket_->setTimeout(timeout_ms);
    if (timeout_error) {
        logger_.debug("Failed to set socket timeout: {}", timeout_error.message());
        if (error_message) {
            *error_message = std::format("Failed to set socket timeout: {}",
                                         timeout_error.message());
        }
        return false;
    }
    
    // Send data
    auto [sent, send_error] = socket_->send(send_data);
    if (send_error) {
        logger_.debug("Send failed: {}", send_error.message());
        if (error_message) {
            *error_message = std::format("Send failed: {}", send_error.message());
        }
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_sent += sent;
    }
    
    // Ignore complete responses from other exchanges, without extending the
    // deadline. The 0x07 auth/heartbeat formats overlap; do not guess a sequence
    // correlation rule without evidence from a real server.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const auto request = send_data.at(0);
    const bool maintenance = request == 0xff || request == 0x07;
    const auto cancelled = [this, maintenance] {
        return (maintenance && stop_threads_.load()) ||
               (cancellation_callback_ && cancellation_callback_());
    };
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
            if (error_message) *error_message = "Receive deadline exceeded";
            return false;
        }
        auto [received, recv_error] = socket_->receiveInterruptibly(
            receive_data, static_cast<int>(remaining), cancelled);
        if (recv_error) {
            if (error_message) {
                *error_message = std::format("Receive failed: {}", receiveErrorMessage(recv_error));
            }
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.bytes_received += received;
        }
        if (receive_data.empty()) break; // Let validation diagnose malformed input.
        const auto type = receive_data[0];
        const bool known = (type == 0x02 && receive_data.size() >= 8) ||
            ((type == 0x04 || type == 0x05 || type == 0xff) && receive_data.size() >= 2) ||
            (type == 0x07 && receive_data.size() >= 20);
        const bool expected = (request == 0x01 && type == 0x02) ||
            (request == 0x03 && type == 0x04) || (request == 0x06 && type == 0x05) ||
            (request == 0xff && (type == 0xff || type == 0x07)) ||
            (request == 0x07 && type == 0x07);
        if (!known || expected) break;
        logger_.debug("Discarded stale response type 0x{:02x}", type);
    }
    return true;
}

// ================= DrcomClientFactory =================
std::unique_ptr<DrcomClient> DrcomClientFactory::create() {
    return std::make_unique<DrcomClient>();
}

} // namespace drcom
