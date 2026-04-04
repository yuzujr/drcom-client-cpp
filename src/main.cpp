#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

#include "drcom/drcom.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <shellapi.h>  // CommandLineToArgvW
#include <windows.h>
#endif

namespace {

#ifndef DRCOM_CLIENT_VERSION
#define DRCOM_CLIENT_VERSION "0.0.0-dev"
#endif

constexpr auto kLoopPollInterval = std::chrono::milliseconds(100);
constexpr auto kStatisticsInterval = std::chrono::seconds(30);

// Global client instance for signal handling
std::atomic<bool> g_shutdown_requested{false};
std::unique_ptr<drcom::DrcomClient> g_client;

bool shutdownRequested() {
    return g_shutdown_requested.load(std::memory_order_relaxed);
}

std::string_view messageOrDefault(const std::string& message,
                                  std::string_view fallback) {
    return message.empty() ? fallback : std::string_view(message);
}

void signalHandler(int) {
    g_shutdown_requested.store(true, std::memory_order_relaxed);
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  -c, --config <file>    Configuration file path\n"
              << "  -h, --help            Show this help message\n"
              << "  -v, --version         Show version information\n"
              << std::endl;
}

int printArgumentError(const char* program_name, std::string_view message) {
    std::cerr << message << std::endl;
    printUsage(program_name);
    return 1;
}

void printVersion() {
    std::cout << "v" << DRCOM_CLIENT_VERSION << std::endl;
}

void logConfiguration(drcom::Logger& logger, const drcom::Config& config) {
    logger.info("Configuration loaded successfully");
    logger.info("Server: {}:{}", config.getServerConfig().ip,
                config.getServerConfig().port);
    logger.info("Bind: {}:{}", config.getClientConfig().ip,
                config.getClientConfig().port);
    logger.info("Auto reconnect: {} ({}s)",
                config.getClientConfig().auto_reconnect ? "enabled" : "disabled",
                config.getClientConfig().reconnect_interval);
    logger.info("Username: {}", config.getUserConfig().username);
}

void logStatistics(drcom::Logger& logger,
                   const drcom::DrcomClient::Statistics& stats) {
    logger.info("Statistics - Auth: {}/{}, Heartbeat: {}/{}, Bytes: {}/{}",
                stats.auth_packets_sent, stats.auth_packets_received,
                stats.heartbeat_packets_sent, stats.heartbeat_packets_received,
                stats.bytes_sent, stats.bytes_received);
}

bool waitInterruptibly(std::chrono::milliseconds delay) {
    auto remaining = delay;
    while (!shutdownRequested() &&
           remaining > std::chrono::milliseconds::zero()) {
        const auto sleep_duration = (std::min)(remaining, kLoopPollInterval);
        std::this_thread::sleep_for(sleep_duration);
        remaining -= sleep_duration;
    }

    return !shutdownRequested();
}

void configureClientCallbacks(drcom::DrcomClient& client,
                              drcom::Logger& logger) {
    client.setEventCallback(
        [&logger](drcom::ClientEvent event, const std::string& message) {
            switch (event) {
                case drcom::ClientEvent::STATE_CHANGED:
                    logger.info("State changed: {}", message);
                    break;
                case drcom::ClientEvent::AUTH_SUCCESS:
                    logger.info("Authentication successful: {}", message);
                    break;
                case drcom::ClientEvent::AUTH_FAILED:
                    logger.error("Authentication failed: {}", message);
                    break;
                case drcom::ClientEvent::KEEPALIVE_SUCCESS:
                    logger.debug("Keep-alive successful: {}", message);
                    break;
                case drcom::ClientEvent::KEEPALIVE_FAILED:
                    logger.warn("Keep-alive failed: {}", message);
                    break;
                case drcom::ClientEvent::NETWORK_ERROR:
                    logger.error("Network error: {}", message);
                    break;
                case drcom::ClientEvent::SERVER_DISCONNECT:
                    logger.warn("Server disconnect: {}", message);
                    break;
            }
        });
}

std::unique_ptr<drcom::DrcomClient> createClient(drcom::Logger& logger) {
    auto client = drcom::DrcomClientFactory::create();
    configureClientCallbacks(*client, logger);
    return client;
}

bool runConnectedLoop(drcom::Logger& logger) {
    auto next_statistics_log =
        std::chrono::steady_clock::now() + kStatisticsInterval;

    while (!shutdownRequested() && g_client && g_client->isConnected()) {
        if (!waitInterruptibly(kLoopPollInterval)) {
            return false;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now < next_statistics_log) {
            continue;
        }

        logStatistics(logger, g_client->getStatistics());
        do {
            next_statistics_log += kStatisticsInterval;
        } while (next_statistics_log <= now);
    }

    return !shutdownRequested();
}

int runClientSupervisor(drcom::Logger& logger, const drcom::Config& config) {
    const auto reconnect_delay =
        std::chrono::seconds(config.getClientConfig().reconnect_interval);

    int exit_code = 0;
    uint64_t connect_attempt = 0;

    while (!shutdownRequested()) {
        ++connect_attempt;
        g_client = createClient(logger);

        logger.info("Connecting to DRCOM server (attempt {})...", connect_attempt);
        if (!g_client->connect()) {
            exit_code = 1;
            const auto disconnect_reason = g_client->getLastDisconnectReason();
            const auto disconnect_message = g_client->getLastDisconnectMessage();

            if (!config.getClientConfig().auto_reconnect ||
                !g_client->shouldReconnect() || shutdownRequested()) {
                logger.error(
                    "Failed to connect to server: {} ({})",
                    messageOrDefault(disconnect_message, "unknown error"),
                    drcom::disconnectReasonToString(disconnect_reason));
                break;
            }

            logger.warn(
                "Connection attempt failed: {} ({}), retrying in {} seconds",
                messageOrDefault(disconnect_message, "unknown error"),
                drcom::disconnectReasonToString(disconnect_reason),
                config.getClientConfig().reconnect_interval);
            g_client.reset();
            if (!waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(
                    reconnect_delay))) {
                break;
            }
            continue;
        }

        exit_code = 0;
        logger.info("Connected successfully! Press Ctrl+C to disconnect.");

        if (!runConnectedLoop(logger)) {
            break;
        }

        exit_code = 1;
        const auto end_state = g_client->getState();
        const auto disconnect_reason = g_client->getLastDisconnectReason();
        const auto disconnect_message = g_client->getLastDisconnectMessage();
        const bool should_reconnect =
            config.getClientConfig().auto_reconnect && g_client->shouldReconnect();
        g_client.reset();

        if (!should_reconnect) {
            logger.warn(
                "Connection ended in state {} with {} ({}); auto reconnect {}",
                drcom::clientStateToString(end_state),
                messageOrDefault(disconnect_message, "no detail"),
                drcom::disconnectReasonToString(disconnect_reason),
                config.getClientConfig().auto_reconnect ? "stopped by policy"
                                                        : "is disabled");
            break;
        }

        logger.warn("Connection lost (state: {}, {}), retrying in {} seconds",
                    drcom::clientStateToString(end_state),
                    messageOrDefault(disconnect_message, "no detail"),
                    config.getClientConfig().reconnect_interval);
        if (!waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(
                reconnect_delay))) {
            break;
        }
    }

    return exit_code;
}

void shutdownClient(drcom::Logger& logger) {
    if (g_client && g_client->isConnected()) {
        logger.info("Disconnecting...");
        g_client->disconnect();
    }
    g_client.reset();
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string config_file = "drcom.conf";

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            printVersion();
            return 0;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 >= argc) {
                return printArgumentError(argv[0],
                                          "Missing value for option: " + arg);
            }
            config_file = argv[++i];
        } else if (arg.rfind("--config=", 0) == 0) {
            config_file = arg.substr(std::string("--config=").size());
            if (config_file.empty()) {
                return printArgumentError(
                    argv[0], "Missing value for option: --config");
            }
        } else if (arg.rfind("-c=", 0) == 0) {
            config_file = arg.substr(std::string("-c=").size());
            if (config_file.empty()) {
                return printArgumentError(argv[0],
                                          "Missing value for option: -c");
            }
        } else {
            return printArgumentError(argv[0], "Unknown argument: " + arg);
        }
    }

    std::cout << "DRCOM Client (C++)" << std::endl;
    std::cout << "=============================" << std::endl;

    try {
        // Initialize logging
        auto& logger = drcom::Logger::getInstance();
        logger.addSink(std::make_unique<drcom::ConsoleSink>());
        logger.addSink(std::make_unique<drcom::FileSink>("drcom.log"));
        logger.setLevel(drcom::LogLevel::INFO);

        logger.info("Starting DRCOM client...");

        // Load configuration
        auto& config = drcom::Config::getInstance();
        if (!config.loadFromFile(config_file)) {
            logger.error("Could not load config file '{}'", config_file);
            return 1;
        }

        if (!config.validate()) {
            logger.error("Configuration validation failed");
            return 1;
        }

        logger.setLevel(config.getClientConfig().debug_enabled
                            ? drcom::LogLevel::DEBUG
                            : drcom::LogLevel::INFO);

        logConfiguration(logger, config);

        // Set up signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        const int exit_code = runClientSupervisor(logger, config);
        shutdownClient(logger);

        logger.info("Client shut down successfully");
        return exit_code;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        auto& logger = drcom::Logger::getInstance();
        logger.error("Unhandled exception: {}", e.what());
        return 1;
    }

    return 0;
}

#ifdef _WIN32
// ============= WinMain 入口 =============
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    int argc = 0;
    LPWSTR* argv_w = CommandLineToArgvW(GetCommandLineW(), &argc);

    std::vector<std::string> args;
    std::vector<char*> argv;
    for (int i = 0; i < argc; i++) {
        int len = WideCharToMultiByte(CP_UTF8, 0, argv_w[i], -1, nullptr, 0,
                                      nullptr, nullptr);
        std::string arg(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, argv_w[i], -1, arg.data(), len, nullptr,
                            nullptr);
        args.push_back(arg);
    }
    LocalFree(argv_w);

    for (auto& s : args) {
        argv.push_back(s.data());
    }

    return main(argc, argv.data());
}
#endif
