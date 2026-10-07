#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <array>
#include <string_view>
#include <thread>
#include <vector>

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
constexpr auto kNetworkPollInterval = std::chrono::seconds(2);
constexpr auto kMaximumRetryDelay = std::chrono::seconds(60);

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
    logger.debug("Statistics - Auth: {}/{}, Heartbeat: {}/{}, Bytes: {}/{}",
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
                    logger.debug("State changed: {}", message);
                    break;
                case drcom::ClientEvent::AUTH_SUCCESS:
                    logger.debug("Authentication successful: {}", message);
                    break;
                case drcom::ClientEvent::AUTH_FAILED:
                    logger.debug("Authentication failed: {}", message);
                    break;
                case drcom::ClientEvent::KEEPALIVE_SUCCESS:
                    logger.debug("Keep-alive successful: {}", message);
                    break;
                case drcom::ClientEvent::KEEPALIVE_FAILED:
                    logger.debug("Keep-alive failed: {}", message);
                    break;
                case drcom::ClientEvent::NETWORK_ERROR:
                    logger.debug("Network error: {}", message);
                    break;
                case drcom::ClientEvent::SERVER_DISCONNECT:
                    logger.debug("Server disconnect: {}", message);
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

struct RouteInfo {
    std::string source;
    std::string interface_name;

    bool operator==(const RouteInfo& other) const {
        return source == other.source && interface_name == other.interface_name;
    }
};

bool isPhysicalInterface(const drcom::NetworkInterface& interface) {
    if (!interface.is_up || interface.is_loopback || !interface.has_mac ||
        interface.ipv4.empty()) {
        return false;
    }

    const auto& name = interface.name;
    constexpr std::array<std::string_view, 10> virtual_prefixes = {
        "Meta", "tailscale", "tun", "tap", "wg", "docker", "br-",
        "virbr", "veth", "podman"};
    return std::none_of(virtual_prefixes.begin(), virtual_prefixes.end(),
                        [&name](std::string_view prefix) {
                            return name.rfind(prefix, 0) == 0;
                        });
}

std::optional<RouteInfo> routeSource(drcom::Config& config) {
    const auto& server = config.getServerConfig();
    for (const auto& interface : drcom::listNetworkInterfaces()) {
        if (!isPhysicalInterface(interface)) {
            continue;
        }

        // Binding the probe to the interface address makes Linux select the
        // physical route instead of a transparent proxy/TUN policy route.
        drcom::UdpSocket probe;
        if (probe.bind({interface.ipv4, 0})) {
            continue;
        }
        if (probe.connect({server.ip, server.port})) {
            continue;
        }
        const auto source = probe.localAddress();
        if (!source || *source != interface.ipv4) {
            continue;
        }

        auto user_config = config.getUserConfig();
        user_config.ip = *source;
        user_config.mac = interface.mac;
        config.setUserConfig(user_config);

        auto client_config = config.getClientConfig();
        client_config.ip = *source;
        config.setClientConfig(client_config);
        return RouteInfo{*source, interface.name};
    }

    return std::nullopt;
}

// Polling the route keeps this portable and also catches a changed Wi-Fi or
// Ethernet address while the client is sleeping after a failed handshake.
bool waitForNetworkChange(drcom::Config& config,
                          const std::optional<RouteInfo>& source,
                          std::chrono::seconds delay) {
    const auto deadline = std::chrono::steady_clock::now() + delay;
    while (!shutdownRequested() && std::chrono::steady_clock::now() < deadline) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto step = (std::min)(remaining,
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(kNetworkPollInterval));
        if (!waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(step))) break;
        if (routeSource(config) != source) return true;
    }
    return false;
}

std::chrono::seconds retryDelay(const drcom::Config& config, unsigned failures) {
    const auto base = (std::min)(config.getClientConfig().reconnect_interval,
                                 static_cast<uint32_t>(kMaximumRetryDelay.count()));
    const auto multiplier = uint32_t{1} << (std::min)(failures - 1, 8u);
    return std::chrono::seconds((std::min)(base * multiplier,
                                           static_cast<uint32_t>(kMaximumRetryDelay.count())));
}

int runClientSupervisor(drcom::Logger& logger, drcom::Config& config) {
    std::optional<RouteInfo> previous_source;
    std::optional<drcom::DisconnectReason> previous_failure;
    unsigned failures = 0;
    bool waiting_for_route = false;

    while (!shutdownRequested()) {
        const auto source = routeSource(config);
        if (!source) {
            if (!waiting_for_route) logger.info("No route to authentication server; waiting for network");
            waiting_for_route = true;
            previous_source.reset();
            previous_failure.reset();
            failures = 0;
            waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(kNetworkPollInterval));
            continue;
        }

        if (waiting_for_route || source != previous_source) {
            logger.info("Network route available via {} ({}); trying authentication",
                        source->source, source->interface_name);
            failures = 0;
            previous_failure.reset();
        }
        waiting_for_route = false;
        previous_source = source;
        g_client = createClient(logger);

        const bool connected = g_client->connect();
        if (connected) {
            logger.info("Connected successfully");
            failures = 0;
            previous_failure.reset();
            if (!runConnectedLoop(logger)) break;
        }

        const auto reason = g_client->getLastDisconnectReason();
        const auto message = g_client->getLastDisconnectMessage();
        const bool reconnect = config.getClientConfig().auto_reconnect &&
                               g_client->shouldReconnect();
        g_client.reset();

        if (!reconnect) {
            logger.error("Authentication stopped: {} ({})",
                         messageOrDefault(message, "unknown error"),
                         drcom::disconnectReasonToString(reason));
            return 1;
        }

        ++failures;
        const auto delay = retryDelay(config, failures);
        if (!previous_failure || *previous_failure != reason) {
            logger.warn("Authentication unavailable: {} ({}); retrying with backoff (up to {}s)",
                        messageOrDefault(message, "unknown error"),
                        drcom::disconnectReasonToString(reason),
                        kMaximumRetryDelay.count());
        } else {
            logger.debug("Authentication retry {} failed: {}; next attempt in {}s",
                         failures, messageOrDefault(message, "unknown error"), delay.count());
        }
        previous_failure = reason;
        if (waitForNetworkChange(config, source, delay)) {
            previous_source.reset();
        }
    }
    return 0;
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
#ifdef _WIN32
        logger.addSink(std::make_unique<drcom::FileSink>("drcom.log"));
#endif
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
