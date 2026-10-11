#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <array>
#include <thread>
#include <string_view>
#include <vector>
#include <cstdio>

#include "drcom/drcom.h"
#include "drcom/runtime_control.h"

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
std::unique_ptr<drcom::RuntimeControl> g_control;
std::unique_ptr<drcom::DrcomClient> g_client;
drcom::RuntimeStatus g_runtime;

int64_t epochSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void publishState(std::string state, int64_t next_retry = 0) {
    g_runtime.state = std::move(state);
    g_runtime.next_retry = next_retry;
    g_control->publish(g_runtime);
}

void printRuntimeStatus() {
    const auto status = g_control->readStatus();
    if (!status) {
        std::cout << "Runtime: unknown (no runtime status; client may be stopped or older)\n";
        return;
    }
    std::cout << "Runtime: " << (status->running ? "running" : "not running")
              << " (PID " << status->pid << ")\n";
    if (status->running && status->fresh) {
        std::cout << "State: " << status->state << '\n';
    } else {
        std::cout << "State: unknown (" << (status->running ? "stale status" : "process exited")
                  << ")\nLast recorded state: " << status->state << '\n';
    }
    if (!status->interface_name.empty())
        std::cout << "Interface: " << status->interface_name << " (" << status->ip << ")\n";
    std::cout << "Authentication attempts: " << status->attempts << '\n';
    if (!status->last_failure.empty())
        std::cout << "Last failure: " << status->last_failure << '\n';
    if (status->running && status->fresh && status->next_retry)
        std::cout << "Next retry: in " << (std::max)(int64_t{0}, status->next_retry - epochSeconds())
                  << "s\n";
}

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
    std::cout << "Usage: " << program_name << " [enable|disable|status] [options]\n"
              << "Options:\n"
              << "  -c, --config <file>    Configuration file path\n"
              << "  --state-dir <dir>      Shared persistent control directory\n"
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
        g_control->refresh();
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

struct RouteInfo {
    std::string source;
    std::string interface_name;
    std::array<uint8_t, 6> mac{};
    bool has_mac{false};

    bool operator==(const RouteInfo&) const = default;
};

std::optional<RouteInfo> routeSource(const drcom::Config& config,
                                    const std::string& requested_bind) {
    const auto& server = config.getServerConfig();
    const auto network_interface = drcom::selectNetworkInterface(
        {server.ip, server.port}, requested_bind);
    if (!network_interface) return std::nullopt;
    drcom::UdpSocket probe;
    if (probe.bind({network_interface->ipv4, 0}) ||
        probe.connect({server.ip, server.port})) return std::nullopt;
    return RouteInfo{network_interface->ipv4, network_interface->name, network_interface->mac,
                     network_interface->has_mac};
}

enum class ConnectedLoopResult { Shutdown, Disconnected, NetworkChanged, Paused };

ConnectedLoopResult runConnectedLoop(drcom::Logger& logger, const drcom::Config& config,
                      const std::string& requested_bind,
                      const std::optional<RouteInfo>& source) {
    auto next_statistics_log =
        std::chrono::steady_clock::now() + kStatisticsInterval;

    auto next_network_check = std::chrono::steady_clock::now() + kNetworkPollInterval;
    while (!shutdownRequested() && g_client && g_client->isConnected()) {
        if (!waitInterruptibly(kLoopPollInterval)) {
            return ConnectedLoopResult::Shutdown;
        }

        if (!g_control->enabled()) {
            g_client->stop();
            return ConnectedLoopResult::Paused;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_network_check) {
            next_network_check = now + kNetworkPollInterval;
            if (routeSource(config, requested_bind) != source) {
                logger.info("Network interface changed; reconnecting");
                g_client->disconnect();
                return ConnectedLoopResult::NetworkChanged;
            }
        }
        if (now < next_statistics_log) {
            continue;
        }

        logStatistics(logger, g_client->getStatistics());
        do {
            next_statistics_log += kStatisticsInterval;
        } while (next_statistics_log <= now);
    }

    return shutdownRequested() ? ConnectedLoopResult::Shutdown
                               : ConnectedLoopResult::Disconnected;
}

// Polling the route keeps this portable and also catches a changed Wi-Fi or
// Ethernet address while the client is sleeping after a failed handshake.
bool waitForNetworkChange(const drcom::Config& config,
                          const std::string& requested_bind,
                          const std::optional<RouteInfo>& source,
                          std::chrono::seconds delay) {
    const auto deadline = std::chrono::steady_clock::now() + delay;
    while (!shutdownRequested() && std::chrono::steady_clock::now() < deadline) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto step = (std::min)(remaining,
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(kNetworkPollInterval));
        if (!waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(step))) break;
        if (!g_control->enabled() || routeSource(config, requested_bind) != source) return true;
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
    bool paused = false;
    auto last_retry_report = std::chrono::steady_clock::now();
    // Keep explicit user settings separate from the runtime binding.
    const auto configured_client = config.getClientConfig();
    const auto configured_user = config.getUserConfig();
    const auto& requested_bind = configured_client.ip;

    while (!shutdownRequested()) {
        if (!g_control->enabled()) {
            if (g_client) { g_client->stop(); g_client.reset(); }
            if (!paused) {
                publishState("disabled");
                logger.info("Automatic authentication disabled; waiting for enable");
            }
            paused = true;
            previous_source.reset();
            previous_failure.reset();
            failures = 0;
            waitInterruptibly(kLoopPollInterval);
            continue;
        }
        if (paused) logger.info("Automatic authentication enabled");
        paused = false;
        const auto source = routeSource(config, requested_bind);
        if (!source) {
            if (g_runtime.state != "waiting for network") {
                g_runtime.interface_name.clear();
                g_runtime.ip.clear();
                publishState("waiting for network");
                logger.info("No usable network interface; waiting for network");
            }
            waiting_for_route = true;
            previous_source.reset();
            previous_failure.reset();
            failures = 0;
            waitInterruptibly(std::chrono::duration_cast<std::chrono::milliseconds>(kNetworkPollInterval));
            continue;
        }

        if (waiting_for_route || source != previous_source) {
            logger.info("Using network interface {} ({}); trying authentication",
                        source->source, source->interface_name);
            failures = 0;
            previous_failure.reset();
        }
        waiting_for_route = false;
        previous_source = source;
        auto runtime_client = configured_client;
        runtime_client.ip = source->source;
        config.setClientConfig(runtime_client);
        auto runtime_user = configured_user;
        if (configured_client.auto_identity) {
            runtime_user.ip = source->source;
            if (source->has_mac) runtime_user.mac = source->mac;
        }
        config.setUserConfig(runtime_user);
        g_runtime.interface_name = source->interface_name;
        g_runtime.ip = source->source;
        ++g_runtime.attempts;
        publishState("authenticating");
        g_client = createClient(logger);
        g_client->setCancellationCallback(
            [&config, requested_bind, source,
             next_check = std::chrono::steady_clock::now()]() mutable {
                if (shutdownRequested()) return true;
                try {
                    if (!g_control->enabled()) return true;
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= next_check) {
                        next_check = now + kNetworkPollInterval;
                        g_control->refresh();
                        if (routeSource(config, requested_bind) != source) return true;
                    }
                } catch (...) { return true; }
                return false;
            });

        auto loop_result = ConnectedLoopResult::Disconnected;
        const bool connected = g_client->connect();
        if (connected) {
            publishState("authenticated");
            logger.info("Connected successfully");
            failures = 0;
            previous_failure.reset();
            loop_result = runConnectedLoop(logger, config, requested_bind, source);
            if (loop_result == ConnectedLoopResult::Shutdown) break;
        }

        if (shutdownRequested()) break;
        if (!g_control->enabled() || loop_result == ConnectedLoopResult::Paused) {
            g_client->stop();
            g_client.reset();
            continue;
        }
        if (routeSource(config, requested_bind) != source) {
            g_client->stop();
            g_client.reset();
            previous_source.reset();
            if (!configured_client.auto_reconnect) return 0;
            continue;
        }
        const auto reason = g_client->getLastDisconnectReason();
        const auto message = g_client->getLastDisconnectMessage();
        if (loop_result == ConnectedLoopResult::NetworkChanged) {
            g_client.reset();
            previous_source.reset();
            if (!configured_client.auto_reconnect) return 0;
            continue;
        }
        const bool reconnect = config.getClientConfig().auto_reconnect &&
                               g_client->shouldReconnect();
        g_client.reset();

        if (!reconnect) {
            g_runtime.last_failure = messageOrDefault(message, "unknown error");
            publishState("error");
            logger.error("Authentication stopped: {} ({})",
                         messageOrDefault(message, "unknown error"),
                         drcom::disconnectReasonToString(reason));
            return 1;
        }

        ++failures;
        const auto delay = retryDelay(config, failures);
        g_runtime.last_failure = messageOrDefault(message, "unknown error");
        publishState("waiting to retry", epochSeconds() + delay.count());
        if (!previous_failure || *previous_failure != reason) {
            logger.warn("Authentication unavailable: {} ({}); next attempt in {}s (backoff up to {}s)",
                        messageOrDefault(message, "unknown error"),
                        drcom::disconnectReasonToString(reason),
                        delay.count(),
                        kMaximumRetryDelay.count());
            last_retry_report = std::chrono::steady_clock::now();
        } else if (std::chrono::steady_clock::now() - last_retry_report >= std::chrono::minutes(5)) {
            logger.info("Still retrying authentication: {} attempts; next attempt in {}s; last failure: {}",
                        g_runtime.attempts, delay.count(), message);
            last_retry_report = std::chrono::steady_clock::now();
        } else {
            logger.debug("Authentication retry {} failed: {}; next attempt in {}s",
                         failures, messageOrDefault(message, "unknown error"), delay.count());
        }
        previous_failure = reason;
        if (waitForNetworkChange(config, requested_bind, source, delay)) {
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
    std::string state_directory;
    std::string command;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "enable" || arg == "disable" || arg == "status") {
            if (!command.empty()) return printArgumentError(argv[0], "Only one command is allowed");
            command = arg;
        } else if (arg == "--state-dir") {
            if (i + 1 >= argc) return printArgumentError(argv[0], "Missing state directory");
            state_directory = argv[++i];
            if (state_directory.empty()) return printArgumentError(argv[0], "Empty state directory");
        } else if (arg == "-h" || arg == "--help") {
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

    try {
        g_control = std::make_unique<drcom::RuntimeControl>(state_directory);
        if (!command.empty()) {
            if (command != "status") g_control->setEnabled(command == "enable");
            std::cout << "Automatic authentication: "
                      << (g_control->enabled() ? "enabled" : "disabled") << '\n'
                      << "State directory: " << g_control->directory().string() << '\n';
            if (command == "status") printRuntimeStatus();
            if (command != "status")
                std::cout << "A running client using this directory will apply the change.\n";
            return 0;
        }
        std::cout << "DRCOM Client (C++)\n=============================\n";
        // Initialize logging
        auto& logger = drcom::Logger::getInstance();
        logger.addSink(std::make_unique<drcom::ConsoleSink>());
#ifdef _WIN32
        logger.addSink(std::make_unique<drcom::FileSink>("drcom.log"));
#endif
        logger.setLevel(drcom::LogLevel::INFO);

        logger.info("Starting DRCOM client...");
        g_control->claim();
        publishState("starting");

        // Load configuration
        auto& config = drcom::Config::getInstance();
        if (!config.loadFromFile(config_file)) {
            g_runtime.last_failure = "Could not load configuration file";
            publishState("error");
            logger.error("Could not load config file '{}'", config_file);
            return 1;
        }

        if (!config.validate()) {
            g_runtime.last_failure = "Configuration validation failed";
            publishState("error");
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
        if (g_runtime.state != "error") publishState("stopped");

        logger.info("Client shut down successfully");
        return exit_code;

    } catch (const std::exception& e) {
        g_shutdown_requested.store(true, std::memory_order_relaxed);
        if (g_client) { g_client->stop(); g_client.reset(); }
        g_runtime.last_failure = e.what();
        try { publishState("error"); } catch (...) {}
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

    // Keep scheduled background runs windowless, but expose CLI command output.
    const bool cli_output = std::any_of(argv.begin() + 1, argv.end(), [](const char* value) {
        const std::string_view arg(value);
        return arg == "enable" || arg == "disable" || arg == "status" ||
               arg == "--help" || arg == "-h" || arg == "--version" || arg == "-v";
    });
    if (cli_output) {
        const auto output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        const auto error_handle = GetStdHandle(STD_ERROR_HANDLE);
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            FILE* reopened = nullptr;
            if (!output_handle || output_handle == INVALID_HANDLE_VALUE)
                freopen_s(&reopened, "CONOUT$", "w", stdout);
            if (!error_handle || error_handle == INVALID_HANDLE_VALUE)
                freopen_s(&reopened, "CONOUT$", "w", stderr);
        }
    }
    return main(argc, argv.data());
}
#endif
