#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>

#include "drcom/drcom.h"

#ifdef _WIN32
#include <shellapi.h>  // CommandLineToArgvW
#include <windows.h>
#endif

// Global client instance for signal handling
std::atomic<bool> g_shutdown_requested{false};
std::unique_ptr<drcom::DrcomClient> g_client;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal
              << ", shutting down gracefully..." << std::endl;
    g_shutdown_requested = true;

    if (g_client && g_client->isConnected()) {
        g_client->disconnect();
    }
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  -c, --config <file>    Configuration file path\n"
              << "  -h, --help            Show this help message\n"
              << "  -v, --version         Show version information\n"
              << std::endl;
}

void printVersion() {
    std::cout << "JLU DRCOM Client (C++) v2.0.0\n"
              << "Cross-platform implementation in modern C++\n"
              << "Based on original C implementation\n"
              << std::endl;
}

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
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
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

        logger.info("Configuration loaded successfully");
        logger.info("Server: {}:{}", config.getServerConfig().ip,
                    config.getServerConfig().port);
        logger.info("Username: {}", config.getUserConfig().username);

        // Set up signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        // Create and configure client
        g_client = drcom::DrcomClientFactory::create();

        // Set up event callback
        g_client->setEventCallback(
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

        // Connect to server
        logger.info("Connecting to DRCOM server...");
        if (!g_client->connect()) {
            logger.error("Failed to connect to server");
            return 1;
        }

        logger.info("Connected successfully! Press Ctrl+C to disconnect.");

        // Main loop
        while (!g_shutdown_requested && g_client->isConnected()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Print statistics every 30 seconds
            static int counter = 0;
            if (++counter >= 30) {
                counter = 0;
                const auto& stats = g_client->getStatistics();
                logger.info(
                    "Statistics - Auth: {}/{}, Heartbeat: {}/{}, Bytes: {}/{}",
                    stats.auth_packets_sent, stats.auth_packets_received,
                    stats.heartbeat_packets_sent,
                    stats.heartbeat_packets_received, stats.bytes_sent,
                    stats.bytes_received);
            }
        }

        if (g_client->isConnected()) {
            logger.info("Disconnecting...");
            g_client->disconnect();
        }

        logger.info("Client shut down successfully");

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