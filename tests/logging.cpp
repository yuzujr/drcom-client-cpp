#include "drcom/logger.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
int main() {
    const auto root = std::filesystem::temp_directory_path() /
        ("drcom-log-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{root};
    bool failed = false;
    try { drcom::FileSink invalid((root / "missing/log").string()); }
    catch (const std::runtime_error&) { failed = true; }
    require(failed, "Log open failure was silently ignored");
    const auto path = root / "drcom.log";
    {
        drcom::FileSink sink(path.string());
        const drcom::LogEntry entry(drcom::LogLevel::DEBUG, std::string(1024, 'x'));
        for (unsigned i = 0; i < 3100; ++i) sink.log(entry);
        sink.flush();
    }
    const auto backup = path.string() + ".1";
    require(std::filesystem::exists(backup), "Log did not rotate");
    constexpr auto limit = 1024 * 1024 + 2048;
    require(std::filesystem::file_size(path) <= limit, "Current log unbounded");
    require(std::filesystem::file_size(backup) <= limit, "Backup log unbounded");
    unsigned files = 0;
    for (const auto& file : std::filesystem::directory_iterator(root)) { (void)file; ++files; }
    require(files == 2, "Rotation retained extra log files");
    std::cout << "Log open failure and bounded rotation passed\n";
}
