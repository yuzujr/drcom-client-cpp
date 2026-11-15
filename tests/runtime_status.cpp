#include "drcom/runtime_control.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
int main() {
    using namespace std::chrono;
    const auto root = std::filesystem::temp_directory_path() /
        ("drcom-status-test-" + std::to_string(steady_clock::now().time_since_epoch().count()));
    struct Cleanup { std::filesystem::path root; ~Cleanup() { std::filesystem::remove_all(root); } } cleanup{root};
    auto now = steady_clock::now();
    drcom::RuntimeControl runtime(root, [&] { return now; });
    runtime.claim();
    drcom::RuntimeStatus status;
    status.state = "authenticated";
    runtime.publish(status);
    const auto path = root / "status";
    const auto marker = std::filesystem::file_time_type::clock::now() - hours(1);
    std::filesystem::last_write_time(path, marker);
    const auto saved = std::filesystem::last_write_time(path);
    for (unsigned i = 0; i < 10000; ++i) { runtime.publish(status); runtime.refresh(); }
    require(std::filesystem::last_write_time(path) == saved, "Identical status rewrote file");
    now += seconds(9);
    runtime.refresh();
    require(std::filesystem::last_write_time(path) == saved, "Heartbeat wrote too early");
    now += seconds(1);
    runtime.refresh();
    require(std::filesystem::last_write_time(path) != saved, "Heartbeat did not refresh");
    auto snapshot = runtime.readStatus();
    require(snapshot && snapshot->fresh && snapshot->running, "Live status not recognized");
    status.state = "disabled";
    runtime.publish(status);
    require(runtime.readStatus()->state == "disabled", "State transition was throttled");
    // A live PID cannot make an old/hung publisher look healthy.
    snapshot = runtime.readStatus();
    std::ofstream(path) << "DRCOM_STATUS_1\n" << snapshot->pid << ' '
        << snapshot->updated - 60 << " 0 0\n\"authenticated\"\n\"\"\n\"\"\n\"\"\n";
    require(!runtime.readStatus()->fresh, "Stale status accepted");
    std::cout << "Status deduplication, heartbeat, immediate transitions and expiry passed\n";
}
