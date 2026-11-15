#ifndef DRCOM_RUNTIME_CONTROL_H
#define DRCOM_RUNTIME_CONTROL_H
#include <filesystem>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <chrono>
#include <functional>

namespace drcom {
struct RuntimeStatus {
    std::string state;
    std::string interface_name;
    std::string ip;
    std::string last_failure;
    uint64_t attempts{0};
    int64_t next_retry{0};
    uint64_t pid{0};
    int64_t updated{0};
    bool running{false};
    bool fresh{false};
    bool operator==(const RuntimeStatus&) const = default;
};
// One persistent automatic-authentication switch per state directory.
class RuntimeControl {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;
    static constexpr auto heartbeat_interval = std::chrono::seconds(10);
    static constexpr auto freshness_limit = std::chrono::seconds(30);
    explicit RuntimeControl(std::filesystem::path directory = {},
                            Clock clock = [] { return std::chrono::steady_clock::now(); });
    ~RuntimeControl();
    bool enabled() const;
    void setEnabled(bool enabled) const;
    // One publisher per directory; commands do not acquire this lock.
    void claim();
    void publish(RuntimeStatus status);
    void refresh();
    std::optional<RuntimeStatus> readStatus() const;
    const std::filesystem::path& directory() const { return directory_; }
private:
    std::filesystem::path directory_;
    void prepareDirectory() const;
    void writeStatusLocked();
    std::mutex status_mutex_;
    RuntimeStatus status_;
    std::chrono::steady_clock::time_point last_write_{};
#ifdef _WIN32
    void* lock_handle_{nullptr};
#else
    int lock_fd_{-1};
#endif
    bool claimed_{false};
    Clock clock_;
};
}
#endif
