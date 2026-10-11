#include "drcom/runtime_control.h"
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <iomanip>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace drcom {
namespace {
int64_t epochSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
bool processRunning(uint64_t pid) {
    if (!pid) return false;
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) return GetLastError() == ERROR_ACCESS_DENIED;
    DWORD code = 0;
    const bool running = GetExitCodeProcess(process, &code) && code == STILL_ACTIVE;
    CloseHandle(process);
    return running;
#else
    if (pid > static_cast<uint64_t>(INT32_MAX)) return false;
    return kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}
}
RuntimeControl::RuntimeControl(std::filesystem::path directory) : directory_(std::move(directory)) {
    if (!directory_.empty()) return;
#ifdef _WIN32
    if (const auto* base = std::getenv("LOCALAPPDATA"); base && *base)
        directory_ = std::filesystem::path(base) / "DrcomClient";
#else
    if (const auto* base = std::getenv("XDG_STATE_HOME"); base && *base)
        directory_ = std::filesystem::path(base) / "drcom-client-cpp";
    else if (const auto* base = std::getenv("HOME"); base && *base)
        directory_ = std::filesystem::path(base) / ".local/state/drcom-client-cpp";
#endif
    if (directory_.empty()) throw std::runtime_error("Cannot locate state directory; use --state-dir");
}
bool RuntimeControl::enabled() const {
    return !std::filesystem::exists(directory_ / "disabled");
}
void RuntimeControl::prepareDirectory() const {
    const bool created = std::filesystem::create_directories(directory_);
#ifndef _WIN32
    if (created) std::filesystem::permissions(directory_, std::filesystem::perms::owner_all);
#else
    (void)created;
#endif
}
void RuntimeControl::setEnabled(bool enabled) const {
    if (enabled) {
        std::filesystem::remove(directory_ / "disabled");
        return;
    }
    prepareDirectory();
    std::ofstream flag(directory_ / "disabled");
    if (!flag) throw std::runtime_error("Cannot save disabled state");
}
RuntimeControl::~RuntimeControl() {
#ifdef _WIN32
    if (lock_handle_) CloseHandle(lock_handle_);
#else
    if (lock_fd_ >= 0) close(lock_fd_);
#endif
}
void RuntimeControl::claim() {
    prepareDirectory();
    const auto path = directory_ / "runtime.lock";
#ifdef _WIN32
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Cannot acquire runtime lock; another client may be running");
    lock_handle_ = handle;
    status_.pid = GetCurrentProcessId();
#else
    lock_fd_ = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd_ < 0 || flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd_ >= 0) close(lock_fd_);
        lock_fd_ = -1;
        throw std::runtime_error("Cannot acquire runtime lock; another client may be running");
    }
    status_.pid = static_cast<uint64_t>(getpid());
#endif
    claimed_ = true;
}
void RuntimeControl::writeStatusLocked() {
    status_.updated = epochSeconds();
    const auto temporary = directory_ / "status.tmp";
    const auto target = directory_ / "status";
    {
        std::ofstream output(temporary);
        output << "DRCOM_STATUS_1\n" << status_.pid << ' ' << status_.updated << ' '
               << status_.attempts << ' ' << status_.next_retry << '\n'
               << std::quoted(status_.state) << '\n'
               << std::quoted(status_.interface_name) << '\n'
               << std::quoted(status_.ip) << '\n'
               << std::quoted(status_.last_failure) << '\n';
        output.close();
        if (!output) throw std::runtime_error("Cannot write runtime status");
    }
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING))
        throw std::runtime_error("Cannot replace runtime status");
#else
    std::filesystem::rename(temporary, target);
#endif
    last_write_ = std::chrono::steady_clock::now();
}
void RuntimeControl::publish(RuntimeStatus status) {
    std::lock_guard<std::mutex> lock(status_mutex_);
    if (!claimed_) return;
    status.pid = status_.pid;
    status_ = std::move(status);
    writeStatusLocked();
}
void RuntimeControl::refresh() {
    std::lock_guard<std::mutex> lock(status_mutex_);
    if (claimed_ && std::chrono::steady_clock::now() - last_write_ >= std::chrono::seconds(2))
        writeStatusLocked();
}
std::optional<RuntimeStatus> RuntimeControl::readStatus() const {
    std::ifstream input(directory_ / "status");
    std::string version;
    RuntimeStatus status;
    if (!(input >> version) || version != "DRCOM_STATUS_1" ||
        !(input >> status.pid >> status.updated >> status.attempts >> status.next_retry
          >> std::quoted(status.state) >> std::quoted(status.interface_name)
          >> std::quoted(status.ip) >> std::quoted(status.last_failure))) return std::nullopt;
    const auto age = epochSeconds() - status.updated;
    status.running = processRunning(status.pid);
    status.fresh = age >= 0 && age <= 6;
    return status;
}
}
