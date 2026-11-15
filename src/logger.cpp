#include "drcom/logger.h"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace drcom {
namespace {
std::tm localTime(std::time_t value) {
    std::tm result{};
#ifdef _WIN32
    localtime_s(&result, &value);
#else
    localtime_r(&value, &result);
#endif
    return result;
}
}

void ConsoleSink::log(const LogEntry& entry) {
    // Format timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    const auto local_time = localTime(time_t);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()
    ) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    // Format level
    const char* level_str = "";
    switch (entry.level) {
        case LogLevel::TRACE: level_str = "TRACE"; break;
        case LogLevel::DEBUG: level_str = "DEBUG"; break;
        case LogLevel::INFO:  level_str = "INFO"; break;
        case LogLevel::WARN:  level_str = "WARN"; break;
        case LogLevel::ERROR: level_str = "ERROR"; break;
        case LogLevel::FATAL: level_str = "FATAL"; break;
    }
    
    std::cout << "[" << ss.str() << "] [" << level_str << "] "<< entry.message << std::endl;
}

FileSink::FileSink(const std::string& filename) 
    : filename_(filename), file_(std::make_unique<std::ofstream>(filename, std::ios::app)) {
    if (!file_->is_open()) throw std::runtime_error("Cannot open log file: " + filename_);
    rotateIfNeeded();
}

FileSink::~FileSink() = default;

void FileSink::log(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(file_mutex_);
    if (!file_ || !file_->is_open()) return;
    
    // Format timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    const auto local_time = localTime(time_t);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()
    ) % 1000;
    
    *file_ << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");
    *file_ << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    // Format level
    const char* level_str = "";
    switch (entry.level) {
        case LogLevel::TRACE: level_str = "TRACE"; break;
        case LogLevel::DEBUG: level_str = "DEBUG"; break;
        case LogLevel::INFO:  level_str = "INFO"; break;
        case LogLevel::WARN:  level_str = "WARN"; break;
        case LogLevel::ERROR: level_str = "ERROR"; break;
        case LogLevel::FATAL: level_str = "FATAL"; break;
    }
    
    *file_ << " [" << level_str << "] " << entry.message << std::endl;
    rotateIfNeeded();
}

void FileSink::rotateIfNeeded() {
    if (!file_ || !file_->is_open()) return;
    constexpr std::uintmax_t kMaximumLogSize = 1024 * 1024;
    std::error_code error;
    if (std::filesystem::file_size(filename_, error) < kMaximumLogSize || error) return;
    file_->close();
    // Keep one previous file. An old, oversized log is discarded at rotation.
    const auto backup = filename_ + ".1";
    std::filesystem::remove(backup, error);
    std::filesystem::rename(filename_, backup, error);
    file_ = std::make_unique<std::ofstream>(filename_,
        error ? std::ios::app : std::ios::trunc);
}

void FileSink::flush() {
    std::lock_guard<std::mutex> lock(file_mutex_);
    if (file_) file_->flush();
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::addSink(std::unique_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.push_back(std::move(sink));
}

void Logger::logHexDump(LogLevel level, const std::string& prefix, 
                       const std::vector<uint8_t>& data) {
    logHexDump(level, prefix, data.data(), data.size());
}

void Logger::logHexDump(LogLevel level, const std::string& prefix, 
                       const uint8_t* data, size_t size) {
    if (level < level_) return;
    
    std::ostringstream oss;
    oss << prefix << " (" << size << " bytes):\n";
    
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) 
            << static_cast<int>(data[i]);
        
        if ((i + 1) % 16 == 0) {
            oss << "\n";
        } else if ((i + 1) % 8 == 0) {
            oss << "    ";
        } else {
            oss << " ";
        }
    }
    
    if (size % 16 != 0) {
        oss << "\n";
    }
    
    log(level, oss.str());
}

void Logger::logPacket(const std::string& label, const std::vector<uint8_t>& data) {
    if (data.empty()) debug("{} (0 bytes)", label);
    else debug("{} ({} bytes, type 0x{:02x})", label, data.size(), data[0]);
}

void Logger::logChallengeSend(const std::vector<uint8_t>& data) {
    logPacket("Send challenge message to server", data);
}

void Logger::logChallengeReceive(const std::vector<uint8_t>& data) {
    logPacket("Receive challenge message from server", data);
}

void Logger::logAuthSend(const std::vector<uint8_t>& data) {
    logPacket("Send auth message to server", data);
}

void Logger::logAuthReceive(const std::vector<uint8_t>& data) {
    logPacket("Receive auth message from server", data);
}

void Logger::logKeepAliveSend(const std::vector<uint8_t>& data) {
    logPacket("Send keep alive auth message to server", data);
}

void Logger::logKeepAliveReceive(const std::vector<uint8_t>& data) {
    logPacket("Receive keep alive auth message from server", data);
}

void Logger::logHeartbeatSend(const std::vector<uint8_t>& data) {
    logPacket("Send keep alive heartbeat message to server", data);
}

void Logger::logHeartbeatReceive(const std::vector<uint8_t>& data) {
    logPacket("Receive keep alive heartbeat message from server", data);
}

void Logger::logLogoutSend(const std::vector<uint8_t>& data) {
    logPacket("Send logout message to server", data);
}

void Logger::logLogoutReceive(const std::vector<uint8_t>& data) {
    logPacket("Receive logout message from server", data);
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) {
        sink->flush();
    }
}

} // namespace drcom
