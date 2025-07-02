#include "drcom/logger.h"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace drcom {

void ConsoleSink::log(const LogEntry& entry) {
    // Format timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()
    ) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
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
    : file_(std::make_unique<std::ofstream>(filename, std::ios::app)) {
}

FileSink::~FileSink() = default;

void FileSink::log(const LogEntry& entry) {
    if (!file_ || !file_->is_open()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(file_mutex_);
    
    // Format timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()
    ) % 1000;
    
    *file_ << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
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
}

void FileSink::flush() {
    if (file_) {
        std::lock_guard<std::mutex> lock(file_mutex_);
        file_->flush();
    }
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

void Logger::logChallengeSend(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Send challenge message to server", data);
}

void Logger::logChallengeReceive(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Receive challenge message from server", data);
    if (data.size() >= 8) {
        logHexDump(LogLevel::DEBUG, "Login salt", data.data() + 4, 4);
    }
}

void Logger::logAuthSend(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Send auth message to server", data);
}

void Logger::logAuthReceive(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Receive auth message from server", data);
}

void Logger::logKeepAliveSend(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Send keep alive auth message to server", data);
}

void Logger::logKeepAliveReceive(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Receive keep alive auth message from server", data);
}

void Logger::logHeartbeatSend(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Send keep alive heartbeat message to server", data);
}

void Logger::logHeartbeatReceive(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Receive keep alive heartbeat message from server", data);
}

void Logger::logLogoutSend(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Send logout message to server", data);
}

void Logger::logLogoutReceive(const std::vector<uint8_t>& data) {
    logHexDump(LogLevel::DEBUG, "Receive logout message from server", data);
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) {
        sink->flush();
    }
}

} // namespace drcom
