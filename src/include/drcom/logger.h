#ifndef LOGGER_H
#define LOGGER_H

#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <iostream>
#include <fstream>
#include <format>

namespace drcom {

/**
 * @brief Log levels enumeration
 */
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

/**
 * @brief Log entry structure
 */
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    std::string message;
    
    LogEntry(LogLevel lvl, std::string msg)
        : timestamp(std::chrono::system_clock::now())
        , level(lvl)
        , message(std::move(msg)) {
    }
};

/**
 * @brief Abstract log sink interface
 */
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void log(const LogEntry& entry) = 0;
    virtual void flush() = 0;
};

/**
 * @brief Console log sink
 */
class ConsoleSink : public LogSink {
public:
    void log(const LogEntry& entry) override;
    void flush() override { std::cout.flush(); }
};

/**
 * @brief File log sink
 */
class FileSink : public LogSink {
public:
    explicit FileSink(const std::string& filename);
    ~FileSink() override;
    
    void log(const LogEntry& entry) override;
    void flush() override;
    
private:
    std::unique_ptr<std::ofstream> file_;
    std::mutex file_mutex_;
};

/**
 * @brief Modern thread-safe logger implementation
 * 
 * This replaces the original C-style Logger with a modern C++ implementation
 * using RAII, smart pointers, and standard library threading primitives.
 */
class Logger {
public:
    static Logger& getInstance();
    
    // Configuration
    void setLevel(LogLevel level) { level_ = level; }
    LogLevel getLevel() const { return level_; }
    
    void addSink(std::unique_ptr<LogSink> sink);
    void removeSinks() { sinks_.clear(); }
    
    // Simple log method that just takes a formatted message
    void log(LogLevel level, const std::string& message) {
        if (level < level_) return;
        
        LogEntry entry(level, message);
        
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& sink : sinks_) {
            sink->log(entry);
        }
    }
    
    // Modern std::format-based logging methods
    template<typename... Args>
    void trace(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::TRACE < level_) return;
        log(LogLevel::TRACE, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void debug(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::DEBUG < level_) return;
        log(LogLevel::DEBUG, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void info(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::INFO < level_) return;
        log(LogLevel::INFO, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void warn(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::WARN < level_) return;
        log(LogLevel::WARN, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void error(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::ERROR < level_) return;
        log(LogLevel::ERROR, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void fatal(std::format_string<Args...> fmt, Args&&... args) {
        if (LogLevel::FATAL < level_) return;
        log(LogLevel::FATAL, std::format(fmt, std::forward<Args>(args)...));
    }
    
    // Convenience overloads for simple string messages
    void trace(const std::string& message) { log(LogLevel::TRACE, message); }
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warn(const std::string& message) { log(LogLevel::WARN, message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }
    void fatal(const std::string& message) { log(LogLevel::FATAL, message); }
    
    // Hex dump utility for network debugging
    void logHexDump(LogLevel level, const std::string& prefix, 
                   const std::vector<uint8_t>& data);
    void logHexDump(LogLevel level, const std::string& prefix, 
                   const uint8_t* data, size_t size);
    
    // Network packet logging (replacing original logger functions)
    void logChallengeSend(const std::vector<uint8_t>& data);
    void logChallengeReceive(const std::vector<uint8_t>& data);
    void logAuthSend(const std::vector<uint8_t>& data);
    void logAuthReceive(const std::vector<uint8_t>& data);
    void logKeepAliveSend(const std::vector<uint8_t>& data);
    void logKeepAliveReceive(const std::vector<uint8_t>& data);
    void logHeartbeatSend(const std::vector<uint8_t>& data);
    void logHeartbeatReceive(const std::vector<uint8_t>& data);
    void logLogoutSend(const std::vector<uint8_t>& data);
    void logLogoutReceive(const std::vector<uint8_t>& data);
    
    void flush();
    
private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    LogLevel level_{LogLevel::INFO};
    std::vector<std::unique_ptr<LogSink>> sinks_;
    std::mutex mutex_;
};

} // namespace drcom

#endif // LOGGER_H