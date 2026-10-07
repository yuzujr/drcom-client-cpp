#include "drcom/runtime_control.h"
#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace drcom {
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
void RuntimeControl::setEnabled(bool enabled) const {
    if (enabled) {
        std::filesystem::remove(directory_ / "disabled");
        return;
    }
    const bool created = std::filesystem::create_directories(directory_);
#ifndef _WIN32
    if (created) std::filesystem::permissions(directory_, std::filesystem::perms::owner_all);
#else
    (void)created;
#endif
    std::ofstream flag(directory_ / "disabled");
    if (!flag) throw std::runtime_error("Cannot save disabled state");
}
}
