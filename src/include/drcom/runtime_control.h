#ifndef DRCOM_RUNTIME_CONTROL_H
#define DRCOM_RUNTIME_CONTROL_H
#include <filesystem>

namespace drcom {
// One persistent automatic-authentication switch per state directory.
class RuntimeControl {
public:
    explicit RuntimeControl(std::filesystem::path directory = {});
    bool enabled() const;
    void setEnabled(bool enabled) const;
    const std::filesystem::path& directory() const { return directory_; }
private:
    std::filesystem::path directory_;
};
}
#endif
