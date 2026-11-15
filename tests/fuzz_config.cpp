#include "drcom/config.h"
#include "drcom/protocol.h"
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace {
struct Scratch {
    std::filesystem::path root = std::filesystem::temp_directory_path() /
        ("drcom-fuzz-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Scratch() { std::filesystem::create_directory(root); }
    ~Scratch() { std::error_code error; std::filesystem::remove_all(root, error); }
};
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static Scratch scratch;
    const auto input = scratch.root / "input.conf";
    const auto saved = scratch.root / "saved.conf";
    {
        std::ofstream stream(input, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    drcom::Config config;
    if (config.loadFromFile(input.string())) {
        const auto original = drcom::protocol::buildLoginPacket(config, {});
        if (!config.saveToFile(saved.string())) std::abort();
        drcom::Config reloaded;
        if (!reloaded.loadFromFile(saved.string()) ||
            drcom::protocol::buildLoginPacket(reloaded, {}) != original) std::abort();
    }
    return 0;
}
