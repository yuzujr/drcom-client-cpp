#include "drcom/crypto.h"
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace drcom::crypto;
    // libFuzzer supplies arbitrary alignment, empty input and block boundaries.
    (void)MD5::hash(data, size);
    (void)ROR::encrypt(data, size);
    const auto checksum = Checksum::calculate(data, size, 8);
    const auto crc = CRC::calculate(data, size, 8);
    for (size_t i = 4; i < 8; ++i)
        if (checksum[i] || crc[i]) std::abort();
    const std::string password(reinterpret_cast<const char*>(data), size);
    (void)DrcomCrypto::generatePasswordHash(password, DrcomCrypto::generateMD5A({}, password));
    return 0;
}
