#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <cstdint>
#include <array>
#include <string>

namespace drcom {
namespace crypto {

/**
 * @brief MD5 hash implementation
 * 
 * Self-contained MD5 implementation for DRCOM protocol
 */
class MD5 {
public:
    static constexpr size_t DIGEST_SIZE = 16;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;
    
    /**
     * @brief Compute MD5 hash of data
     * @param data Input data
     * @return MD5 digest
     */
    static Digest hash(const std::vector<uint8_t>& data);
    static Digest hash(const uint8_t* data, size_t size);
    static Digest hash(const std::string& data);
    
private:
    struct Context {
        uint32_t state[4];
        uint32_t count[2];
        uint8_t buffer[64];
    };
    
    static void init(Context& ctx);
    static void update(Context& ctx, const uint8_t* data, size_t size);
    static void final(Context& ctx, Digest& digest);
    static void transform(uint32_t state[4], const uint8_t block[64]);
};

/**
 * @brief XOR encryption utility
 */
class XOR {
public:
    /**
     * @brief XOR two byte arrays
     * @param a First array
     * @param b Second array
     * @param output_size Maximum output size
     * @return XOR result
     */
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& a,
                                       const std::vector<uint8_t>& b,
                                       size_t output_size = SIZE_MAX);
    
    static std::vector<uint8_t> encrypt(const uint8_t* a, size_t a_size,
                                       const uint8_t* b, size_t b_size,
                                       size_t output_size = SIZE_MAX);
};

/**
 * @brief ROR (Rotate Right) encryption for JLU login
 */
class ROR {
public:
    /**
     * @brief Apply ROR encryption to data
     * @param data Input data
     * @return ROR encrypted data
     */
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> encrypt(const uint8_t* data, size_t size);
};

/**
 * @brief Checksum calculation for JLU login
 */
class Checksum {
public:
    /**
     * @brief Calculate checksum for JLU protocol
     * @param data Input data (size must be multiple of 4)
     * @param output_size Output size in bytes
     * @return Checksum bytes
     */
    static std::vector<uint8_t> calculate(const std::vector<uint8_t>& data,
                                         size_t output_size = 4);
    static std::vector<uint8_t> calculate(const uint8_t* data, size_t size,
                                         size_t output_size = 4);

private:
    static constexpr uint32_t MAGIC_NUMBER = 1234;
    static constexpr uint32_t MULTIPLIER = 1968;
};

/**
 * @brief CRC calculation for JLU keep alive
 */
class CRC {
public:
    /**
     * @brief Calculate CRC for JLU keep alive packets
     * @param data Input data
     * @param output_size Output size in bytes
     * @return CRC bytes
     */
    static std::vector<uint8_t> calculate(const std::vector<uint8_t>& data,
                                         size_t output_size = 4);
    static std::vector<uint8_t> calculate(const uint8_t* data, size_t size,
                                         size_t output_size = 4);

private:
    static constexpr uint32_t MULTIPLIER = 711;
};

/**
 * @brief High-level crypto utilities for DRCOM protocol
 */
class DrcomCrypto {
public:
    /**
     * @brief Generate MD5A digest (0x03 0x01 [salt] [password])
     * @param salt 4-byte salt
     * @param password User password
     * @return MD5 digest
     */
    static MD5::Digest generateMD5A(const std::array<uint8_t, 4>& salt,
                                   const std::string& password);
    
    /**
     * @brief Generate MD5B digest (0x01 [password] [salt] 0x00 0x00 0x00 0x00)
     * @param salt 4-byte salt
     * @param password User password
     * @return MD5 digest
     */
    static MD5::Digest generateMD5B(const std::array<uint8_t, 4>& salt,
                                   const std::string& password);
    
    /**
     * @brief Generate MD5C digest for login packet
     * @param packet_data First 97 bytes of login packet
     * @return First 8 bytes of MD5 digest
     */
    static std::array<uint8_t, 8> generateMD5C(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Generate password hash for login (ROR(password XOR MD5A))
     * @param password User password
     * @param md5a MD5A digest
     * @return Encrypted password
     */
    static std::vector<uint8_t> generatePasswordHash(const std::string& password,
                                                    const MD5::Digest& md5a);
    
    /**
     * @brief Generate MAC XOR MD5A for login
     * @param mac 6-byte MAC address
     * @param md5a MD5A digest
     * @return XOR result
     */
    static std::array<uint8_t, 6> generateMacHash(const std::array<uint8_t, 6>& mac,
                                                 const MD5::Digest& md5a);
};

} // namespace crypto
} // namespace drcom

#endif // CRYPTO_H