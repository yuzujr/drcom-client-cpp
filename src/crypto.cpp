#include "drcom/crypto.h"
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <string>
#include <array>

namespace drcom {
namespace crypto {

// ================= MD5 Implementation =================
// Ported from the original md5.c implementation
namespace {
    using MD5_u32plus = uint32_t;
    
    struct MD5_CTX {
        MD5_u32plus lo, hi;
        MD5_u32plus a, b, c, d;
        uint8_t buffer[64];
        MD5_u32plus block[16];
    };

    // MD5 basic functions
    #define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
    #define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
    #define H(x, y, z) (((x) ^ (y)) ^ (z))
    #define H2(x, y, z) ((x) ^ ((y) ^ (z)))
    #define I(x, y, z) ((y) ^ ((x) | ~(z)))

    // MD5 transformation step
    #define STEP(f, a, b, c, d, x, t, s) \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
        (a) += (b);

    // SET/GET macros for endianness handling
    #if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
    #define SET(n) (*(MD5_u32plus *)&ptr[(n) * 4])
    #define GET(n) SET(n)
    #else
    #define SET(n) \
        (ctx->block[(n)] = \
        (MD5_u32plus)ptr[(n) * 4] | \
        ((MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
        ((MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
        ((MD5_u32plus)ptr[(n) * 4 + 3] << 24))
    #define GET(n) (ctx->block[(n)])
    #endif

    static const void *body(MD5_CTX *ctx, const void *data, unsigned long size) {
        const uint8_t *ptr = (const uint8_t *)data;
        MD5_u32plus a, b, c, d;
        MD5_u32plus saved_a, saved_b, saved_c, saved_d;

        a = ctx->a;
        b = ctx->b;
        c = ctx->c;
        d = ctx->d;

        do {
            saved_a = a;
            saved_b = b;
            saved_c = c;
            saved_d = d;

            // Round 1
            STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
            STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
            STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
            STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
            STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
            STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
            STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
            STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
            STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
            STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
            STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
            STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
            STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
            STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
            STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
            STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

            // Round 2
            STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
            STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
            STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
            STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
            STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
            STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
            STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
            STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
            STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
            STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
            STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
            STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
            STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
            STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
            STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
            STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

            // Round 3
            STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
            STEP(H2, d, a, b, c, GET(8), 0x8771f681, 11)
            STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
            STEP(H2, b, c, d, a, GET(14), 0xfde5380c, 23)
            STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
            STEP(H2, d, a, b, c, GET(4), 0x4bdecfa9, 11)
            STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
            STEP(H2, b, c, d, a, GET(10), 0xbebfbc70, 23)
            STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
            STEP(H2, d, a, b, c, GET(0), 0xeaa127fa, 11)
            STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
            STEP(H2, b, c, d, a, GET(6), 0x04881d05, 23)
            STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
            STEP(H2, d, a, b, c, GET(12), 0xe6db99e5, 11)
            STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
            STEP(H2, b, c, d, a, GET(2), 0xc4ac5665, 23)

            // Round 4
            STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
            STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
            STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
            STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
            STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
            STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
            STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
            STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
            STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
            STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
            STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
            STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
            STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
            STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
            STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
            STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

            a += saved_a;
            b += saved_b;
            c += saved_c;
            d += saved_d;

            ptr += 64;
        } while (size -= 64);

        ctx->a = a;
        ctx->b = b;
        ctx->c = c;
        ctx->d = d;

        return ptr;
    }

    static void MD5_Init(MD5_CTX *ctx) {
        ctx->a = 0x67452301;
        ctx->b = 0xefcdab89;
        ctx->c = 0x98badcfe;
        ctx->d = 0x10325476;
        ctx->lo = 0;
        ctx->hi = 0;
    }

    static void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size) {
        MD5_u32plus saved_lo;
        unsigned long used, available;

        saved_lo = ctx->lo;
        if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
            ctx->hi++;
        ctx->hi += size >> 29;

        used = saved_lo & 0x3f;

        if (used) {
            available = 64 - used;

            if (size < available) {
                memcpy(&ctx->buffer[used], data, size);
                return;
            }

            memcpy(&ctx->buffer[used], data, available);
            data = (const uint8_t *)data + available;
            size -= available;
            body(ctx, ctx->buffer, 64);
        }

        if (size >= 64) {
            data = body(ctx, data, size & ~(unsigned long)0x3f);
            size &= 0x3f;
        }

        memcpy(ctx->buffer, data, size);
    }

    #define OUT(dst, src) \
        (dst)[0] = (uint8_t)(src); \
        (dst)[1] = (uint8_t)((src) >> 8); \
        (dst)[2] = (uint8_t)((src) >> 16); \
        (dst)[3] = (uint8_t)((src) >> 24);

    static void MD5_Final(uint8_t *result, MD5_CTX *ctx) {
        unsigned long used, available;

        used = ctx->lo & 0x3f;
        ctx->buffer[used++] = 0x80;
        available = 64 - used;

        if (available < 8) {
            memset(&ctx->buffer[used], 0, available);
            body(ctx, ctx->buffer, 64);
            used = 0;
            available = 64;
        }

        memset(&ctx->buffer[used], 0, available - 8);

        ctx->lo <<= 3;
        OUT(&ctx->buffer[56], ctx->lo)
        OUT(&ctx->buffer[60], ctx->hi)

        body(ctx, ctx->buffer, 64);

        OUT(&result[0], ctx->a)
        OUT(&result[4], ctx->b)
        OUT(&result[8], ctx->c)
        OUT(&result[12], ctx->d)

        memset(ctx, 0, sizeof(*ctx));
    }

    // Cleanup macros
    #undef F
    #undef G
    #undef H
    #undef H2
    #undef I
    #undef STEP
    #undef SET
    #undef GET
    #undef OUT
}

// ================= MD5 Class Implementation =================

MD5::Digest MD5::hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}
MD5::Digest MD5::hash(const uint8_t* data, size_t size) {
    Digest digest{};
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, size);
    MD5_Final(digest.data(), &ctx);
    return digest;
}
MD5::Digest MD5::hash(const std::string& data) {
    return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ================= XOR =================
std::vector<uint8_t> XOR::encrypt(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, size_t output_size) {
    size_t size = std::min({a.size(), b.size(), output_size});
    std::vector<uint8_t> result(size);
    for (size_t i = 0; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> XOR::encrypt(const uint8_t* a, size_t a_size, const uint8_t* b, size_t b_size, size_t output_size) {
    size_t size = std::min({a_size, b_size, output_size});
    std::vector<uint8_t> result(size);
    for (size_t i = 0; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// ================= ROR =================
std::vector<uint8_t> ROR::encrypt(const std::vector<uint8_t>& data) {
    return encrypt(data.data(), data.size());
}

std::vector<uint8_t> ROR::encrypt(const uint8_t* data, size_t size) {
    std::vector<uint8_t> result(size);
    for (size_t i = 0; i < size; ++i) {
        result[i] = static_cast<uint8_t>((data[i] << 3) | (data[i] >> 5));
    }
    return result;
}

// ================= Checksum =================
std::vector<uint8_t> Checksum::calculate(const std::vector<uint8_t>& data, size_t output_size) {
    return calculate(data.data(), data.size(), output_size);
}

std::vector<uint8_t> Checksum::calculate(const uint8_t* data, size_t size, size_t output_size) {
    uint32_t sum = MAGIC_NUMBER;
    for (size_t i = 0; i < size; i += 4) {
        uint32_t tmp = 0;
        for (int j = 4; j > 0; --j) {
            tmp *= 256;
            if (i + j - 1 < size) tmp += data[i + j - 1];
        }
        sum ^= tmp;
    }
    sum = (MULTIPLIER * sum) & 0xffffffff;
    std::vector<uint8_t> result(output_size);
    for (size_t i = 0; i < output_size; ++i) {
        result[i] = static_cast<uint8_t>((sum >> (i * 8)) & 0xff);
    }
    return result;
}

// ================= CRC =================
std::vector<uint8_t> CRC::calculate(const std::vector<uint8_t>& data, size_t output_size) {
    return calculate(data.data(), data.size(), output_size);
}

std::vector<uint8_t> CRC::calculate(const uint8_t* data, size_t size, size_t output_size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i += 2) {
        uint32_t tmp = 0;
        for (int j = 2; j > 0; --j) {
            tmp *= 256;
            if (i + j - 1 < size) tmp += data[i + j - 1];
        }
        sum ^= tmp;
    }
    sum = (MULTIPLIER * sum);
    std::vector<uint8_t> result(output_size);
    for (size_t i = 0; i < output_size; ++i) {
        result[i] = static_cast<uint8_t>((sum >> (i * 8)) & 0xff);
    }
    return result;
}

// ================= DrcomCrypto 高级接口 =================
MD5::Digest DrcomCrypto::generateMD5A(const std::array<uint8_t, 4>& salt, const std::string& password) {
    std::vector<uint8_t> buf;
    buf.push_back(0x03);
    buf.push_back(0x01);
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), password.begin(), password.end());
    return MD5::hash(buf);
}

MD5::Digest DrcomCrypto::generateMD5B(const std::array<uint8_t, 4>& salt, const std::string& password) {
    std::vector<uint8_t> buf;
    buf.push_back(0x01);
    buf.insert(buf.end(), password.begin(), password.end());
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), {0x00, 0x00, 0x00, 0x00});
    return MD5::hash(buf);
}

std::array<uint8_t, 8> DrcomCrypto::generateMD5C(const std::vector<uint8_t>& packet_data) {
    std::vector<uint8_t> buf = packet_data;
    buf.push_back(0x14);
    buf.push_back(0x00);
    buf.push_back(0x07);
    buf.push_back(0x0b);
    auto digest = MD5::hash(buf);
    std::array<uint8_t, 8> result{};
    std::copy_n(digest.begin(), 8, result.begin());
    return result;
}

std::vector<uint8_t> DrcomCrypto::generatePasswordHash(const std::string& password, const MD5::Digest& md5a) {
    size_t len = std::min<size_t>(16, password.size());
    std::vector<uint8_t> pw_bytes(password.begin(), password.begin() + len);
    std::vector<uint8_t> md5a_bytes(md5a.begin(), md5a.begin() + len);
    auto xor_result = XOR::encrypt(md5a_bytes, pw_bytes, len);
    return ROR::encrypt(xor_result);
}

std::array<uint8_t, 6> DrcomCrypto::generateMacHash(const std::array<uint8_t, 6>& mac, const MD5::Digest& md5a) {
    std::array<uint8_t, 6> result{};
    for (size_t i = 0; i < 6; ++i) {
        result[i] = mac[i] ^ md5a[i];
    }
    return result;
}

} // namespace crypto
} // namespace drcom
