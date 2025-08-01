#ifndef SHA256_NEON_H
#define SHA256_NEON_H

#include <cstdint>

void sha256neon_4B(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3
);

#endif // SHA256_NEON_H
