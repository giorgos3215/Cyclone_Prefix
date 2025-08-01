#ifndef RIPEMD160_NEON_H
#define RIPEMD160_NEON_H

#include <arm_neon.h>
#include <cstdint>

namespace ripemd160neon {

// Initialyzying Ripemd160
void Initialize(uint32x4_t *state);

// Transform NEON
void Transform(uint32x4_t *state, uint8_t *blocks[4]);

// Hashing functions
void ripemd160neon_32(
    unsigned char *i0, unsigned char *i1, unsigned char *i2, unsigned char *i3,
    unsigned char *d0, unsigned char *d1, unsigned char *d2, unsigned char *d3);

}  // namespace ripemd160neon

#endif  // RIPEMD160_NEON_H
