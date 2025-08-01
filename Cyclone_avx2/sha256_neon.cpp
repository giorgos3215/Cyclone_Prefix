#include "sha256_neon.h"
#include <arm_neon.h>
#include <string.h>
#include <stdint.h>

namespace _sha256neon {

#ifdef _MSC_VER
#define ALIGN16 __declspec(align(16))
#else
#define ALIGN16 __attribute__((aligned(16)))
#endif

// Initialize SHA-256 state with initial hash values
void Initialize(uint32x4_t* s) {
    const uint32_t init[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    for (int i = 0; i < 8; ++i) {
        s[i] = vdupq_n_u32(init[i]);
    }
}

// SHA-256 macroses with NEON intrinsics
#define Ch(x, y, z) vbslq_u32(x, y, z)
#define Maj(x, y, z) veorq_u32(veorq_u32(vandq_u32(x, y), vandq_u32(x, z)), vandq_u32(y, z))
#define ROR(x, n) vorrq_u32(vshrq_n_u32(x, n), vshlq_n_u32(x, 32 - n))
#define SHR(x, n) vshrq_n_u32(x, n)

#define S0(x) (veorq_u32(ROR(x, 2), veorq_u32(ROR(x, 13), ROR(x, 22))))
#define S1(x) (veorq_u32(ROR(x, 6), veorq_u32(ROR(x, 11), ROR(x, 25))))
#define s0(x) (veorq_u32(ROR(x, 7), veorq_u32(ROR(x, 18), SHR(x, 3))))
#define s1(x) (veorq_u32(ROR(x, 17), veorq_u32(ROR(x, 19), SHR(x, 10))))

#define Round(a, b, c, d, e, f, g, h, Kt, Wt)                                    \
    T1 = vaddq_u32(vaddq_u32(vaddq_u32(vaddq_u32(h, S1(e)), Ch(e, f, g)), Kt), Wt); \
    T2 = vaddq_u32(S0(a), Maj(a, b, c));                                  \
    h = g;                                                                       \
    g = f;                                                                       \
    f = e;                                                                       \
    e = vaddq_u32(d, T1);                                                 \
    d = c;                                                                       \
    c = b;                                                                       \
    b = a;                                                                       \
    a = vaddq_u32(T1, T2);

void Transform(uint32x4_t* state, const uint8_t* data[4]) {
    uint32x4_t a, b, c, d, e, f, g, h;
    uint32x4_t W[64];
    uint32x4_t T1, T2;

    // Load state into local variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    // Prepare message schedule W[0..15]
    for (int t = 0; t < 16; ++t) {
        ALIGN16 uint32_t wt[4];
        for (int i = 0; i < 4; ++i) {
            const uint8_t* ptr = data[i] + t * 4;
            wt[i] = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | ((uint32_t)ptr[3]);
        }
        W[t] = vld1q_u32(wt);
    }

    for (int t = 16; t < 64; ++t) {
        W[t] = vaddq_u32(
                    vaddq_u32(s1(W[t - 2]), W[t - 7]),
                    vaddq_u32(s0(W[t - 15]), W[t - 16]));
    }

    // Constants
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Main loop of SHA-256
    for (int t = 0; t < 64; ++t) {
        uint32x4_t Kt = vdupq_n_u32(K[t]);
        Round(a, b, c, d, e, f, g, h, Kt, W[t]);
    }

    state[0] = vaddq_u32(state[0], a); state[1] = vaddq_u32(state[1], b);
    state[2] = vaddq_u32(state[2], c); state[3] = vaddq_u32(state[3], d);
    state[4] = vaddq_u32(state[4], e); state[5] = vaddq_u32(state[5], f);
    state[6] = vaddq_u32(state[6], g); state[7] = vaddq_u32(state[7], h);
}

} // namespace _sha256neon

void sha256neon_4B(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3) {

    uint32x4_t state[8];

    _sha256neon::Initialize(state);

    const uint8_t* data[4] = { data0, data1, data2, data3 };

    _sha256neon::Transform(state, data);

    ALIGN16 uint32_t digest[8][4];

    for (int i = 0; i < 8; ++i) {
        vst1q_u32(digest[i], state[i]);
    }

    unsigned char* hashArray[4] = { hash0, hash1, hash2, hash3 };

    for (int i = 0; i < 4; ++i) {
        unsigned char* hash = hashArray[i];
        for (int j = 0; j < 8; ++j) {
            uint32_t word = digest[j][i];
            word = __builtin_bswap32(word);
            memcpy(hash + j * 4, &word, 4);
        }
    }
}
