#include "Aes256_arm64.h"
#include <stddef.h>
#include <arm_neon.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <arm_acle.h>   /* NDK: AES intrinsics live here under __ARM_FEATURE_CRYPTO */
#endif

/* AES-256 single block via ARMv8-A AES-ACLE — canonical pattern (ARMv8-A ARM DDI0487C.a
 * A6.7.2450 AESE/AESMC). The 15 round keys are pre-expanded by the proven kotlin
 * Aes256.expandKey (software); only the AES BLOCK is HW.
 *   rk[0]          AddRoundKey(state, rk[0])
 *   r = 1..13      vaeseq_u8 (SubBytes+ShiftRows+AddRoundKey) then vaesmcq_u8 (MixColumns)
 *   r = 14 (final) vaeseq_u8 (no MixColumns)
 * uint8x16_t vectors stay INSIDE this .c; the bound API uses plain uint8_t* so KMP cinterop
 * skips binding SIMD vector types (the 4859-byte-knm cinterop gap). Host-verified:
 * `clang -march=armv8-a+crypto` lowers to @llvm.aarch64.crypto.aese/aesmc (IR) and
 * --target=aarch64-linux-android21 emits aes256_enc1block into the .o. Device KAT still
 * needs real arm64 Android HW (no image/emulator on this host, see tickets/11-1 & 11-2). */
static inline void aes256_enc_block(uint8x16_t *state, const uint8x16_t rk[15]) {
    *state = veorq_u8(*state, rk[0]);            /* AddRoundKey                       */
    for (int r = 1; r < 14; r++) {
        *state = vaeseq_u8(*state, rk[r]);       /* SubBytes+ShiftRows+AddRoundKey    */
        *state = vaesmcq_u8(*state);             /* MixColumns                       */
    }
    *state = vaeseq_u8(*state, rk[14]);          /* final round: no MixColumns       */
}

void aes256_enc1block(const uint8_t rk[240], const uint8_t in_[16], uint8_t out[16]) {
    uint8x16_t rk_vec[15];
    for (int i = 0; i < 15; i++) rk_vec[i] = vld1q_u8(rk + (size_t)i * 16);
    uint8x16_t state = vld1q_u8(in_);
    aes256_enc_block(&state, rk_vec);
    vst1q_u8(out, state);
}
