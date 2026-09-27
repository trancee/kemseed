#ifndef AES256_ARM64_H
#define AES256_ARM64_H

#include <stdint.h>

/* AES-256-ECB single block via ARMv8-A AES-ACLE (vaeseq_u8/vaesmcq_u8).
 * rk   : 15 round keys (240 bytes), pre-expanded by the caller (kotlin Aes256.expandKey).
 * in_  : 16-byte plaintext block.
 * out  : 16-byte ciphertext block.
 * The arm64 AES block is constant-time in hardware (no S-box table), avoiding the ADR-0002
 * cache-timing surface the pure path carries. Vectors stay inside the .c; this API is plain
 * bytes so KMP cinterop does not need to bind uint8x16_t. */
#ifdef __cplusplus
extern "C" {
#endif
void aes256_enc1block(const uint8_t rk[240], const uint8_t in_[16], uint8_t out[16]);
#ifdef __cplusplus
}
#endif

#endif /* AES256_ARM64_H */
