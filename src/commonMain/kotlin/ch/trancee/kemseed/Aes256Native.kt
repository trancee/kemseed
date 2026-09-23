package ch.trancee.kemseed

/**
 * Native (hardware-accelerated) AES-256 single-block ECB dispatch point — the
 * D11=B seam (ADR-0002 §5.2). The GCM/GMAC building blocks (`Aes256Gcm`,
 * [Gmac.gcmAuthTag]) call `encryptBlock` through this interface instead of
 * `Aes256` directly, so a platform can swap in TEE/SIMD AES without touching the
 * GHASH arithmetic:
 *
 * - Android: arm64 AES-ACLE instructions (`__builtin_arm_aesecb128`) via an NDK
 *   C shim — **not** Keystore `AES/GCM` (per-key keygen/init overhead dominates
 *   for tiny BLE PDUs; HW AES instructions are the real fast-path). Needs the
 *   `androidNativeArm64` target + NDK cinterop.
 * - iOS: CommonCrypto `CCCryptor` (HW AES on arm64). CryptoKit `AES.GCM` is
 *   Swift-only and invisible to KMP, so a CommonCrypto C shim is required.
 *
 * Each instance is materialised once per key (one expanded schedule / one HW key)
 * and reused across the H = AES(0^16), S = AES(J0) and per-CTR-block keystream
 * blocks of a single seal/open (ADR-0002 §5.2 — hoist the key material out of the
 * per-block path, the same invariant as the pure-Kotlin schedule caching).
 *
 * Single-block, in-place: encrypts exactly [Aes256.BLOCK_SIZE] bytes from
 * [block] into [out] (which may alias [block]).
 *
 * CT posture: native backends are constant-time by construction (HW AES in
 * TEE/SIMD, no secret-indexed table reads). The pure-Kotlin reference actuals
 * currently in use on every target carry the documented AES S-box cache-timing
 * surface (ADR-0002 §5.2) and are correctness-gated (FIPS-197 + NIST GCM KATs),
 * not side-channel-gated.
 */
expect class Aes256Native(key: ByteArray) {
    fun encryptBlock(block: ByteArray, out: ByteArray)
}
