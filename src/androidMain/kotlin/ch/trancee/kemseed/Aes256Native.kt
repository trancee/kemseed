package ch.trancee.kemseed

/**
 * Pure-Kotlin reference backend for [Aes256Native] on the Android JVM target.
 *
 * Wraps the cached `Aes256Key` (one schedule per [Aes256Native] instance, reused
 * across the H/S/CTR blocks of a single seal/open — ADR-0002 §5.2) and delegates
 * to the in-place `Aes256Key.encryptBlock(block, out)` (T1). Byte-exact against
 * the FIPS-197 / NIST GCM KATs (host-gated via `testAndroidHostTest`).
 *
 * HW Android backend deferred to the device-KAT-gated follow-up (D11=B part 2):
 * arm64 AES-ACLE via an NDK C shim on `androidNativeArm64`. Requires the NDK
 * target + `cinterop` and cannot be host-KAT'd (R1) — lands as a device test.
 */
actual class Aes256Native actual constructor(key: ByteArray) {
    private val sched = Aes256.expandKey(key)
    actual fun encryptBlock(block: ByteArray, out: ByteArray): Unit = sched.encryptBlock(block, out)
}
