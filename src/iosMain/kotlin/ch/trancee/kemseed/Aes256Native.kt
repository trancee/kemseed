package ch.trancee.kemseed

/**
 * Pure-Kotlin reference backend for [Aes256Native] on iOS.
 *
 * Same caching/in-place shape as the Android backend. HW iOS backend deferred to
 * the device-KAT-gated follow-up (D11=B part 2): CommonCrypto `CCCryptor` AES via
 * a `cinterop` C shim (R1 — CryptoKit `AES.GCM` is Swift-only and invisible to
 * KMP). Cannot be host-KAT'd, so it lands with a device test.
 */
actual class Aes256Native actual constructor(key: ByteArray) {
    private val sched = Aes256.expandKey(key)
    actual fun encryptBlock(block: ByteArray, out: ByteArray): Unit = sched.encryptBlock(block, out)
}
