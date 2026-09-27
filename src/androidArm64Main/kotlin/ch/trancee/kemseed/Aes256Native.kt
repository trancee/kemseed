package ch.trancee.kemseed

/**
 * Pure-Kotlin reference backend for [Aes256Native] on Android arm64 (kotlin/Native).
 *
 * Mirrors the iOS backend (`iosMain`): same `Aes256.expandKey` schedule + in-place
 * single-block encrypt. HW AES-ACLE backend (D11.2 part 2) is deferred — kompact 0.3.0
 * resolves the klib variant, but the arm_neon AES intrinsics don't bind via NDK cinterop
 * (see `tickets/11-2-android-nativeacl-aesgcm-fastpath.md` §Status update). Once the
 * AES-ACLE C shim binds, swap this `actual` for the `platform.Arm64Crypto` one.
 *
 * Host-gated (R1): the 128-vector GCM Oracle + 20 NIST-CBC/GCM/GMAC goldens + 2000-pair
 * GHASH cross-check pin the pure `Aes256`/`Aes256Gcm`/`Gmac` arithmetic on the JVM host;
 * byte-exact cross-platform. Device KAT (arm64 AES block) pending on hardware.
 */
actual class Aes256Native actual constructor(key: ByteArray) {
    private val sched = Aes256.expandKey(key)
    actual fun encryptBlock(block: ByteArray, out: ByteArray): Unit = sched.encryptBlock(block, out)
}
