/*
 * HKDF over HMAC-SHA3-256 (RFC 5869), built on FIPS 202 Keccak.sha3_256.
 *
 * Pure-Kotlin, KMP commonMain (android + iosArm64). No java.* imports.
 *
 * Block size = SHA3-256 rate = 136 bytes (Keccak.RATE_SHA3_256, the HMAC
 * block size for a 256-bit sponge hash with capacity 512). HMAC follows
 * RFC 2104: when the key is longer than the block it is first hashed; when
 * shorter it is zero-padded to the block size; ipad=0x36, opad=0x5c.
 *
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM); a NULL/empty salt is replaced
 * by a string of HashLen (=HASH_SIZE=32) zero bytes per RFC 5869 §2.2.
 * HKDF-Expand: T(i) = HMAC-Hash(PRK, T(i-1) || info || [i]); the counter
 * [i] is a single byte (1..255), so outputLen <= 255*HASH_SIZE (§2.3).
 *
 * Goldens in HkdfTest are the RFC 5869 §B fixtures run with SHA3-256
 * (computed by an independent oracle: Python hmac+hashlib cross-checked
 * against `cryptography` HKDF(SHA3_256)). See ADR-0002 §4.
 */
package ch.trancee.kemseed

internal object Hkdf {

    internal const val HASH_SIZE: Int = 32      // SHA3-256 digest length (HashLen)
    internal const val BLOCK_SIZE: Int = 136    // SHA3-256 rate = HMAC block size

    /** HMAC-SHA3-256(key, msg) per RFC 2104. */
    fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        // Keys longer than the block are digested first (RFC 2104 §2).
        val k = if (key.size > BLOCK_SIZE) Keccak.sha3_256(key) else key
        val k0 = k.copyOf(BLOCK_SIZE)           // zero-pad/truncate to block size
        val ipad = ByteArray(BLOCK_SIZE)
        val opad = ByteArray(BLOCK_SIZE)
        for (i in 0 until BLOCK_SIZE) {
            val b = k0[i].toInt() and 0xff
            ipad[i] = (b xor 0x36).toByte()
            opad[i] = (b xor 0x5c).toByte()
        }
        // inner = H((K' xor ipad) || msg); outer = H((K' xor opad) || inner)
        val inner = Keccak.sha3_256(ipad + msg)
        return Keccak.sha3_256(opad + inner)
    }

    /** HKDF-Extract(salt, ikm) -> PRK (32 bytes). NULL salt -> 32 zero bytes. */
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(HASH_SIZE) else salt
        return hmac(s, ikm)
    }

    /** HKDF-Expand(prk, info, outputLen) -> OKM. RFC 5869 §2.3 length bound. */
    fun expand(prk: ByteArray, info: ByteArray, outputLen: Int): ByteArray {
        if (outputLen < 0) throw IllegalArgumentException("outputLen < 0")
        if (outputLen > 255 * HASH_SIZE) throw IllegalArgumentException(
            "HKDF-Expand output too long: $outputLen > ${255 * HASH_SIZE}"
        )
        val out = ByteArray(outputLen)
        var t = ByteArray(0)          // T(0) is the empty string
        var pos = 0
        var i = 1
        while (pos < outputLen) {
            // T(i) = HMAC(prk, T(i-1) || info || [i]); [i] is a single byte.
            t = hmac(prk, t + info + i.toByte())
            val n = kotlin.math.min(t.size, outputLen - pos)
            t.copyInto(out, pos, 0, n)
            pos += n
            i++
        }
        return out
    }

    /** HKDF-Extract then HKDF-Expand, the single entry-point the protocol uses. */
    fun extractThenExpand(
        salt: ByteArray, ikm: ByteArray, info: ByteArray, outputLen: Int
    ): ByteArray = expand(extract(salt, ikm), info, outputLen)
}
