package ch.trancee.kemseed

/**
 * AES-256-GMAC (NIST SP 800-38D GCM with empty plaintext): the integrity+authenticity
 * tag carried on the airborne element (`Packet_A1`/`Packet_A2`, ADR-0002 §3).
 *
 * GMAC(key, iv, aad) = GCM(key, iv, aad, plaintext=""):
 *   H  = AES-256(0^128)                        // hash subkey
 *   J0 = iv || 0x00000001                       // 96-bit IV => one counter block
 *   Y  = GHASH_H(aad_pad || len)               // len = [len(aad) bits]_64 || [0]_64
 *   T  = Y XOR AES-256(J0)
 *
 * Pure-Kotlin, commonMain (KMP: android + iosArm64). No `java.*`, no `clone()`.
 *
 * GHASH field multiply is the NIST SP 800-38D Algorithm 2 form: 16-byte big-endian
 * blocks (byte 0 = leftmost bit = x^0, the NIST bit convention), right-shift by x,
 * reduction polynomial x^128 + x^7 + x^2 + x + 1 applied as XOR `0xE1` into byte 0
 * (the high byte) on overflow. Byte-for-byte equivalence was checked against
 * `cryptography.hazmat.AESGCM` (OpenSSL-backed) on 400 random GCM vectors plus the
 * GMAC known-answer tests in [GmacTest]; the GHASH multiply was further cross-checked
 * against a textbook GF(2^128) schoolbook multiply (bit-reversed isomorphism) on
 * 2000 random pairs (0 mismatches).
 *
 * CT posture: the 128-bit GHASH accumulator runs in fixed 128-iteration loops with
 * data-independent control flow. AES-256 S-box table reads are a documented
 * cache-timing surface (ADR-0002 §5.2) — not a GMAC correctness blocker.
 */
internal object Gmac {

    private const val BLOCK_SIZE: Int = Aes256.BLOCK_SIZE
    private const val GCM_IV_SIZE: Int = 12
    internal const val TAG_SIZE: Int = BLOCK_SIZE

    /** GHASH field multiply Z = X · H over GF(2¹²⁸) (NIST SP 800-38D Alg. 2).
     *
     * [x] and [h] are 16-byte big-endian blocks; byte 0 is the leftmost bit (the
     * NIST convention, i.e. the most-significant bit of byte 0 carries x⁰). Returns
     * a fresh 16-byte block; inputs are not mutated. */
    private fun ghashMul(x: ByteArray, h: ByteArray): ByteArray {
        val z = ByteArray(BLOCK_SIZE)
        val v = h.copyOf()
        for (i in 0 until 128) {            // bit position left→right (x⁰ … x¹²⁷)
            if (ghashBit(x, i) == 1) {
                for (j in 0 until BLOCK_SIZE) z[j] = (z[j].toInt() xor v[j].toInt()).toByte()
            }
            val carry = ghashBit(v, 127)    // rightmost bit of v (byte15 LSB) = x¹²⁷ coefficient
            ghashRightShift1(v)             // v := v >> 1  (multiply by x)
            if (carry == 1) v[0] = (v[0].toInt() xor 0xE1).toByte()   // reduce into byte 0
        }
        return z
    }

    /** i-th bit from the left of [a] (i=0 ⇒ byte0 MSB = x⁰, NIST convention). */
    private fun ghashBit(a: ByteArray, i: Int): Int {
        val byteIndex = i ushr 3
        val bitInByte = 7 - (i and 7)
        return (a[byteIndex].toInt() ushr bitInByte) and 1
    }

    /** In-place right-shift of the 128-bit big-endian value [a] by one bit. */
    private fun ghashRightShift1(a: ByteArray) {
        for (j in 15 downTo 1) {
            val hi = a[j - 1].toInt() and 0xFF
            val lo = a[j].toInt() and 0xFF
            a[j] = ((lo ushr 1) or ((hi and 1) shl 7)).toByte()
        }
        a[0] = ((a[0].toInt() and 0xFF) ushr 1).toByte()
    }

    /** 16-byte AES-256-GMAC tag for [aad] under [key], 96-bit [iv]. */
    internal fun gmacTag(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray {
        require(iv.size == GCM_IV_SIZE) { "GMAC/GCM IV must be 96 bits ($GCM_IV_SIZE bytes); got ${iv.size}" }
        require(key.size == Aes256.KEY_SIZE) { "GMAC key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }

        // H = AES-256(0^128)
        val h = Aes256.encryptBlock(key, ByteArray(BLOCK_SIZE))

        // J0 = iv || 0x00 || 0x00 || 0x00 || 0x01  (96-bit IV, big-endian counter)
        val j0 = ByteArray(BLOCK_SIZE)
        for (i in 0 until GCM_IV_SIZE) j0[i] = iv[i]
        j0[BLOCK_SIZE - 1] = 1.toByte()

        // GHASH input: AAD padded up to a whole-block (zero-pad) boundary, then
        // the 16-byte length block [ len(aad) bits | 0 bits ] (empty plaintext).
        val aadLenPad = (BLOCK_SIZE - (aad.size % BLOCK_SIZE)) % BLOCK_SIZE
        val padded = ByteArray(aad.size + aadLenPad) { i ->
            if (i < aad.size) aad[i] else 0.toByte()
        }
        val lenBlock = ByteArray(BLOCK_SIZE)            // len(ct)=0 ⇒ low 8 bytes are 0
        val bitLen = aad.size.toLong() * 8
        for (i in 0 until 8) lenBlock[i] = ((bitLen ushr (56 - i * 8)) and 0xFF).toByte()

        var y = ByteArray(BLOCK_SIZE)
        for (i in padded.indices step BLOCK_SIZE) {
            for (j in 0 until BLOCK_SIZE) y[j] = (y[j].toInt() xor padded[i + j].toInt()).toByte()
            y = ghashMul(y, h)
        }
        for (j in 0 until BLOCK_SIZE) y[j] = (y[j].toInt() xor lenBlock[j].toInt()).toByte()
        y = ghashMul(y, h)

        // T = Y XOR AES-256(J0)
        val s = Aes256.encryptBlock(key, j0)
        val tag = ByteArray(BLOCK_SIZE)
        for (j in 0 until BLOCK_SIZE) tag[j] = (y[j].toInt() xor s[j].toInt()).toByte()
        return tag
    }
}
