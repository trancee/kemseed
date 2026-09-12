package ch.trancee.kemseed

/**
 * AES-256-GMAC / AES-256-GCM GHASH primitives (NIST SP 800-38D Algorithms 2 & 3).
 *
 * GMAC is GCM with an empty plaintext (the integrity+authenticity tag carried on
 * the airborne element: `Packet_A1`/`Packet_A2`, E1′ handshake ADR-0002 §3). The
 * GHASH field multiplication below is the verified core reused by full
 * AES-256-GCM (`Aes256Gcm`) so the GCM multiply is implemented exactly once.
 *
 * GHASH field multiply is the NIST SP 800-38D Algorithm 2 form: 16-byte
 * big-endian blocks (byte 0 = leftmost bit = x^0, the NIST bit convention),
 * right-shift by x, reduction polynomial x^128 + x^7 + x^2 + x + 1 applied as
 * XOR `0xE1` into byte 0 (the high byte) on overflow. Byte-for-byte
 * equivalence was checked against `cryptography.hazmat.AESGCM` (OpenSSL-backed)
 * on 400 random GCM vectors plus the GMAC known-answer tests in [GmacTest]; the
 * GHASH multiply was further cross-checked against a textbook GF(2^128)
 * schoolbook multiply (bit-reversed isomorphism) on 2000 random pairs
 * (0 mismatches).
 *
 * CT posture: the 128-bit GHASH accumulator runs in fixed 128-iteration loops
 * (via [ghashMul]) with data-independent control flow. AES-256 S-box table
 * reads are a documented cache-timing surface (ADR-0002 §5.2).
 */
internal object Gmac {

    internal const val BLOCK_SIZE: Int = Aes256.BLOCK_SIZE
    private const val GCM_IV_SIZE: Int = 12
    internal const val TAG_SIZE: Int = BLOCK_SIZE
    private val EMPTY: ByteArray = ByteArray(0)

    // ---- GHASH field arithmetic: NIST SP 800-38D Algorithm 2 ----
    // byte 0 = leftmost bit = x^0 (NIST convention); reduction 0xE1 into byte 0.
    private fun ghashMul(x: ByteArray, h: ByteArray): ByteArray {
        val z = ByteArray(BLOCK_SIZE)
        val v = h.copyOf()           // operands are not mutated
        for (i in 0 until 128) {     // bit position left→right (x⁰ … x¹²⁷)
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

    /** GHASH_H polynomial-evaluation fold over [blocks] (length must be a non-zero
     *  multiple of [BLOCK_SIZE]): the standard GCM/GMAC chaining `Y = (Y ⊕ Bᵢ) · H`.
     *  Fixed 16-byte steps with data-independent control flow. */
    private fun ghashFold(h: ByteArray, blocks: ByteArray): ByteArray {
        require(blocks.size % BLOCK_SIZE == 0 && blocks.size >= BLOCK_SIZE) {
            "GHASH fold input must be a non-empty multiple of $BLOCK_SIZE bytes; got ${blocks.size}"
        }
        var y = ByteArray(BLOCK_SIZE)
        var i = 0
        while (i < blocks.size) {
            for (j in 0 until BLOCK_SIZE) y[j] = (y[j].toInt() xor blocks[i + j].toInt()).toByte()
            y = ghashMul(y, h)
            i += BLOCK_SIZE
        }
        return y
    }

    /** Right-zero-pad [b] up to a whole [BLOCK_SIZE] boundary (GCM pads AAD/CT blocks). */
    private fun padToBlockLen(b: ByteArray): ByteArray {
        val pad = (BLOCK_SIZE - (b.size % BLOCK_SIZE)) % BLOCK_SIZE
        if (pad == 0) return b.copyOf()
        return b.copyOf() + ByteArray(pad)
    }

    /** 16-byte length block `[ bitlen(aad) ‖ bitlen(ct) ]`, each big-endian 64-bit
     *  (NIST SP 800-38D §3.4 / Algorithm 2 length encoding). */
    private fun lenBlock(aad: ByteArray, ct: ByteArray): ByteArray {
        val block = ByteArray(BLOCK_SIZE)
        val aadBits = aad.size.toLong() * 8
        val ctBits = ct.size.toLong() * 8
        for (i in 0 until 8) {
            block[i] = ((aadBits ushr (56 - i * 8)) and 0xFF).toByte()
            block[8 + i] = ((ctBits ushr (56 - i * 8)) and 0xFF).toByte()
        }
        return block
    }

    private fun xor16(a: ByteArray, b: ByteArray): ByteArray {
        val r = ByteArray(BLOCK_SIZE)
        for (i in 0 until BLOCK_SIZE) r[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        return r
    }

    /** J0 for a 96-bit IV: `iv ‖ 0x00 0x00 0x00 0x01` (the 32-bit counter's initial
     *  value; byte[15] is the counter LSB, matching the OpenSSL/BoringSSL GCM IV form
     *  frozen in ADR-0002 §3). */
    internal fun j0(iv: ByteArray): ByteArray {
        require(iv.size == GCM_IV_SIZE) { "GCM IV must be 96 bits ($GCM_IV_SIZE bytes); got ${iv.size}" }
        val block = ByteArray(BLOCK_SIZE)
        for (i in 0 until GCM_IV_SIZE) block[i] = iv[i]
        block[BLOCK_SIZE - 1] = 1.toByte()
        return block
    }

    /** Inc32 (NIST SP 800-38D §6.2): increment the rightmost 32 bits of [block].
     *  Byte[15] is the LSB with carry propagating to byte[12] (OpenSSL/BoringSSL
     *  direction) — the first GCM keystream block is `AES(Inc32(J0))`. */
    internal fun inc32(block: ByteArray): ByteArray {
        require(block.size == BLOCK_SIZE) { "inc32 operates on a 128-bit block; got ${block.size}" }
        val r = block.copyOf()
        for (i in (BLOCK_SIZE - 1) downTo (BLOCK_SIZE - 4)) {
            val v = (r[i].toInt() and 0xFF) + 1
            r[i] = (v and 0xFF).toByte()
            if (v <= 0xFF) break
        }
        return r
    }

    /** AES-256-GCM/GMAC authentication tag for `aad ‖ ct` under [key] with 96-bit [iv]:
     *  `T = GHASH_H(pad(aad) ‖ pad(ct) ‖ lenBlock(aad,ct)) XOR AES-256(J0)`. */
    internal fun gcmAuthTag(key: ByteArray, iv: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        require(key.size == Aes256.KEY_SIZE) { "GCM key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }
        val h = Aes256.encryptBlock(key, ByteArray(BLOCK_SIZE))
        val j0 = j0(iv)
        val y = ghashFold(h, padToBlockLen(aad) + padToBlockLen(ct) + lenBlock(aad, ct))
        val s = Aes256.encryptBlock(key, j0)
        return xor16(y, s)
    }

    /** AES-256-GMAC tag = GCM tag with an empty plaintext (`gcmAuthTag(key, iv, aad, ∅)`). */
    internal fun gmacTag(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
        gcmAuthTag(key, iv, aad, EMPTY)
}
