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
    // Operands are held as two 64-bit Long limbs (hi = bytes 0-7, lo = bytes 8-15), so the
    // 128-iteration schoolbook runs on word ops (~4x fewer byte ops than a per-byte loop).
    // Control flow is fixed (128 iters) and the per-bit conditional is a *masked* Long xor --
    // no secret-dependent branch, so this is constant-time and avoids the cache timing of a
    // lookup-table GHASH (whose index would be the secret accumulator). Byte-exact vs the
    // OpenSSL oracle (Aes256GcmTest: 128 random vectors + V1-V6 goldens).
    private fun bytesToLong(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or ((b[off + i].toInt() and 0xFF).toLong())
        return v
    }

    private fun longToBytes(v: Long, b: ByteArray, off: Int) {
        for (i in 0 until 8) b[off + 7 - i] = (v ushr (i * 8)).toByte()
    }

    private fun ghashMul(x: ByteArray, h: ByteArray): ByteArray {
        val xHi = bytesToLong(x, 0)
        val xLo = bytesToLong(x, 8)
        var zHi = 0L
        var zLo = 0L
        var vHi = bytesToLong(h, 0)
        var vLo = bytesToLong(h, 8)
        for (i in 0 until 128) {
            val bit = if (i < 64) (xHi ushr (63 - i)) and 1L else (xLo ushr (127 - i)) and 1L
            val mask = -bit // 0L or -1L -- fixed control flow (CT)
            zHi = zHi xor (vHi and mask)
            zLo = zLo xor (vLo and mask)
            val carry = vLo and 1L // rightmost bit of v (x^0) shifts out
            val vLoNew = (vLo ushr 1) or ((vHi and 1L) shl 63)
            val vHiNew = (vHi ushr 1) xor ((0xE1L shl 56) and (-carry)) // reduce into byte 0
            vHi = vHiNew
            vLo = vLoNew
        }
        val z = ByteArray(BLOCK_SIZE)
        longToBytes(zHi, z, 0)
        longToBytes(zLo, z, 8)
        return z
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

    /** AES-256-GCM/GMAC authentication tag for `aad ‖ ct` under [native] (one key/schedule)
     *  with 96-bit [iv]: `T = GHASH_H(pad(aad) ‖ pad(ct) ‖ lenBlock(aad,ct)) XOR AES-256(J0)`.
     *  Both the hash subkey H = AES(0^16) and S = AES(J0) are produced through the same
     *  [Aes256Native] instance (materialised once per seal/open) rather than re-expanding the
     *  AES key per block (ADR-0002 §5.2). H and S reuse one 16-byte scratch buffer — H is
     *  consumed by [ghashFold] before S overwrites it. */
    internal fun gcmAuthTag(native: Aes256Native, iv: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        val buf = ByteArray(BLOCK_SIZE)
        native.encryptBlock(ByteArray(BLOCK_SIZE), buf)            // H = AES(0^16)
        val j0 = j0(iv)
        val y = ghashFold(buf, padToBlockLen(aad) + padToBlockLen(ct) + lenBlock(aad, ct))
        native.encryptBlock(j0, buf)                                // S = AES(J0) — reuse buf (H already consumed)
        return xor16(y, buf)
    }

    /** AES-256-GMAC tag = GCM tag with an empty plaintext, under a raw 32-byte [key].
     *  Used by the Hmb1 handshake DoS-gate signer verification (#15); materialises [Aes256Native]
     *  once per call (signer verify is infrequent vs. the per-PDU GCM path). */
    internal fun gmacTag(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
        gcmAuthTag(Aes256Native(key), iv, aad, EMPTY)
}
