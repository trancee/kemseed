/*
 * Keccak-f[1600] / FIPS 202 hash + XOF (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256).
 *
 * Pure-Kotlin, KMP commonMain (android + iosArm64). No java.* imports.
 *
 * Constants are transcribed verbatim from `crypto/internal/fips140/sha3`
 * (Go stdlib, which is NIST-FIPS-202-conformant) and cross-checked against
 * CPython's `_sha3` NIST known-answer vectors:
 *   rc  : the 24 IOTA round constants (§5.4, FIPS 202).
 *   RHO : the 25 ρ rotation offsets, indexed by lane = x + 5*y.
 *
 * SHA3-256 : rate=136 B, capacity=512 bit, domain sep 0x06, output 32 B.
 * SHA3-512 : rate=72 B,  capacity=512 bit, domain sep 0x06, output 64 B.
 * SHAKE-128: rate=168 B, capacity=256 bit, domain sep 0x1F, XOF.
 * SHAKE-256: rate=136 B, capacity=512 bit, domain sep 0x1F, XOF.
 *
 * Absorb/squeeze are byte-oriented — every protocol input (and every ML-KEM
 * GFU/XOF input) is byte-aligned, so pad10* collapses into whole bytes: the
 * domain byte is XORed into the message tail and the final 0x80 bit into
 * state[rateBytes-1]. Lanes are little-endian (byte 0 = LSB of the lane).
 */
package ch.trancee.kemseed

internal object Keccak {

    private const val RHO_LANES: Int = 25        // 5 * 5
    internal const val RATE_SHA3_256: Int = 136   // bytes  (= 17 lanes)
    internal const val RATE_SHA3_512: Int = 72    // bytes  (= 9 lanes)
    internal const val RATE_SHAKE_128: Int = 168  // bytes  (= 21 lanes)
    internal const val RATE_SHAKE_256: Int = 136  // bytes  (= 17 lanes)

    /** 24 IOTA round constants (§5.4 FIPS 202). */
    private val RC: LongArray = longArrayOf(
        0x0000000000000001UL.toLong(), 0x0000000000008082UL.toLong(),
        0x800000000000808AUL.toLong(), 0x8000000080008000UL.toLong(),
        0x000000000000808BUL.toLong(), 0x0000000080000001UL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008009UL.toLong(),
        0x000000000000008AUL.toLong(), 0x0000000000000088UL.toLong(),
        0x0000000080008009UL.toLong(), 0x000000008000000AUL.toLong(),
        0x000000008000808BUL.toLong(), 0x800000000000008BUL.toLong(),
        0x8000000000008089UL.toLong(), 0x8000000000008003UL.toLong(),
        0x8000000000008002UL.toLong(), 0x8000000000000080UL.toLong(),
        0x000000000000800AUL.toLong(), 0x800000008000000AUL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008080UL.toLong(),
        0x0000000080000001UL.toLong(), 0x8000000080008008UL.toLong(),
    )
    /** ρ offsets, indexed by lane index = x + 5*y (x = column 0..4, y = row 0..4). */
    private val RHO: IntArray = intArrayOf(
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    )

    private fun rol64(x: Long, n: Int): Long =
        if (n == 0) x else (x shl n) or (x ushr (64 - n))

    /** Keccak-f[1600] permutation (24 rounds), in place. */
    private fun keccakF1600(s: LongArray) {
        val b = LongArray(RHO_LANES)
        for (rnd in 0..23) {
            // θ (theta)
            val c = LongArray(5)
            for (x in 0..4) {
                var v = 0L
                for (y in 0..4) v = v xor s[x + 5 * y]
                c[x] = v
            }
            val d = LongArray(5)
            for (x in 0..4) d[x] = c[(x + 4) % 5] xor rol64(c[(x + 1) % 5], 1)
            for (x in 0..4) for (y in 0..4) s[x + 5 * y] = s[x + 5 * y] xor d[x]
            // ρ (rho) + π (pi)
            for (x in 0..4) for (y in 0..4) {
                val off = RHO[x + 5 * y]
                val r = if (off == 0) s[x + 5 * y] else rol64(s[x + 5 * y], off)
                val nx = y
                val ny = (2 * x + 3 * y) % 5
                b[nx + 5 * ny] = r
            }
            // χ (chi)
            for (x in 0..4) for (y in 0..4) {
                val a = b[x + 5 * y]
                val e = b[(x + 1) % 5 + 5 * y]
                val c2 = b[(x + 2) % 5 + 5 * y]
                s[x + 5 * y] = a xor ((e.inv()) and c2)
            }
            // ι (iota)
            s[0] = s[0] xor RC[rnd]
        }
    }

    /** XOR [n] bytes of [src] (offset [srcOff]) into the rate lanes little-endian. */
    private fun xorRateBytes(state: LongArray, src: ByteArray, srcOff: Int, n: Int) {
        for (k in 0 until n) {
            val lane = k / 8
            val bitOff = (k % 8) * 8
            state[lane] = state[lane] xor ((src[srcOff + k].toLong() and 0xffL) shl bitOff)
        }
    }

    /** XOR a single domain/pad byte (or'd into the byte at [bytePos]) of state. */
    private fun xorByte(state: LongArray, bytePos: Int, v: Int) {
        val lane = bytePos / 8
        val bitOff = (bytePos % 8) * 8
        state[lane] = state[lane] xor ((v.toLong() and 0xffL) shl bitOff)
    }

    private fun sponge(input: ByteArray, rateBytes: Int, dsbyte: Int, outLen: Int): ByteArray {
        val state = LongArray(RHO_LANES)
        // ---- absorb ----
        var pos = 0
        while (pos + rateBytes <= input.size) {
            xorRateBytes(state, input, pos, rateBytes)
            keccakF1600(state)
            pos += rateBytes
        }
        val rest = input.size - pos
        xorRateBytes(state, input, pos, rest)          // message tail (0..rateBytes-1 bytes)
        // Domain byte lands at the rate byte right after the message tail; if the
        // message already filled the rate the while-loop permuted it and we start
        // a fresh all-zero block here (rest == 0). pad10* terminates at the MSB
        // of the last rate byte (both XORs merge into one lane if they coincide).
        xorByte(state, rest, dsbyte)                   // append domain byte after message tail
        xorByte(state, rateBytes - 1, 0x80)            // pad10* terminator
        // If domain byte and 0x80 share the final byte they land in one lane.
        keccakF1600(state)
        // ---- squeeze ----
        val out = ByteArray(outLen)
        var outPos = 0
        while (outPos < outLen) {
            val chunk = if (rateBytes < outLen - outPos) rateBytes else outLen - outPos
            for (k in 0 until chunk) {
                val lane = k / 8
                val bitOff = (k % 8) * 8
                out[outPos + k] = ((state[lane] ushr bitOff) and 0xffL).toByte()
            }
            outPos += chunk
            if (outPos < outLen) keccakF1600(state)
        }
        return out
    }

    /** SHA3-256, 32-byte digest (FIPS 202 §6.1, domain sep 0x06). */
    fun sha3_256(input: ByteArray): ByteArray =
        sponge(input, RATE_SHA3_256, 0x06, 32)

    /** SHA3-512, 64-byte digest (FIPS 202 §6.1, domain sep 0x06). */
    fun sha3_512(input: ByteArray): ByteArray =
        sponge(input, RATE_SHA3_512, 0x06, 64)

    /** SHAKE-128 extendable-output function (FIPS 202 §6.2, domain sep 0x1F). */
    fun shake128(input: ByteArray, outLen: Int): ByteArray =
        sponge(input, RATE_SHAKE_128, 0x1F, outLen)

    /** SHAKE-256 extendable-output function (FIPS 202 §6.2, domain sep 0x1F). */
    fun shake256(input: ByteArray, outLen: Int): ByteArray =
        sponge(input, RATE_SHAKE_256, 0x1F, outLen)
}
