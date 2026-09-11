/*
 * ML-KEM-512 (FIPS 203) – Pure-Kotlin KMP implementation (commonMain: Android + iOS arm64).
 *
 * Validated against the deterministic NIST FIPS 203 ML-KEM-512 known-answer vectors
 * (`kats/ml_kem_512.kat`, see MlKem512Test): q=3329 (FIPS 203 §4.1, NOT the 8380417 typo
 * that stale issue #19 listed — 8380417 is not an ML-KEM modulus).
 *
 * Hash/GFU wiring (FIPS 203 §4.1, Alg 4–9), pinned from the spec + itzmeanjan/ml-kem reference:
 *   G   = SHA3-512      KeyGen/Encaps/Decaps: G(m || H(pk)) -> (K, r)
 *   H   = SHA3-256      h = H(pk) (32-byte digest stored in sk)
 *   J   = SHAKE-256, 32 bytes   rk = J(z || c)  (implicit-rejection tag, Decaps)
 *   XOF = SHAKE-128     SampleNTT / SampleMatrix A  (Alg 7)
 *   PRF = SHAKE-256     SamplePoly CBD input for s, e, r  (Alg 8)
 * All of SHA3-256/512 + SHAKE-128/256 already live (and are NIST-green) in Keccak.kt.
 *
 * Constants (FIPS 203 §4.1, Table 2): q = 3329, n = 256, ζ = 17 (primitive 256-th root of
 * unity mod 3329), k = 2, η₁ = 3, η₂ = 2, dᵤ = 10, dᵥ = 4.
 * Artifact sizes: pk = 800, sk = 1632, ct = 768, ss = 32.
 *
 * Implementation note: every polynomial is a canonical [0, q) IntArray(256); arithmetic
 * uses Int with Long intermediates (→ canonical [0, q) via Barrett + one reduction).
 * No java.* / clone() usage, so it is iosArm64-safe (cf. X25519.kt). The NTT tables are
 * precomputed once at object init; the field ops use data-oblivious reduction (no early
 * exit) and Decaps uses a constant-time ct==c' select for implicit rejection.
 */
package ch.trancee.kemseed

internal object MlKem512 {

    // ---- ML-KEM-512 parameters (FIPS 203 §4.1, Table 2) ----
    internal const val Q: Int = 3329
    private const val Q_BIT_WIDTH: Int = 12
    internal const val N: Int = 256
    private const val LOG2N: Int = 8
    private const val K: Int = 2
    private const val ETA1: Int = 3
    private const val ETA2: Int = 2
    private const val DU: Int = 10
    private const val DV: Int = 4
    private const val ZETA: Int = 17            // primitive 256-th root of unity mod q
    private const val BARRETT_R: Int = 5039      // floor(2^(2*Q_BIT_WIDTH) / Q) = 2^24 / 3329

    // ---- published artifact lengths (FIPS 203 ML-KEM-512) ----
    public const val PUBLIC_KEY_LEN: Int = 800    // k*12*32 + 32
    public const val SECRET_KEY_LEN: Int = 1632   // k*12*32 + (k*12*32+32) + 32 + 32
    public const val CIPHERTEXT_LEN: Int = 768    // 32*(k*du + dv)
    public const val SHARED_SECRET_LEN: Int = 32

    // ---- prime-field Z_q arithmetic (canonical [0, Q)) ----
    private fun addZq(a: Int, b: Int): Int {
        var s = a + b
        if (s >= Q) s -= Q
        return s
    }

    private fun subZq(a: Int, b: Int): Int {
        var d = a - b
        if (d < 0) d += Q
        return d
    }

    private fun negZq(a: Int): Int = if (a == 0) 0 else Q - a

    private fun mulZq(a: Int, b: Int): Int {
        val v = a.toLong() * b
        val m = (v * BARRETT_R) ushr (2 * Q_BIT_WIDTH)
        var t = v - m * Q
        if (t < 0) t += Q.toLong()
        if (t >= Q) t -= Q.toLong()
        return t.toInt()
    }

    private fun modPow(base: Int, exp: Int): Int {
        var r = 1
        var b = base % Q
        var e = exp
        while (e > 0) {
            if ((e and 1) == 1) r = mulZq(r, b)
            b = mulZq(b, b)
            e = e ushr 1
        }
        return r
    }

    /** Difference of two small non-negative integers, reduced to canonical [0, Q). */
    private fun zqDiff(a: Int, b: Int): Int {
        var d = a - b
        while (d < 0) d += Q
        while (d >= Q) d -= Q
        return d
    }

    // ---- bit-reversal + NTT tables (precomputed at object init) ----
    private fun bitRev(v: Int, bits: Int): Int {
        var r = 0
        var x = v
        for (_i in 0 until bits) {
            r = (r shl 1) or (x and 1)
            x = x ushr 1
        }
        return r
    }

    private val INV_N: Int = modPow(N / 2, Q - 2)            // 128^-1 mod 3329
    private val NTT_ZETA_EXP: IntArray = IntArray(128) { i -> modPow(ZETA, bitRev(i, 7)) }
    private val INTT_ZETA_EXP: IntArray = IntArray(128) { i -> negZq(NTT_ZETA_EXP[i]) }
    private val POLY_MUL_ZETA_EXP: IntArray = IntArray(128) { i ->
        modPow(ZETA, (bitRev(i, 7) shl 1) or 1)
    }

    // ---- NTT (Cooley-Tukey, bit-reversed output) — Alg 9 ----
    internal fun ntt(poly: IntArray, off: Int) {
        var lvl = LOG2N - 1
        while (lvl >= 1) {
            val len = 1 shl lvl
            val lenx2 = len shl 1
            val kBeg = N ushr (lvl + 1)
            var start = 0
            while (start < N) {
                val kNow = kBeg + (start ushr (lvl + 1))
                val zeta = NTT_ZETA_EXP[kNow]
                var i = start
                while (i < start + len) {
                    val tmp = mulZq(zeta, poly[off + i + len])
                    poly[off + i + len] = subZq(poly[off + i], tmp)
                    poly[off + i] = addZq(poly[off + i], tmp)
                    i++
                }
                start += lenx2
            }
            lvl--
        }
    }

    // ---- iNTT (Gentleman-Sande, standard order, ·INV_N) — Alg 10 ----
    internal fun intt(poly: IntArray, off: Int) {
        var lvl = 1
        while (lvl < LOG2N) {
            val len = 1 shl lvl
            val lenx2 = len shl 1
            val kBeg = (N ushr lvl) - 1
            var start = 0
            while (start < N) {
                val kNow = kBeg - (start ushr (lvl + 1))
                val negZeta = INTT_ZETA_EXP[kNow]
                var i = start
                while (i < start + len) {
                    val tmp = poly[off + i]
                    poly[off + i] = addZq(poly[off + i], poly[off + i + len])
                    poly[off + i + len] = subZq(tmp, poly[off + i + len])
                    poly[off + i + len] = mulZq(poly[off + i + len], negZeta)
                    i++
                }
                start += lenx2
            }
            lvl++
        }
        for (i in 0 until N) poly[off + i] = mulZq(poly[off + i], INV_N)
    }

    // ---- basemul / polymul (NTT-domain negacyclic product) — Alg 11/12 ----
    private fun basemul(f: IntArray, fOff: Int, g: IntArray, gOff: Int, h: IntArray, hOff: Int, zeta: Int) {
        val f0 = f[fOff]; val f1 = f[fOff + 1]
        val g0 = g[gOff]; val g1 = g[gOff + 1]
        var t = mulZq(f0, g0)
        var u = mulZq(f1, g1)
        u = mulZq(u, zeta)
        h[hOff] = addZq(t, u)
        u = mulZq(g1, f0)
        t = mulZq(g0, f1)
        h[hOff + 1] = addZq(u, t)
    }

    private fun polymul(f: IntArray, fOff: Int, g: IntArray, gOff: Int, h: IntArray, hOff: Int) {
        for (i in 0 until (N / 2)) {
            val off = i * 2
            basemul(f, fOff + off, g, gOff + off, h, hOff + off, POLY_MUL_ZETA_EXP[i])
        }
    }

    /** c = a · b in the NTT domain (elementwise negacyclic polymul + accumulate). */
    private fun matrixMultiply(a: IntArray, aRows: Int, aCols: Int, b: IntArray, bCols: Int, c: IntArray) {
        val tmp = IntArray(N)
        for (i in 0 until aRows) {
            for (j in 0 until bCols) {
                val coff = (i * bCols + j) * N
                for (kk in 0 until aCols) {
                    polymul(a, (i * aCols + kk) * N, b, (kk * bCols + j) * N, tmp, 0)
                    for (t in 0 until N) c[coff + t] = addZq(c[coff + t], tmp[t])
                }
            }
        }
    }

    // ---- ByteEncode (Alg 5) / ByteDecode (Alg 6), l in {1,4,5,10,11,12} ----
    internal fun encode(l: Int, poly: IntArray, polyOff: Int, out: ByteArray, outOff: Int) {
        when (l) {
            1 -> {
                val itr = N ushr 3
                for (i in 0 until itr) {
                    val off = i shl 3
                    var w = 0
                    w = (w or (poly[polyOff + off + 0] and 1))
                    w = w or ((poly[polyOff + off + 1] and 1) shl 1)
                    w = w or ((poly[polyOff + off + 2] and 1) shl 2)
                    w = w or ((poly[polyOff + off + 3] and 1) shl 3)
                    w = w or ((poly[polyOff + off + 4] and 1) shl 4)
                    w = w or ((poly[polyOff + off + 5] and 1) shl 5)
                    w = w or ((poly[polyOff + off + 6] and 1) shl 6)
                    w = w or ((poly[polyOff + off + 7] and 1) shl 7)
                    out[outOff + i] = w.toByte()
                }
            }
            4 -> {
                for (i in 0 until (N ushr 1)) {
                    val off = i shl 1
                    out[outOff + i] = (((poly[polyOff + off + 1] and 0xF) shl 4) or (poly[polyOff + off + 0] and 0xF)).toByte()
                }
            }
            5 -> {
                for (i in 0 until (N ushr 3)) {
                    val poff = i shl 3
                    val boff = i * 5
                    val t0 = poly[polyOff + poff + 0]; val t1 = poly[polyOff + poff + 1]
                    val t2 = poly[polyOff + poff + 2]; val t3 = poly[polyOff + poff + 3]
                    val t4 = poly[polyOff + poff + 4]; val t5 = poly[polyOff + poff + 5]
                    val t6 = poly[polyOff + poff + 6]; val t7 = poly[polyOff + poff + 7]
                    out[outOff + boff + 0] = (((t1 and 7) shl 5) or (t0 and 31)).toByte()
                    out[outOff + boff + 1] = (((t3 and 1) shl 7) or ((t2 and 31) shl 2) or ((t1 ushr 3) and 3)).toByte()
                    out[outOff + boff + 2] = (((t4 and 15) shl 4) or ((t3 ushr 1) and 15)).toByte()
                    out[outOff + boff + 3] = (((t6 and 3) shl 6) or ((t5 and 31) shl 1) or ((t4 ushr 4) and 1)).toByte()
                    out[outOff + boff + 4] = (((t7 and 31) shl 3) or ((t6 ushr 2) and 7)).toByte()
                }
            }
            10 -> {
                for (i in 0 until (N ushr 2)) {
                    val poff = i shl 2
                    val boff = i * 5
                    val t0 = poly[polyOff + poff + 0]; val t1 = poly[polyOff + poff + 1]
                    val t2 = poly[polyOff + poff + 2]; val t3 = poly[polyOff + poff + 3]
                    out[outOff + boff + 0] = (t0 and 0xFF).toByte()
                    out[outOff + boff + 1] = (((t1 and 63) shl 2) or ((t0 ushr 8) and 3)).toByte()
                    out[outOff + boff + 2] = (((t2 and 15) shl 4) or ((t1 ushr 6) and 15)).toByte()
                    out[outOff + boff + 3] = (((t3 and 3) shl 6) or ((t2 ushr 4) and 63)).toByte()
                    out[outOff + boff + 4] = ((t3 ushr 2) and 0xFF).toByte()
                }
            }
            11 -> {
                for (i in 0 until (N ushr 3)) {
                    val poff = i shl 3
                    val boff = i * 11
                    val t0 = poly[polyOff + poff + 0]; val t1 = poly[polyOff + poff + 1]
                    val t2 = poly[polyOff + poff + 2]; val t3 = poly[polyOff + poff + 3]
                    val t4 = poly[polyOff + poff + 4]; val t5 = poly[polyOff + poff + 5]
                    val t6 = poly[polyOff + poff + 6]; val t7 = poly[polyOff + poff + 7]
                    out[outOff + boff + 0] = (t0 and 0xFF).toByte()
                    out[outOff + boff + 1] = (((t1 and 31) shl 3) or ((t0 ushr 8) and 7)).toByte()
                    out[outOff + boff + 2] = (((t2 and 3) shl 6) or ((t1 ushr 5) and 63)).toByte()
                    out[outOff + boff + 3] = ((t2 ushr 2) and 0xFF).toByte()
                    out[outOff + boff + 4] = (((t3 and 127) shl 1) or ((t2 ushr 10) and 1)).toByte()
                    out[outOff + boff + 5] = (((t4 and 15) shl 4) or ((t3 ushr 7) and 15)).toByte()
                    out[outOff + boff + 6] = (((t5 and 1) shl 7) or ((t4 ushr 4) and 127)).toByte()
                    out[outOff + boff + 7] = ((t5 ushr 1) and 0xFF).toByte()
                    out[outOff + boff + 8] = (((t6 and 63) shl 2) or ((t5 ushr 9) and 3)).toByte()
                    out[outOff + boff + 9] = (((t7 and 7) shl 5) or ((t6 ushr 6) and 31)).toByte()
                    out[outOff + boff + 10] = ((t7 ushr 3) and 0xFF).toByte()
                }
            }
            12 -> {
                for (i in 0 until (N ushr 1)) {
                    val poff = i shl 1
                    val boff = i * 3
                    val t0 = poly[polyOff + poff + 0]; val t1 = poly[polyOff + poff + 1]
                    out[outOff + boff + 0] = (t0 and 0xFF).toByte()
                    out[outOff + boff + 1] = (((t1 and 15) shl 4) or ((t0 ushr 8) and 15)).toByte()
                    out[outOff + boff + 2] = ((t1 ushr 4) and 0xFF).toByte()
                }
            }
        }
    }

    internal fun decode(l: Int, bytes: ByteArray, byteOff: Int, poly: IntArray, polyOff: Int) {
        when (l) {
            1 -> {
                val itr = N ushr 3
                for (i in 0 until itr) {
                    val byte = bytes[byteOff + i].toInt() and 0xFF
                    val off = i shl 3
                    poly[polyOff + off + 0] = byte and 1
                    poly[polyOff + off + 1] = (byte ushr 1) and 1
                    poly[polyOff + off + 2] = (byte ushr 2) and 1
                    poly[polyOff + off + 3] = (byte ushr 3) and 1
                    poly[polyOff + off + 4] = (byte ushr 4) and 1
                    poly[polyOff + off + 5] = (byte ushr 5) and 1
                    poly[polyOff + off + 6] = (byte ushr 6) and 1
                    poly[polyOff + off + 7] = (byte ushr 7) and 1
                }
            }
            4 -> {
                for (i in 0 until (N ushr 1)) {
                    val off = i shl 1
                    val byte = bytes[byteOff + i].toInt() and 0xFF
                    poly[polyOff + off + 0] = byte and 15
                    poly[polyOff + off + 1] = (byte ushr 4) and 15
                }
            }
            5 -> {
                for (i in 0 until (N ushr 3)) {
                    val poff = i shl 3
                    val boff = i * 5
                    val b0 = bytes[byteOff + boff + 0].toInt() and 0xFF
                    val b1 = bytes[byteOff + boff + 1].toInt() and 0xFF
                    val b2 = bytes[byteOff + boff + 2].toInt() and 0xFF
                    val b3 = bytes[byteOff + boff + 3].toInt() and 0xFF
                    val b4 = bytes[byteOff + boff + 4].toInt() and 0xFF
                    poly[polyOff + poff + 0] = b0 and 31
                    poly[polyOff + poff + 1] = ((b1 and 3) shl 3) or ((b0 ushr 5) and 7)
                    poly[polyOff + poff + 2] = (b1 ushr 2) and 31
                    poly[polyOff + poff + 3] = ((b2 and 15) shl 1) or ((b1 ushr 7) and 1)
                    poly[polyOff + poff + 4] = ((b3 and 1) shl 4) or (b2 ushr 4)
                    poly[polyOff + poff + 5] = (b3 ushr 1) and 31
                    poly[polyOff + poff + 6] = ((b4 and 7) shl 2) or ((b3 ushr 6) and 3)
                    poly[polyOff + poff + 7] = (b4 ushr 3) and 31
                }
            }
            10 -> {
                for (i in 0 until (N ushr 2)) {
                    val poff = i shl 2
                    val boff = i * 5
                    val b0 = bytes[byteOff + boff + 0].toInt() and 0xFF
                    val b1 = bytes[byteOff + boff + 1].toInt() and 0xFF
                    val b2 = bytes[byteOff + boff + 2].toInt() and 0xFF
                    val b3 = bytes[byteOff + boff + 3].toInt() and 0xFF
                    val b4 = bytes[byteOff + boff + 4].toInt() and 0xFF
                    poly[polyOff + poff + 0] = ((b1 and 3) shl 8) or b0
                    poly[polyOff + poff + 1] = ((b2 and 15) shl 6) or (b1 ushr 2)
                    poly[polyOff + poff + 2] = ((b3 and 63) shl 4) or (b2 ushr 4)
                    poly[polyOff + poff + 3] = ((b4) shl 2) or (b3 ushr 6)
                }
            }
            11 -> {
                for (i in 0 until (N ushr 3)) {
                    val poff = i shl 3
                    val boff = i * 11
                    val b0 = bytes[byteOff + boff + 0].toInt() and 0xFF
                    val b1 = bytes[byteOff + boff + 1].toInt() and 0xFF
                    val b2 = bytes[byteOff + boff + 2].toInt() and 0xFF
                    val b3 = bytes[byteOff + boff + 3].toInt() and 0xFF
                    val b4 = bytes[byteOff + boff + 4].toInt() and 0xFF
                    val b5 = bytes[byteOff + boff + 5].toInt() and 0xFF
                    val b6 = bytes[byteOff + boff + 6].toInt() and 0xFF
                    val b7 = bytes[byteOff + boff + 7].toInt() and 0xFF
                    val b8 = bytes[byteOff + boff + 8].toInt() and 0xFF
                    val b9 = bytes[byteOff + boff + 9].toInt() and 0xFF
                    val b10 = bytes[byteOff + boff + 10].toInt() and 0xFF
                    poly[polyOff + poff + 0] = ((b1 and 7) shl 8) or b0
                    poly[polyOff + poff + 1] = ((b2 and 63) shl 5) or (b1 ushr 3)
                    poly[polyOff + poff + 2] = ((b4 and 1) shl 10) or (b3 shl 2) or (b2 ushr 6)
                    poly[polyOff + poff + 3] = ((b5 and 15) shl 7) or (b4 ushr 1)
                    poly[polyOff + poff + 4] = ((b6 and 127) shl 4) or (b5 ushr 4)
                    poly[polyOff + poff + 5] = ((b8 and 3) shl 9) or (b7 shl 1) or (b6 ushr 7)
                    poly[polyOff + poff + 6] = ((b9 and 31) shl 6) or (b8 ushr 2)
                    poly[polyOff + poff + 7] = (b10 shl 3) or (b9 ushr 5)
                }
            }
            12 -> {
                for (i in 0 until (N ushr 1)) {
                    val poff = i shl 1
                    val boff = i * 3
                    val b0 = bytes[byteOff + boff + 0].toInt() and 0xFF
                    val b1 = bytes[byteOff + boff + 1].toInt() and 0xFF
                    val b2 = bytes[byteOff + boff + 2].toInt() and 0xFF
                    val t0 = ((b1 and 15) shl 8) or b0          // in [0, 4096)
                    val t1 = (b2 shl 4) or ((b1 ushr 4) and 15)  // in [0, 4096)
                    poly[polyOff + poff + 0] = modZq(t0.toLong())
                    poly[polyOff + poff + 1] = modZq(t1.toLong())
                }
            }
        }
    }

    /** Barrett reduction of any non-negative Long into canonical [0, Q). */
    private fun modZq(v: Long): Int {
        var t = v
        while (t >= Q) {
            val m = (t * BARRETT_R) ushr (2 * Q_BIT_WIDTH)
            t = t - m * Q
            if (t < 0) t += Q.toLong()
        }
        while (t < 0) t += Q.toLong()
        if (t >= Q) t -= Q.toLong()
        return t.toInt()
    }

    /** Compress (FIPS 203 formula 4.7): x in [0,Q) -> [0, 2^d). */
    private fun compress(d: Int, x: Int): Int {
        val mask = (1L shl d) - 1L
        val dividend = x.toLong() shl d
        val quotient0 = (dividend * BARRETT_R) ushr (2 * Q_BIT_WIDTH)
        var remainder = dividend - quotient0 * Q
        var quotient1 = quotient0 + (((Q / 2L - remainder) shr 63) and 1L)
        var quotient2 = quotient1 + (((Q.toLong() + Q / 2L - remainder) shr 63) and 1L)
        return (quotient2 and mask).toInt()
    }

    /** Decompress (FIPS 203 formula 4.8): x in [0, 2^d) -> [0, Q). */
    private fun decompress(d: Int, x: Int): Int {
        val t1 = 1L shl d ushr 1                       // 2^(d-1)
        val t2 = Q.toLong() * x
        val t3 = t2 + t1
        return (t3 ushr d).toInt()
    }

    private fun polyCompress(d: Int, poly: IntArray, off: Int) {
        for (i in 0 until N) poly[off + i] = compress(d, poly[off + i])
    }

    private fun polyDecompress(d: Int, poly: IntArray, off: Int) {
        for (i in 0 until N) poly[off + i] = decompress(d, poly[off + i])
    }

    private fun polyVecCompress(k: Int, d: Int, v: IntArray, off: Int) {
        for (i in 0 until k) polyCompress(d, v, off + i * N)
    }

    private fun polyVecDecompress(k: Int, d: Int, v: IntArray, off: Int) {
        for (i in 0 until k) polyDecompress(d, v, off + i * N)
    }

    private fun polyVecNtt(k: Int, v: IntArray, off: Int) {
        for (i in 0 until k) ntt(v, off + i * N)
    }

    private fun polyVecIntt(k: Int, v: IntArray, off: Int) {
        for (i in 0 until k) intt(v, off + i * N)
    }

    private fun polyVecEncode(k: Int, l: Int, src: IntArray, srcOff: Int, dst: ByteArray, dstOff: Int) {
        for (i in 0 until k) encode(l, src, srcOff + i * N, dst, dstOff + i * 32 * l)
    }

    private fun polyVecDecode(k: Int, l: Int, src: ByteArray, srcOff: Int, dst: IntArray, dstOff: Int) {
        for (i in 0 until k) decode(l, src, srcOff + i * 32 * l, dst, dstOff + i * N)
    }

    private fun polyVecAdd(k: Int, src: IntArray, srcOff: Int, dst: IntArray, dstOff: Int) {
        for (i in 0 until k) {
            for (j in 0 until N) dst[dstOff + i * N + j] = addZq(dst[dstOff + i * N + j], src[srcOff + i * N + j])
        }
    }

    private fun polyVecSubFrom(k: Int, src: IntArray, srcOff: Int, dst: IntArray, dstOff: Int) {
        for (i in 0 until k) {
            for (j in 0 until N) dst[dstOff + i * N + j] = subZq(dst[dstOff + i * N + j], src[srcOff + i * N + j])
        }
    }

    // ---- SampleNTT (Alg 7): SHAKE-128 XOF -> 256 NTT-domain coeffs in [0, Q) ----
    private fun sampleNtt(seed: ByteArray): IntArray {
        val out = IntArray(N)
        // SHAKE is a stream; pre-squeezing a generous buffer is byte-identical to the
        // reference's incremental `squeeze(RATE)` loop (rate=168, but we only need ~256
        // accepts out of ~2730 candidate triples, so 8 KiB is astronomically sufficient).
        val buf = Keccak.shake128(seed, 8192)
        var idx = 0
        var bi = 0
        while (idx < N && bi + 3 <= buf.size) {
            val b0 = buf[bi].toInt() and 0xFF
            val b1 = buf[bi + 1].toInt() and 0xFF
            val b2 = buf[bi + 2].toInt() and 0xFF
            val d1 = ((b1 and 0x0F) shl 8) or b0
            val d2 = (b2 shl 4) or (b1 ushr 4)
            if (d1 < Q) out[idx++] = d1
            if (idx < N && d2 < Q) out[idx++] = d2
            bi += 3
        }
        return out
    }

    // ---- SampleMatrix A (Alg 13, steps 3-7): SHAKE-128(ρ || nonces), NTT-domain ----
    private fun generateMatrix(rho: ByteArray, transpose: Boolean): IntArray {
        val mat = IntArray(K * K * N)
        for (i in 0 until K) {
            for (j in 0 until K) {
                val seed = if (transpose)
                    (rho + byteArrayOf(i.toByte(), j.toByte()))   // ρ ‖ i ‖ j  -> A^T[i][j]
                else
                    (rho + byteArrayOf(j.toByte(), i.toByte()))   // ρ ‖ j ‖ i  -> A[i][j]
                val poly = sampleNtt(seed)
                val base = (i * K + j) * N
                for (t in 0 until N) mat[base + t] = poly[t]
            }
        }
        return mat
    }

    // ---- SamplePoly CBD (Alg 8): PRF=SHAKE-256(σ || nonce||i), 64*eta bytes -> 256 coeffs ----
    private fun sampleCbd(eta: Int, prf: ByteArray, out: IntArray, off: Int) {
        if (eta == 2) {
            for (i in 0 until (64 * eta)) { // 64*eta = 128 iters -> 256 coeffs (2 coeffs/iter)
                val w = prf[i].toInt() and 0xFF
                val t0 = w and 0x55
                val t1 = (w ushr 1) and 0x55
                val t2 = t0 + t1
                out[off + (i shl 1) + 0] = zqDiff(t2 and 3, (t2 ushr 2) and 3)
                out[off + (i shl 1) + 1] = zqDiff((t2 ushr 4) and 3, (t2 ushr 6) and 3)
            }
        } else {
            val mask24 = 0b001001001001001001001001
            for (i in 0 until 64) {
                val bo = i * 3
                val word = (prf[bo].toInt() and 0xFF) or
                    ((prf[bo + 1].toInt() and 0xFF) shl 8) or
                    ((prf[bo + 2].toInt() and 0xFF) shl 16)
                val t0 = word and mask24
                val t1 = (word ushr 1) and mask24
                val t2 = (word ushr 2) and mask24
                val t3 = t0 + t1 + t2
                out[off + (i shl 2) + 0] = zqDiff(t3 and 7, (t3 ushr 3) and 7)
                out[off + (i shl 2) + 1] = zqDiff((t3 ushr 6) and 7, (t3 ushr 9) and 7)
                out[off + (i shl 2) + 2] = zqDiff((t3 ushr 12) and 7, (t3 ushr 15) and 7)
                out[off + (i shl 2) + 3] = zqDiff((t3 ushr 18) and 7, (t3 ushr 21) and 7)
            }
        }
    }

    private fun generateVector(sigma: ByteArray, eta: Int, nonce: Int, nPolys: Int): IntArray {
        val out = IntArray(nPolys * N)
        val prfLen = 64 * eta
        for (i in 0 until nPolys) {
            val prfIn = sigma + byteArrayOf(((nonce + i) and 0xFF).toByte())
            val prf = Keccak.shake256(prfIn, prfLen)
            sampleCbd(eta, prf, out, i * N)
        }
        return out
    }

    // ---- constant-time byte compare (returns 1 iff equal) ----
    private fun bytesEqual(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Int {
        var d = 0
        for (i in 0 until len) d = d or ((a[aOff + i].toInt() xor b[bOff + i].toInt()))
        return if (d == 0) 1 else 0
    }

    private fun copyBytes(src: ByteArray, srcOff: Int, len: Int): ByteArray {
        val out = ByteArray(len)
        for (i in 0 until len) out[i] = src[srcOff + i]
        return out
    }

    // ---- K-PKE KeyGen (Alg 13) -> (pubkey[k*12*32+32], seckey[k*12*32]) ----
    private fun kPkeKeygen(d: ByteArray): Pair<ByteArray, ByteArray> {
        val rhoSigma = Keccak.sha3_512(d + byteArrayOf(K.toByte()))   // G(d || k) -> rho || sigma
        val rho = copyBytes(rhoSigma, 0, 32)
        val sigma = copyBytes(rhoSigma, 32, 32)

        val aPrime = generateMatrix(rho, /* transpose = */ false)   // A' = NTT(A), [0]=A[0][0]...
        val s = generateVector(sigma, ETA1, 0, K)                      // nonce 0, 1
        val e = generateVector(sigma, ETA1, K, K)                      // nonce 2, 3
        polyVecNtt(K, s, 0)
        polyVecNtt(K, e, 0)

        val tPrime = IntArray(K * N)                                 // A' · s + e  (NTT domain)
        matrixMultiply(aPrime, K, K, s, 1, tPrime)
        polyVecAdd(K, e, 0, tPrime, 0)

        val pkOff = K * 12 * 32                                       // 768
        val pubkey = ByteArray(pkOff + 32)                             // 800
        val seckey = ByteArray(K * 12 * 32)                            // 768
        polyVecEncode(K, 12, tPrime, 0, pubkey, 0)
        for (i in 0 until 32) pubkey[pkOff + i] = rho[i]
        polyVecEncode(K, 12, s, 0, seckey, 0)
        return Pair(pubkey, seckey)
    }

    // ---- K-PKE Encrypt (Alg 14) -> ct[k*du*32 + dv*32] (throws on invalid pk) ----
    private fun kPkeEncrypt(pubkey: ByteArray, msg: ByteArray, rcoin: ByteArray): ByteArray {
        val tPrimeOff = K * 12 * 32                                   // 768
        val rho = copyBytes(pubkey, tPrimeOff, 32)

        // modulus check: re-encode t' and compare to the bytes carried in pk
        val tPrime = IntArray(K * N)
        polyVecDecode(K, 12, pubkey, 0, tPrime, 0)
        val reencoded = ByteArray(tPrimeOff)
        polyVecEncode(K, 12, tPrime, 0, reencoded, 0)
        if (bytesEqual(reencoded, 0, pubkey, 0, tPrimeOff) == 0) {
            throw IllegalArgumentException("invalid ML-KEM public key (modulus check failed)")
        }

        val aPrimeT = generateMatrix(rho, /* transpose = */ true)     // A^T
        val r = generateVector(rcoin, ETA1, 0, K)                     // nonce 0, 1
        val e1 = generateVector(rcoin, ETA2, K, K)                    // nonce 2, 3
        val e2 = generateVector(rcoin, ETA2, 2 * K, 1)                // nonce 4
        polyVecNtt(K, r, 0)

        val u = IntArray(K * N)                                       // u = A^T · r, then intt + e1
        matrixMultiply(aPrimeT, K, K, r, 1, u)
        polyVecIntt(K, u, 0)
        polyVecAdd(K, e1, 0, u, 0)

        val v = IntArray(N)                                           // v = t' · r, then intt + e2 + m
        matrixMultiply(tPrime, 1, K, r, 1, v)
        intt(v, 0)
        polyVecAdd(1, e2, 0, v, 0)

        val mPoly = IntArray(N)
        decode(1, msg, 0, mPoly, 0)
        polyDecompress(1, mPoly, 0)                                   // Decompress(1, DecodeBytes(m))
        polyVecAdd(1, mPoly, 0, v, 0)

        val ctxt = ByteArray(CIPHERTEXT_LEN)                            // 768
        polyVecCompress(K, DU, u, 0)
        polyVecEncode(K, DU, u, 0, ctxt, 0)                           // u part: k*du*32 = 640
        polyCompress(DV, v, 0)
        encode(DV, v, 0, ctxt, K * DU * 32)                           // v part: dv*32 = 128
        return ctxt
    }

    // ---- K-PKE Decrypt (Alg 15) -> recovered 32-byte message m' ----
    private fun kPkeDecrypt(seckey: ByteArray, ct: ByteArray): ByteArray {
        val uOff = K * DU * 32                                        // 640
        val vOff = uOff                                                // v starts at 640
        val u = IntArray(K * N)
        val v = IntArray(N)
        polyVecDecode(K, DU, ct, 0, u, 0)
        polyVecDecompress(K, DU, u, 0)                                // Decompress(du, DecodeBytes(u))
        decode(DV, ct, vOff, v, 0)
        polyDecompress(DV, v, 0)                                      // Decompress(dv, DecodeBytes(v))

        val sPrime = IntArray(K * N)
        polyVecDecode(K, 12, seckey, 0, sPrime, 0)                    // NTT-domain s'
        polyVecNtt(K, u, 0)

        val w = IntArray(N)                                           // w = s' · u, intt
        matrixMultiply(sPrime, 1, K, u, 1, w)
        intt(w, 0)
        polyVecSubFrom(1, w, 0, v, 0)                                 // v -= w

        polyCompress(1, v, 0)                                         // Compress(1, ·) -> message bits
        val msg = ByteArray(32)
        encode(1, v, 0, msg, 0)
        return msg
    }

    // ---- ML-KEM KeyGen (Alg 16) -> (pk[800], sk[1632]) ----
    public fun keygen(d: ByteArray, z: ByteArray): Pair<ByteArray, ByteArray> {
        val (pkPke, skPke) = kPkeKeygen(d)                            // K-PKE keypair
        val h = Keccak.sha3_256(pkPke)                                // H(pk)

        val pk = pkPke.copyOf()
        val sk = ByteArray(SECRET_KEY_LEN)                            // s'(768) || pk(800) || H(pk)(32) || z(32)
        var off = 0
        for (i in skPke.indices) sk[off + i] = skPke[i]; off += skPke.size
        for (i in pk.indices) sk[off + i] = pk[i]; off += pk.size
        for (i in h.indices) sk[off + i] = h[i]; off += h.size
        for (i in z.indices) sk[off + i] = z[i]
        return Pair(pk, sk)
    }

    // ---- ML-KEM Encapsulate_internal (Alg 17): (pk, m) -> (ss=K, ct) ----
    public fun encapsulate(pk: ByteArray, m: ByteArray): Pair<ByteArray, ByteArray> {
        val hPk = Keccak.sha3_256(pk)                                 // H(pk)
        val g = Keccak.sha3_512(m + hPk)                              // G(m || H(pk)) -> K || r
        val ss = copyBytes(g, 0, 32)                                  // K
        val r = copyBytes(g, 32, 32)                                  // r (32-byte encaps coin)
        val ct = kPkeEncrypt(pk, m, r)                                // c* = K-PKE.Encrypt(pk, m, r)
        return Pair(ss, ct)
    }

    // ---- ML-KEM Decapsulate_internal (Alg 18): (sk, ct) -> ss (implicit-rejection, CT) ----
    public fun decapsulate(sk: ByteArray, ct: ByteArray): ByteArray {
        val skOff0 = K * 12 * 32                                       // 768 : s'
        val skOff1 = skOff0 + PUBLIC_KEY_LEN                          // 1568: H(pk)
        val skOff2 = skOff1 + 32                                      // 1600: z

        val pkeSk = copyBytes(sk, 0, skOff0)                           // s'
        val pk = copyBytes(sk, skOff0, PUBLIC_KEY_LEN)                // pk (carried in sk)
        val h = copyBytes(sk, skOff1, 32)                             // H(pk)
        val z = copyBytes(sk, skOff2, 32)                             // z

        val m2 = kPkeDecrypt(pkeSk, ct)                               // m' = K-PKE.Decrypt(s', c)
        val g2 = Keccak.sha3_512(m2 + h)                              // G(m' || H(pk)) -> K' || r'
        val kp = copyBytes(g2, 0, 32)                                 // K'
        val rp = copyBytes(g2, 32, 32)                                // r'
        val cPrime = try { kPkeEncrypt(pk, m2, rp) } catch (_: IllegalArgumentException) { ByteArray(CIPHERTEXT_LEN) }

        val rk = Keccak.shake256(z + ct, 32)                          // J(z || c) (implicit-rejection tag)

        // constant-time select: ss = (ct == c') ? K' : rk
        val eq = bytesEqual(ct, 0, cPrime, 0, CIPHERTEXT_LEN)
        val ss = ByteArray(SHARED_SECRET_LEN)
        for (i in 0 until SHARED_SECRET_LEN) {
            val km = kp[i].toInt() and 0xFF
            val rm = rk[i].toInt() and 0xFF
            // (eq==1 -> km) | (eq==0 -> rm), branchless via the Int mask sel = -eq
            // (eq is 0 or 1, so sel is 0 or 0xFFFFFFFF as a two's-complement Int).
            val sel = -eq
            ss[i] = ((km and sel) or (rm and sel.inv())).toByte()
        }
        return ss
    }
}
