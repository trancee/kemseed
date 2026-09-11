/*
 * X25519 (RFC 7748) — Pure-Kotlin, constant-time, KMP (commonMain: android + iosArm64).
 *
 * Field arithmetic reuses the #10 CSIDH spike's verified radix-2^26 GF(p) engine
 * (carry / schoolbook / ctSub / ctCadd / csubch / Barrett reduce / mul / sqr / pow),
 * proven bit-exact vs BigInteger. Specialised here to p = 2^255 - 19 (Curve25519
 * base field):
 *   p  limbs (10 × 2^26, LE):        [67108845, 67108863×8, 2097151]
 *   Barrett μ = floor(2^520 / p):    [19456, 0×9, 32, 0×9]  (verified: μ·p ≤ 2^520 < (μ+1)·p)
 *   invert exp e = p - 2 = 2^255 - 21 (255 bits; derived from 4 × 64-bit limbs of
 *     2^255 - 21 = [2^64-21, 2^64-1, 2^64-1, 2^63-1], NO BigInteger).
 *
 * Montgomery ladder follows the Don Davis reference (golang/crypto v0.3.0
 * curve25519.go scalarMult); its field ops are mapped onto the spike engine above.
 *
 * CT (ADR-0002 §4): no data-dependent branch on the secret scalar or ephemeral key.
 * cswap/csel use arithmetic masks (-1/0); loop counts are public. All-zero `ss`
 * (low-order input) is returned as 0^32 and the *protocol* layer CT-aborts before
 * any ML-KEM work (#08 §3 / #11). No java.* imports (iosArm64 safe).
 */
package ch.trancee.kemseed

internal object X25519 {

    private const val N: Int = 10           // 10 limbs × 26 bits = 260 (>= 255)
    private const val B: Long = 1L shl 26   // radix 2^26
    private const val M: Long = B - 1L      // 2^26 - 1

    // p = 2^255 - 19, little-endian radix-2^26 limbs.
    private val P: LongArray = longArrayOf(
        67108845L, 67108863L, 67108863L, 67108863L, 67108863L,
        67108863L, 67108863L, 67108863L, 67108863L, 2097151L,
    )
    // Barrett μ = floor(2^(2N) / p), 2N = 20 limbs.
    private val MU: LongArray = longArrayOf(
        19456L, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        32L, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    // e = p - 2 = 2^255 - 21, as 4 × 64-bit little-endian limbs (no BigInteger).
    private val P_MINUS_TWO: LongArray = longArrayOf(
        -21L,                  // 2^64 - 21
        -1L,                   // 2^64 - 1
        -1L,                   // 2^64 - 1
        0x7FFFFFFFFFFFFFFFL,   // 2^63 - 1
    )
    // e MSB-first bits (255 bits) — branch-free square-and-multiply; exp is public.
    private val INV_EXP: IntArray = run {
        val bits = IntArray(255)
        var bi = 0
        for (li in 3 downTo 0) {
            val w = P_MINUS_TWO[li]
            for (bit in 63 downTo 0) {
                if (li * 64 + bit < 255) {
                    bits[bi++] = if ((w ushr bit) and 1L == 1L) 1 else 0
                }
            }
        }
        // sanity: leading bit must be 1 (2^255-21 has bit-length 255)
        check(bits[0] == 1) { "inversion exponent MSB must be set" }
        check(bits.count { it == 1 } == 253) { "popcount(2^255-21) must be 253" }
        bits
    }

    // ----- branch-free field ops (reused from #10 spike; proven bit-exact) -----
    private fun carry(h: LongArray, len: Int) {
        var c = 0L
        for (i in 0 until len) { val v = h[i] + c; c = v ushr 26; h[i] = v and M }
    }
    private fun schoolbook(a: LongArray, b: LongArray): LongArray {
        val out = LongArray(a.size + b.size)
        for (i in a.indices) { val ai = a[i]; var k = i; for (j in b.indices) { out[k] += ai * b[j]; k++ } }
        return out
    }
    // r = a - b over `len` limbs (a,b padded 0 past size); returns borrow (0/1). CT.
    private fun ctSub(r: LongArray, a: LongArray, b: LongArray, len: Int): Long {
        var borrow = 0L
        for (i in 0 until len) {
            val ai = if (i < a.size) a[i] else 0L
            val bi = if (i < b.size) b[i] else 0L
            val d = ai - bi - borrow
            r[i] = d and M
            borrow = d ushr 63
        }
        return borrow
    }
    // r += (p ∧ mask) with carry; mask = 0 or -1. CT.
    private fun ctCadd(r: LongArray, pPadded: LongArray, len: Int, mask: Long) {
        var c = 0L
        for (i in 0 until len) {
            val pi = if (i < pPadded.size) pPadded[i] else 0L
            val v = r[i] + (pi and mask) + c
            c = v ushr 26
            r[i] = v and M
        }
    }
    // r = r mod p (conditional subtract on a len-limb buffer; value < 2p => 1 pass). CT.
    private fun csubch(r: LongArray, len: Int) {
        val tmp = LongArray(len)
        val borrow = ctSub(tmp, r, P, len)
        val keep = borrow - 1L                 // -1 (all ones) if r >= p, else 0
        for (i in 0 until len) r[i] = (tmp[i] and keep) or (r[i] and keep.inv())
    }
    // Barrett reduce of a 2N-limb product z -> N limbs, canonical (< p). CT.
    private fun reduce(z: LongArray): LongArray {
        val len = 2 * N + 2
        val xhi = LongArray(N + 1) { z[N - 1 + it] }
        val prod = schoolbook(xhi, MU)
        carry(prod, prod.size)
        val qhat = LongArray(N + 1) { idx -> val j = N + 1 + idx; if (j < prod.size) prod[j] else 0L }
        val qp = schoolbook(qhat, P)
        carry(qp, qp.size)
        val r = LongArray(len)
        for (i in 0 until 2 * N) r[i] = z[i]
        val borrow = ctSub(r, r, qp, len)
        ctCadd(r, P, len, -borrow)
        repeat(5) { csubch(r, len) }
        return r.copyOfRange(0, N)
    }

    fun mul(a: LongArray, b: LongArray): LongArray { val z = schoolbook(a, b); carry(z, 2 * N); return reduce(z) }
    fun sqr(a: LongArray): LongArray = mul(a, a)
    fun one(): LongArray { val r = LongArray(N); r[0] = 1L; return r }
    fun zero(): LongArray = LongArray(N)
    // r = a + b (a,b < p => a+b < 2^256 < 2^260, no carry lost). CT.
    fun add(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(N) { a[it] + b[it] }; carry(r, N); return r
    }
    // r = a - b (canonical, < p). CT.
    fun sub(a: LongArray, b: LongArray): LongArray {
        val len = N + 1
        val r = LongArray(len) { if (it < a.size) a[it] else 0L }
        val borrow = ctSub(r, r, b, len)
        ctCadd(r, P, len, -borrow)
        repeat(2) { csubch(r, len) }
        return r.copyOfRange(0, N)
    }
    // CT conditional swap (mask = 0 or -1).
    fun cswap(a: LongArray, b: LongArray, mask: Long) {
        for (i in 0 until N) { val t = mask and (a[i] xor b[i]); a[i] = a[i] xor t; b[i] = b[i] xor t }
    }
    // r = a * k  (k small; e.g. 121666 = (A+2)/4 for A=486662). CT.
    fun mulSmall(a: LongArray, k: Long): LongArray {
        val z = LongArray(2 * N) { if (it < N) a[it] * k else 0L }; carry(z, 2 * N); return reduce(z)
    }
    // branch-free select: mask==-1 -> b, mask==0 -> a.
    private fun csel(a: LongArray, b: LongArray, mask: Long): LongArray {
        val r = LongArray(N)
        for (i in 0 until N) r[i] = (b[i] and mask) or (a[i] and mask.inv())
        return r
    }
    fun inv(a: LongArray): LongArray = pow(a, INV_EXP)
    private fun pow(base: LongArray, exp: IntArray): LongArray {
        var r = one()
        val unit = one()
        for (bit in exp) { r = sqr(r); r = mul(r, csel(unit, base, -bit.toLong())) }
        return r
    }

    // ---- byte packing (radix-2^26 <-> 32-byte LE, bit 255 cleared) ----
    private fun fromBytes(s: ByteArray): LongArray {
        val r = LongArray(N)
        var acc = 0L; var nbits = 0; var si = 0
        for (bi in 0 until N) {
            while (nbits < 26 && si < s.size) { acc = acc or ((s[si].toLong() and 0xffL) shl nbits); nbits += 8; si++ }
            r[bi] = acc and M
            acc = acc ushr 26
            nbits -= 26
        }
        return r
    }
    private fun toBytes(r: LongArray): ByteArray {
        val len = 2 * N + 2
        val scratch = LongArray(len) { if (it < N) r[if (it < r.size) it else 0] else 0L }
        carry(scratch, len)
        repeat(5) { csubch(scratch, len) }
        val out = ByteArray(32)
        var acc = 0L; var nbits = 0; var bi = 0
        for (i in 0 until N) {
            acc = acc or (scratch[i] shl nbits)
            nbits += 26
            while (nbits >= 8 && bi < 32) { out[bi++] = (acc and 0xffL).toByte(); acc = acc ushr 8; nbits -= 8 }
        }
        while (bi < 32) { out[bi++] = (acc and 0xffL).toByte(); acc = acc ushr 8 }
        out[31] = (out[31].toInt() and 0x7f).toByte()  // u-coordinate < 2^255
        return out
    }

    // RFC 7748 §5.2 X25519. Returns the 32-byte shared secret; for low-order inputs
    // (all-zero point) returns 0^32 — the protocol CT-aborts `ss` before ML-KEM (#08 §3/#11).
    fun scalarMult(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
        require(publicKey.size == 32) { "X25519 public key must be 32 bytes" }
        val e = privateKey.copyOf()
        e[0] = (e[0].toInt() and 248).toByte()   // clamp: clear low 3 bits
        e[31] = (e[31].toInt() and 127).toByte() // clear high bit
        e[31] = (e[31].toInt() or 64).toByte()   // set bit 254
        val x1 = fromBytes(publicKey)           // u (base point or peer public)
        var x2 = one()
        var z2 = zero()
        var x3 = x1.copyOf()                    // independent of x1 (cswap mutates in place)
        var z3 = one()
        var swap = 0
        for (pos in 254 downTo 0) {
            val bit = (e[pos ushr 3].toInt() ushr (pos and 7)) and 1
            swap = swap xor bit
            val m = (-swap).toLong()            // 0 or -1 (all ones) — CT mask
            cswap(x2, x3, m); cswap(z2, z3, m)
            swap = bit
            // Montgomery ladder step (Don Davis ref; field ops -> spike engine).
            // NOTE: receivers are reassigned in order exactly like the C/Go reference;
            // the field ops above return fresh arrays (no input mutation), so var
            // rebinding is a faithful in-place translation.
            var tmp0 = sub(x3, z3)              // tmp0 = x3 - z3
            var tmp1 = sub(x2, z2)              // tmp1 = x2 - z2
            x2 = add(x2, z2)                    // x2 = x2 + z2
            z2 = add(x3, z3)                    // z2 = x3 + z3
            z3 = mul(tmp0, x2)                  // z3 = (x3-z3)(x2+z2)
            z2 = mul(z2, tmp1)                  // z2 = (x3+z3)(x2-z2)
            tmp0 = sqr(tmp1)                    // tmp0 = (x2-z2)^2
            tmp1 = sqr(x2)                      // tmp1 = (x2+z2)^2
            x3 = add(z3, z2)                    // x3 = z3 + z2
            z2 = sub(z3, z2)                    // z2 = z3 - z2
            x2 = mul(tmp1, tmp0)                // x2 = (x2+z2)^2 (x2-z2)^2
            tmp1 = sub(tmp1, tmp0)              // tmp1 = (x2+z2)^2 - (x2-z2)^2
            z2 = sqr(z2)                        // z2 = (z3-z2)^2
            z3 = mulSmall(tmp1, 121666L)        // z3 = 121666 * tmp1  (121666 = (A+2)/4, A=486662)
            x3 = sqr(x3)                        // x3 = (z3+z2)^2
            tmp0 = add(tmp0, z3)                // tmp0 = (x2-z2)^2 + 121666*tmp1
            z3 = mul(x1, z2)                    // z3 = x1 * (z3-z2)^2
            z2 = mul(tmp1, tmp0)                // z2 = tmp1 * tmp0
        }
        val fm = (-swap).toLong()             // final CT swap
        cswap(x2, x3, fm); cswap(z2, z3, fm)
        val ss = mul(x2, inv(z2))
        return toBytes(ss)
    }
}
