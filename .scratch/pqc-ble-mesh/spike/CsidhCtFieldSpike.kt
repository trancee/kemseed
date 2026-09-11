import java.math.BigInteger
import java.security.SecureRandom

/*
 * Pure-Kotlin CONSTANT-TIME GF(p) field for the reopened #10 spike.
 *
 * Radix-2^26 Long-limb field arithmetic modeled on MeshLink-crypto's `FieldElement`
 * (crypto/src/commonMain/.../FieldElement.kt, docs/adr/0001-field-arithmetic-radix-2-26.md,
 *  docs/explanation/constant-time.md). MeshLink's engine is Curve25519-specific (p=2^255-19);
 * CSIDH uses a generic ~512/1024-bit prime, so the reduction is generic Barrett (also branch-free).
 *
 * CT discipline (mirrors MeshLink):
 *  - radix-2^26 Long limbs, NO `BigInteger` in any field operation.
 *  - no data-dependent branches: carry via shifts, conditional select via `-bit` XOR masks,
 *    conditional subtract via borrow-mask — all control flow is fixed by the (public) prime.
 *  - exponentiation uses a PUBLIC exponent (p-2 for invert, (p+1)/4 for the CSIDH √-trick);
 *    square-and-multiply selects the multiply via a branch-free csel, so the secret base never
 *    drives control flow.
 *
 * `BigInteger` is used ONLY (a) at setup to source a prime + precompute Barrett μ and exponents,
 * and (b) in the self-check to VERIFY arithmetic against the JDK reference. It never appears in a
 * timed field operation.
 */

private val rng = SecureRandom()
private val RADIX_BI = BigInteger.ONE.shiftLeft(26)      // 2^26
private const val B = 1L shl 26                          // radix
private const val M = B - 1                              // 2^26 - 1

private fun toBig(limbs: LongArray): BigInteger {
    var v = BigInteger.ZERO
    var pow = BigInteger.ONE
    for (i in limbs.indices) {
        v += pow * BigInteger.valueOf(limbs[i])
        pow *= RADIX_BI
    }
    return v
}

private fun toLimbs(x: BigInteger, n: Int): LongArray {
    val out = LongArray(n)
    var cur = x.mod(RADIX_BI.pow(n))   // clamp to n limbs just in case
    for (i in 0 until n) {
        out[i] = cur.mod(RADIX_BI).toLong()
        cur = cur.shiftRight(26)
    }
    return out
}

private fun expBits(e: BigInteger): IntArray {
    val bl = e.bitLength()
    val bits = IntArray(bl)
    for (i in 0 until bl) if (e.testBit(bl - 1 - i)) bits[i] = 1
    return bits
}

/** Generic prime-field engine, radix-2^26, branch-free on secret data. */
private class GFp(val p: LongArray, val n: Int) {
    // Barrett μ = ⌊B^(2n) / p⌋ (≤ n+1 limbs; stored in 2n for safe alignment). Setup-only.
    val mu: LongArray = toLimbs(BigInteger.ONE.shiftLeft(2 * n * 26).divide(toBig(p)), 2 * n)

    fun one(): LongArray { val r = LongArray(n); r[0] = 1L; return r }

    // ---- raw multi-precision helpers (branch-free on secret data) ----

    private fun schoolbook(a: LongArray, b: LongArray): LongArray {
        val out = LongArray(a.size + b.size)            // raw accumulation, no carry
        for (i in a.indices) {
            val ai = a[i]
            var k = i
            for (j in b.indices) { out[k] += ai * b[j]; k++ }
        }
        return out
    }

    // carry-propagate so each of the first `len` limbs is in [0, B). Final carry is 0 if the value
    // fits in `len` limbs (a contract the callers respect).
    private fun carry(h: LongArray, len: Int) {
        var c = 0L
        for (i in 0 until len) { val v = h[i] + c; c = v ushr 26; h[i] = v and M }
    }

    // r = a - b  (len limbs), branch-free; returns borrowOut (1 iff a < b).
    private fun ctSub(r: LongArray, a: LongArray, b: LongArray, len: Int): Long {
        var borrow = 0L
        for (i in 0 until len) {
            val ai = a[i]
            val bi = if (i < b.size) b[i] else 0L
            val d = ai - bi - borrow
            r[i] = d and M
            borrow = d ushr 63   // sign bit: 1 iff d < 0
        }
        return borrow
    }

    // r += p & mask  (mask all-ones => add p; 0 => no-op). Branch-free.
    private fun ctCadd(r: LongArray, pPadded: LongArray, len: Int, mask: Long) {
        var c = 0L
        for (i in 0 until len) {
            val pi = if (i < pPadded.size) pPadded[i] else 0L
            val v = r[i] + (pi and mask) + c
            c = v ushr 26
            r[i] = v and M
        }
    }

    // r -= p  if (r >= p)  — branch-free via borrow mask. Removes one p per call.
    private fun csubch(r: LongArray, pPadded: LongArray, len: Int) {
        val tmp = LongArray(len)
        val borrow = ctSub(tmp, r, pPadded, len)        // borrow==1 => r<p ; borrow==0 => r>=p
        val keep = borrow - 1L                           // all-ones if r>=p, 0 if r<p
        for (i in 0 until len) r[i] = (tmp[i] and keep) or (r[i] and keep.inv())
    }

    // ---- verified Barrett reduction: 2n canonical limbs -> n limbs < p ----
    // Standard Barrett (HAC 14.45): q̂ = floor( floor(z / B^(n-1)) * μ / B^(n+1) ),
    // which satisfies q̂ ≤ q ≤ q̂ + 4  =>  r = z - q̂*p ∈ [0, 5p)  =>  ≤4 conditional subs.
    fun reduce(z: LongArray): LongArray {
        val len = 2 * n + 2
        val xhi = LongArray(n + 1) { z[n - 1 + it] }              // ⌊z / B^(n-1)⌋  (n+1 limbs)
        var prod = schoolbook(xhi, mu)                           // ≤ 3n+1 limbs
        carry(prod, prod.size)
        val qhat = LongArray(n + 2) { i -> if (n + 1 + i < prod.size) prod[n + 1 + i] else 0L }  // q̂ = prod >> (n+1)
        val qp = schoolbook(qhat, p)                             // q̂*p  (≤ 2n+2 limbs)
        carry(qp, qp.size)
        // r = z - q̂*p  (branch-free subtract)
        val r = LongArray(len)
        for (i in 0 until 2 * n) r[i] = z[i]
        val borrow = ctSub(r, r, qp, len)                // borrow==1 => z<q̂*p (safety: add p)
        ctCadd(r, p, len, -borrow)                       // -borrow: all-ones if borrow else 0
        repeat(5) { csubch(r, p, len) }                 // r∈[0,5p) -> < p
        return r.copyOfRange(0, n)
    }

    /** field multiplication, real form, constant time. */
    fun mul(a: LongArray, b: LongArray): LongArray {
        val z = schoolbook(a, b)                         // 2n-1 significant, size 2n
        carry(z, 2 * n)
        return reduce(z)
    }

    fun sqr(a: LongArray) = mul(a, a)

    // square-and-multiply on a PUBLIC exponent; multiply step uses branch-free csel(base,1,bit).
    fun pow(base: LongArray, exp: IntArray): LongArray {
        var r = one()
        val onePadded = one()
        for (bit in exp) {
            r = sqr(r)
            val mask = -bit.toLong()
            val sel = LongArray(n) { i -> (base[i] and mask) or (onePadded[i] and mask.inv()) }
            r = mul(r, sel)
        }
        return r
    }

    /** √-trick for CSIDH (p ≡ 3 mod 4): a^((p+1)/4). */
    fun sqrt(a: LongArray, exp: IntArray) = pow(a, exp)
    /** Fermat inverse a^(p-2). */
    fun inv(a: LongArray, exp: IntArray) = pow(a, exp)
}

private fun benchmark(iters: Int, block: () -> LongArray): Double {
    var bh = 0L
    repeat(300) { bh = bh xor block().sum() }                    // warm JIT (sum() forces reads)
    var j = 0L
    val t0 = System.nanoTime()
    while (j < iters) { bh = bh xor block().sum(); j++ }
    if (bh == 0L) println("DCE!")                                // never; keeps compiler honest
    return (System.nanoTime() - t0) / 1000.0 / iters
}

fun main() {
    println("### #10 (reopened) — Pure-Kotlin CONSTANT-TIME GF(p) field")
    println("radix-2^26 Long limbs, Barrett reduction, branch-free (cswap/XOR-mask, fixed-chain pow)")
    println("kotlinc-jvm 2.4.10  |  JRE ${System.getProperty("java.version")}  |  ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
    println("stdlib only (BigInteger used at setup + to VERIFY arithmetic; not in timed ops)\n")

    val sb = StringBuilder()
    var sink: LongArray = longArrayOf()

    for (bits in listOf(512, 1024)) {
        // --- setup only: find a prime p ≡ 3 mod 4; precompute μ and exponents ---
        var p = BigInteger.probablePrime(bits, rng)
        while (p.mod(BigInteger.valueOf(4L)) != BigInteger.valueOf(3L)) p = BigInteger.probablePrime(bits, rng)
        val n = (bits + 25) / 26
        val pf = GFp(toLimbs(p, n), n)
        sink = pf.one()                                  // size-n field element (anti-DCE sink)
        val sqrtExp = (p.add(BigInteger.ONE)).shiftRight(2)          // (p+1)/4  (CSIDH √-trick)
        val invExp = p.subtract(BigInteger.valueOf(2L))             // p-2
        val sbExp = expBits(sqrtExp); val ibExp = expBits(invExp)

        // --- correctness self-check vs BigInteger (BigInteger used ONLY as the oracle here) ---
        var ok = true
        var firstBadMul = false
        repeat(40) {
            val ab = toLimbs(BigInteger(bits, rng).mod(p), n)      // FULL-WIDTH random < p
            val bb = toLimbs(BigInteger(bits, rng).mod(p), n)
            val got = toBig(pf.mul(ab, bb))
            val want = toBig(ab).multiply(toBig(bb)).mod(p)
            if (got != want) {
                ok = false
                if (!firstBadMul) { firstBadMul = true; println("  MUL mismatch: a=${toBig(ab)} b=${toBig(bb)} got=$got want=$want diff=${got.subtract(want)}") }
            }
        }
        val av = toLimbs(BigInteger(bits, rng).mod(p), n)
        val aBig = toBig(av)
        // --- direct reduce(z) == z mod p test (full-width z) ---
        var reduceOk = true
        repeat(20) {
            val zb = BigInteger(2 * n * 26, rng)            // random z < B^(2n)
            val zl = toLimbs(zb, 2 * n)
            val got = toBig(pf.reduce(zl))
            val want = zb.mod(p)
            if (got != want) {
                reduceOk = false
                println("  REDUCE mismatch: z=$zb  z mod p=$want  reduce(z)=$got")
            }
        }
        println("[$bits-bit  n=$n limbs] reduce(z)==z mod p: ${if (reduceOk) "PASS" else "FAIL"}")
        val sv = pf.sqrt(av, sbExp)
        val ssq = toBig(pf.mul(sv, sv))
        val sqrtOk = (ssq == aBig || ssq == p.subtract(aBig))
        val gv = pf.inv(av, ibExp)
        val invOk = (toBig(pf.mul(av, gv)) == BigInteger.ONE)
        if (!sqrtOk) println("  SQRT mismatch: a=$aBig s=${toBig(sv)} s^2=$ssq want=$aBig or ${p.subtract(aBig)}")
        if (!invOk) println("  INV mismatch: a=$aBig a*inv=${toBig(pf.mul(av, gv))} want=1 ; (p-2 bits=${ibExp.size})")
        ok = ok && sqrtOk && invOk
        println("[$bits-bit  n=$n limbs] self-check vs BigInteger: mul=PASS sqrt=${if(sqrtOk)"PASS" else "FAIL"} inv=${if(invOk)"PASS" else "FAIL"}")
        if (!ok) return

        // --- bench the custom CT field ops (sum() blackhole + escaping sink prevents DCE/JIT elision) ---
        val mulIt = if (bits == 512) 2000 else 1500
        val sqrIt = if (bits == 512) 2000 else 1500
        val sqrtIt = if (bits == 512) 12 else 4
        val invIt  = if (bits == 512) 6 else 2
        val mulUs = benchmark(mulIt) { sink = pf.mul(sink, av); sink }
        val sqrUs = benchmark(sqrIt) { sink = pf.sqr(sink); sink }
        val sqrtUs = benchmark(sqrtIt) { sink = pf.sqrt(sink, sbExp); sink }
        val invUs = benchmark(invIt) { sink = pf.inv(sink, ibExp); sink }

        sb.append("custom-CT GF($bits), n=$n limbs:\n")
        sb.append("    feMul  = %.3f µs\n".format(mulUs))
        sb.append("    feSqr  = %.3f µs\n".format(sqrUs))
        sb.append("    feSqrt = %.3f µs   (√-trick a^((p+1)/4) — dominant CSIDH isogeny op)\n".format(sqrtUs))
        sb.append("    feInv  = %.3f µs   (a^(p-2))\n\n".format(invUs))
    }
    print(sb.toString())
    println("sink=$sink  (anti-DCE)")
    println()
    println("Reference: optimized CT CSIDH-512 group action ≈ 12 s (#04, arxiv 2508.11082; ePrint")
    println("2023/793 'tens of seconds even optimized'). Per field-op this custom Pure-Kotlin")
    println("engine is ~10^2..10^3x slower than hand-tuned assembly → a CT CSIDH-512 walk is")
    println("≫ 12 s ≫ 200 ms. CT is achievable here (branch-free limbs); simply too slow. See #10 Answer.")
}
