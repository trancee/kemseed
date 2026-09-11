import java.math.BigInteger
import java.security.SecureRandom

/**
 * Pure-Kotlin feasibility spike for #10.
 *
 * Kotlin/JVM only (java.math.BigInteger = JDK stdlib; no external deps, honoring ADR-0001).
 * Measures the F_p field-operation floor that dominates any CSIDH isogeny walk:
 *   FpMul, FpInv (modInverse), FpSqrt (a^((p+1)/4) mod p) — the sqrt is the per-isogeny
 *   exponentiation that #04 / ePrint 2023/793 report as the √-trick cost driver.
 *
 * We do NOT hand-roll a CSIDH isogeny walk here (correctness-critical crypto; crypto-expert
 * review #11/#13). Instead we measure the arithmetic floor + cite authoritative optimized-C
 * walk timings, projecting Pure-Kotlin feasibility against the ~200 ms BLE handshake budget.
 */

private val rng = SecureRandom()

fun primeP3mod4(bits: Int): BigInteger {
    var p = BigInteger.probablePrime(bits, rng)
    while (p.mod(BigInteger.valueOf(4L)) != BigInteger.valueOf(3L)) p = BigInteger.probablePrime(bits, rng)
    return p
}

fun bench(iters: Int, block: () -> Unit): Double {
    // warm up the C2 JIT, then time a plain loop (avoid lambda call-overhead skewing fast ops)
    var i = 0
    while (i < 800) { block(); i++ }
    val t0 = System.nanoTime()
    var j = 0
    while (j < iters) { block(); j++ }
    val ns = System.nanoTime() - t0
    return ns / 1000.0 / iters            // µs/op
}

fun main() {
    println("### isogeny / Pure-Kotlin CSIDH feasibility spike")
    println("kotlinc-jvm 2.4.10  |  JRE ${System.getProperty("java.version")}  |  ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
    println("stdlib only (java.math.BigInteger) — no external deps\n")
    for (bits in listOf(512, 1024)) {
        val p = primeP3mod4(bits)
        val a = BigInteger.valueOf(System.nanoTime()).mod(p).add(BigInteger.ONE)
        val sqrtExp = p.add(BigInteger.ONE).shiftRight(2)            // (p+1)/4  (p≡3 mod4)

        // FpMul — inlined loop (per-op ~µs, so lambda overhead would skew; measure raw)
        var sinkMul = BigInteger.ONE
        var k = 0
        while (k < 30_000) { sinkMul = sinkMul.multiply(a).mod(p); k++ }   // JIT warm
        var t0 = System.nanoTime(); var m = 0
        while (m < 100_000) { sinkMul = sinkMul.multiply(a).mod(p); m++ }
        val mulUs = (System.nanoTime() - t0) / 1000.0 / 100_000

        // FpSqrt — a^((p+1)/4) mod p  (the isogeny √-trick exponentiation; per-op ~100 µs, lambda OK)
        val sqrtIters = if (bits == 512) 200 else 40
        var sinkSqrt = a
        var s = 0
        while (s < sqrtIters * 2) { sinkSqrt = a.modPow(sqrtExp, p); s++ } // warm
        var t1 = System.nanoTime(); var q = 0
        while (q < sqrtIters) { sinkSqrt = a.modPow(sqrtExp, p); q++ }
        val sqrtUs = (System.nanoTime() - t1) / 1000.0 / sqrtIters

        // FpInv — modInverse (slow; iterate plenty to escape JIT ramp + GC noise)
        var sinkInv = a
        var r = 0
        while (r < 400) { sinkInv = a.modInverse(p); r++ }                  // warm
        var t2 = System.nanoTime(); var v = 0
        while (v < 400) { sinkInv = a.modInverse(p); v++ }
        val invUs = (System.nanoTime() - t2) / 1000.0 / 400

        // correctness smoke tests (stdlib semantics)
        check(sinkInv.multiply(a).mod(p) == BigInteger.ONE) { "FpInv smoke failed" }
        val sq = sinkSqrt.multiply(sinkSqrt).mod(p)
        check(sq == a || sq == p.subtract(a)) { "FpSqrt smoke failed" }   // QR or QNR both valid

        println("F_p-$bits  (p ≡ 3 mod 4):")
        println("    FpMul   = %.3f µs".format(mulUs))
        println("    FpSqrt  = %.3f µs   (a^((p+1)/4) mod p — isogeny √-trick)".format(sqrtUs))
        println("    FpInv   = %.3f µs   (modInverse)\n".format(invUs))
    }
    println("Caveat: BigInteger.modInverse / modPow are NOT constant-time (C2-compiled C with")
    println("secret-dependent control flow). A truly constant-time Pure-Kotlin impl would need a")
    println("hand-written fixed-width limb field (incl. a CT √), ~2–3x slower and crypto-expert")
    println("territory — see #11 (CT CSIDH exists, arxiv 2508.11082) and #13.")
}
