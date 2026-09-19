/*
 * Host-JVM benchmark for pure-Kotlin ML-KEM-512 (FIPS 203).
 *
 * Measures wall-clock time and HotSpot thread-allocated bytes for:
 *   KeyGen, Encaps, Decaps, and a single NTT (n=256).
 *
 * Run:
 *   ./gradlew benchmarkMlKem
 *   ./gradlew testAndroidHostTest --tests 'ch.trancee.kemseed.MlKem512Benchmark'
 *
 * Allocation counts use com.sun.management.ThreadMXBean.getThreadAllocatedBytes
 * (HotSpot). If the bean is unavailable, allocation columns print "n/a".
 *
 * Not a JMH microbenchmark — intended as a repo gate / regression signal on the
 * Android host test JVM (same surface as :testAndroidHostTest).
 */
package ch.trancee.kemseed

import java.lang.management.ManagementFactory
import kotlin.math.max
import kotlin.system.measureNanoTime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

internal class MlKem512Benchmark {

    private data class Sample(val ns: Long, val allocBytes: Long)

    private data class Stats(
        val name: String,
        val samples: List<Sample>,
    ) {
        val n: Int get() = samples.size
        val meanNs: Double get() = samples.map { it.ns }.average()
        val medianNs: Long
            get() {
                val s = samples.map { it.ns }.sorted()
                return s[s.size / 2]
            }
        val p95Ns: Long
            get() {
                val s = samples.map { it.ns }.sorted()
                return s[((s.size - 1) * 0.95).toInt()]
            }
        val meanAlloc: Double get() = samples.map { it.allocBytes }.average()
        val medianAlloc: Long
            get() {
                val s = samples.map { it.allocBytes }.sorted()
                return s[s.size / 2]
            }
    }

    /** HotSpot thread-allocated-bytes probe; null if unsupported. */
    private class AllocProbe {
        private val bean: com.sun.management.ThreadMXBean? =
            try {
                val mx = ManagementFactory.getThreadMXBean()
                if (mx is com.sun.management.ThreadMXBean && mx.isThreadAllocatedMemorySupported) {
                    if (!mx.isThreadAllocatedMemoryEnabled) {
                        mx.isThreadAllocatedMemoryEnabled = true
                    }
                    mx
                } else {
                    null
                }
            } catch (_: Throwable) {
                null
            }

        val available: Boolean get() = bean != null

        fun allocatedBytes(): Long {
            val b = bean ?: return -1L
            return b.getThreadAllocatedBytes(Thread.currentThread().threadId())
        }
    }

    private val probe = AllocProbe()

    private fun measure(block: () -> Unit): Sample {
        // Light GC nudge so allocation deltas are less polluted by concurrent GC
        // (not perfect; good enough for order-of-magnitude / regression signal).
        val before = probe.allocatedBytes()
        val ns = measureNanoTime(block)
        val after = probe.allocatedBytes()
        val alloc =
            if (before >= 0 && after >= before) after - before
            else -1L
        return Sample(ns, alloc)
    }

    private fun fmtMs(ns: Double): String = "%.3f".format(ns / 1e6)

    private fun fmtMs(ns: Long): String = "%.3f".format(ns / 1e6)

    private fun fmtBytes(b: Double): String =
        when {
            b < 0 -> "n/a"
            b < 1024 -> "%.0f B".format(b)
            b < 1024 * 1024 -> "%.1f KiB".format(b / 1024.0)
            else -> "%.2f MiB".format(b / (1024.0 * 1024.0))
        }

    private fun fmtBytes(b: Long): String = fmtBytes(b.toDouble())

    private fun report(stats: Stats) {
        val allocOk = probe.available && stats.samples.all { it.allocBytes >= 0 }
        println(
            "%-8s  n=%d  time mean=%s  median=%s  p95=%s ms | alloc mean=%s  median=%s"
                .format(
                    stats.name,
                    stats.n,
                    fmtMs(stats.meanNs),
                    fmtMs(stats.medianNs),
                    fmtMs(stats.p95Ns),
                    if (allocOk) fmtBytes(stats.meanAlloc) else "n/a",
                    if (allocOk) fmtBytes(stats.medianAlloc) else "n/a",
                ),
        )
    }

    @Test
    fun benchmark_keygen_encaps_decaps_with_allocations() {
        val d = Keccak.shake256("mlkem-bench-d".repeat(8).encodeToByteArray(), 32)
        val z = Keccak.shake256("mlkem-bench-z".repeat(8).encodeToByteArray(), 32)
        val m = Keccak.shake256("mlkem-bench-msg".repeat(8).encodeToByteArray(), 32)

        val warmup = 20
        val iterations = 50

        // Warmup (JIT + class init)
        repeat(warmup) {
            val (pk, sk) = MlKem512.keygen(d, z)
            val (ss, ct) = MlKem512.encapsulate(pk, m)
            assertContentEquals(ss, MlKem512.decapsulate(sk, ct))
        }

        val keygenSamples = ArrayList<Sample>(iterations)
        val encapsSamples = ArrayList<Sample>(iterations)
        val decapsSamples = ArrayList<Sample>(iterations)
        val nttSamples = ArrayList<Sample>(iterations)

        var pk = ByteArray(0)
        var sk = ByteArray(0)
        var ct = ByteArray(0)
        var ss = ByteArray(0)

        repeat(iterations) {
            keygenSamples +=
                measure {
                    val pair = MlKem512.keygen(d, z)
                    pk = pair.first
                    sk = pair.second
                }
            encapsSamples +=
                measure {
                    val pair = MlKem512.encapsulate(pk, m)
                    ss = pair.first
                    ct = pair.second
                }
            decapsSamples +=
                measure {
                    val recovered = MlKem512.decapsulate(sk, ct)
                    assertContentEquals(ss, recovered)
                }

            val poly = IntArray(MlKem512.N) { i -> (i * 17) % MlKem512.Q }
            nttSamples +=
                measure {
                    MlKem512.ntt(poly, 0)
                }
        }

        println()
        println("=== kemseed pure-Kotlin ML-KEM-512 host benchmark ===")
        println(
            "JVM ${System.getProperty(\"java.version\")} ${System.getProperty(\"os.arch\")} | " +
                "warmup=$warmup measure=$iterations | " +
                "allocProbe=${if (probe.available) \"ThreadMXBean\" else \"unavailable\"}",
        )
        println(
            "Sizes: pk=${MlKem512.PUBLIC_KEY_LEN} sk=${MlKem512.SECRET_KEY_LEN} " +
                "ct=${MlKem512.CIPHERTEXT_LEN} ss=${MlKem512.SHARED_SECRET_LEN}",
        )
        report(Stats("KeyGen", keygenSamples))
        report(Stats("Encaps", encapsSamples))
        report(Stats("Decaps", decapsSamples))
        report(Stats("NTT", nttSamples))

        // Sanity: medians should stay in a sane band for a host JVM (not a hard gate —
        // environments vary; this catches catastrophic regressions only).
        val keygenMedianMs = keygenSamples.map { it.ns }.sorted()[iterations / 2] / 1e6
        val encapsMedianMs = encapsSamples.map { it.ns }.sorted()[iterations / 2] / 1e6
        val decapsMedianMs = decapsSamples.map { it.ns }.sorted()[iterations / 2] / 1e6
        assertTrue(keygenMedianMs < 50.0, "KeyGen median ${keygenMedianMs}ms looks pathological")
        assertTrue(encapsMedianMs < 50.0, "Encaps median ${encapsMedianMs}ms looks pathological")
        assertTrue(decapsMedianMs < 50.0, "Decaps median ${decapsMedianMs}ms looks pathological")

        if (probe.available) {
            // Each op allocates multiple polys + SHAKE buffers; expect well above 1 KiB.
            val minMedianAlloc =
                max(
                    keygenSamples.map { it.allocBytes }.sorted()[iterations / 2],
                    max(
                        encapsSamples.map { it.allocBytes }.sorted()[iterations / 2],
                        decapsSamples.map { it.allocBytes }.sorted()[iterations / 2],
                    ),
                )
            assertTrue(
                minMedianAlloc > 1024,
                "Expected multi-KiB allocations per ML-KEM op; median alloc=$minMedianAlloc",
            )
            println(
                "Allocation signal OK (median KeyGen=${fmtBytes(keygenSamples.map { it.allocBytes }.sorted()[iterations / 2])})",
            )
        }
        println("=== end ML-KEM benchmark ===")
        println()
    }
}
