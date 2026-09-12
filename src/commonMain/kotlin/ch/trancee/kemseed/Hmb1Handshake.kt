/*
 * HMB1-E1' handshake orchestrator — derivation + GMAC frame verify layer.
 *
 * Pure-Kotlin, KMP commonMain (no java.*). Wires the committed 0c primitives
 * (X25519, Keccak, Hkdf, Gmac, MlKem512) per ADR-0002 §3/§O3 + #08 §3/§6:
 *
 *   epk  = X25519.scalarMult(ephPriv, BASE9 = u=9)        // scalar clamped inside
 *   K_gmac = HKDF-Extract("hmb1-gmac-v1", NetKey)         // signer key (#06/#15)
 *   wire = version ‖ nonce ‖ senderId ‖ flags ‖ epk ‖ GMAC(16)             (60 B)
 *   IV   = 0x11 ‖ dir ‖ nonce ‖ 0x00 0x00                                   (12 B)
 *   AAD_A1 = version ‖ flags ‖ nonce ‖ senderId ‖ epk                       (44 B)
 *   AAD_A2 = version ‖ flags ‖ nonce_r ‖ senderId_r ‖ epk_r ‖ AAD_A1        (transcript-bound)
 *   GMAC verified BEFORE X25519/ML-KEM (DoS gate, #15).
 *   ss      = X25519.scalarMult(ephPriv_local, epk_remote)  // CT-abort if all-zero
 *   T       = SHA3-256("HMB1-TR" ‖ wire_A1 ‖ wire_A2)
 *   K_seed  = HKDF-Extract(salt=T, IKM=ss ‖ NetKey)
 *   (d,z)   = SHAKE-256("HMB1-DZ" ‖ T ‖ K_seed, 64)
 *   (pk,sk) = ML-KEM-512.keygen(d, z)                         // local only, never on air
 *   m       = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)           // bound coin
 *   (K_df,c*) = Hmb1Handshake.selfEncapKdf(pk, m)            // #13 sole Encaps gate; c* never on air
 *   key_AB  = HKDF-Expand(K_df, "HMB1-K-AB" ‖ sid_i ‖ sid_r, 32)
 *   key_BA  = HKDF-Expand(K_df, "HMB1-K-BA" ‖ sid_i ‖ sid_r, 32)
 *
 * E2E self-consistency + Decaps(sk,c*)==K_df are asserted in Hmb1HandshakeTest;
 * the upstream chain (epk/IV/AAD/GMAC/T/ss/K_seed/d/z/m) is pinned to an
 * independent Python (cryptography + hashlib) oracle — see test header.
 */
package ch.trancee.kemseed

import kotlin.time.TimeMark
import kotlin.time.TimeSource

internal object Hmb1Handshake {

    internal const val VERSION: Int = 1
    internal const val FRAME_SIZE: Int = 60
    internal const val NONCE_SIZE: Int = 8
    internal const val SENDER_ID_SIZE: Int = 2
    internal const val EPK_SIZE: Int = 32
    internal const val CACHE_CAPACITY: Int = 1024      // 2^10 (#15 DoS policy)
    internal const val CACHE_TTL_MS: Long = 30_000L    // #15 freshness window

    /** Direction byte carried on the wire (GCM IV) and in the #15 cache key. */
    enum class Direction(val wire: Int) {
        INIT(0xA0),   // initiator → responder, #08 Packet_A1
        RESP(0xA1),   // responder → initiator, #08 Packet_A2
    }

    internal val DIR_INIT: Direction = Direction.INIT
    internal val DIR_RESP: Direction = Direction.RESP

    internal val GMAC_LABEL: ByteArray = "hmb1-gmac-v1".encodeToByteArray()
    internal val TR_LABEL: ByteArray = "HMB1-TR".encodeToByteArray()
    internal val DZ_LABEL: ByteArray = "HMB1-DZ".encodeToByteArray()
    internal val EM_LABEL: ByteArray = "HMB1-EM".encodeToByteArray()
    internal val KAB_LABEL: ByteArray = "HMB1-K-AB".encodeToByteArray()
    internal val KBA_LABEL: ByteArray = "HMB1-K-BA".encodeToByteArray()

    /** X25519 base point u=9 (RFC 7748), little-endian 32 bytes. */
    internal val BASE9: ByteArray = ByteArray(32).apply { this[0] = 9 }

    /** Monotonic clock for #15 TTL deltas (immune to wall-clock skew; available in common). */
    private val monotonicBase: TimeMark = TimeSource.Monotonic.markNow()
    private val monotonicNow: Long get() = monotonicBase.elapsedNow().inWholeMilliseconds

    /** Parsed 60-byte air frame (version ‖ nonce ‖ senderId ‖ flags ‖ epk ‖ mac). */
    internal class WireFrame internal constructor(private val wire: ByteArray) {
        init { check(wire.size == FRAME_SIZE) { "frame must be $FRAME_SIZE bytes" } }
        val version: Int get() = wire[0].toInt() and 0xff
        val nonce: ByteArray get() = wire.copyOfRange(1, NONCE_SIZE + 1)
        val senderId: ByteArray get() = wire.copyOfRange(NONCE_SIZE + 1, NONCE_SIZE + 1 + SENDER_ID_SIZE)
        val flags: Int get() = wire[NONCE_SIZE + 1 + SENDER_ID_SIZE].toInt() and 0xff
        val epk: ByteArray get() = wire.copyOfRange(12, 12 + EPK_SIZE)
        val mac: ByteArray get() = wire.copyOfRange(12 + EPK_SIZE, FRAME_SIZE)
        val aad: ByteArray get() = aadOf(version, flags, nonce, senderId, epk)
        companion object { fun parse(wire: ByteArray): WireFrame = WireFrame(wire) }
    }

    class Derived(
        val ss: ByteArray, val T: ByteArray, val kSeed: ByteArray,
        val d: ByteArray, val z: ByteArray, val pk: ByteArray, val sk: ByteArray,
        val m: ByteArray, val kDf: ByteArray, private val cStar: ByteArray,
        val keyAB: ByteArray, val keyBA: ByteArray,
    ) {
        /** #13 test-only self-check: `Decaps_internal(sk, c*) == K_df` (ADR-0002 §3). */
        fun decapsSelfCheck(): Boolean = ctEquals(MlKem512.decapsulate(sk, cStar), kDf)
    }

    /** Why a frame/derivation was rejected (before any ML-KEM work on ss==0 / GMAC fail). */
    enum class Reject { REPLAY, GMAC_FAIL, BAD_FORMAT, SS_ZERO }

    sealed interface DeriveResult {
        data class Ok(val derived: Derived) : DeriveResult
        data class Err(val reason: Reject) : DeriveResult
    }

    /** #15 freshness cache keyed by `dir ‖ nonce`: 2^10 entries, 30 s TTL, LRU eviction. */
    class ReplayCache(
        private val capacity: Int = CACHE_CAPACITY,
        private val ttlMs: Long = CACHE_TTL_MS,
        private val clock: () -> Long = { monotonicNow },
    ) {
        fun recordOrReject(dir: Direction, nonce: ByteArray): Reject? {
            val now = clock()
            val key = BytesKey(byteArrayOf(dir.wire.toByte()) + nonce)
            // purge expired (#15 30 s TTL) — monotonic clock immune to wall skew
            val it = entries.entries.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (e.value < now) it.remove()
            }
            // duplicate within TTL => replay, short-circuit before any crypto (#08 §4)
            if (key in entries) return Reject.REPLAY
            // cap exceeded => evict oldest surviving entry (LRU)
            while (entries.size >= capacity) entries.remove(entries.keys.first())
            entries[key] = now + ttlMs
            return null
        }

        /** Content-aware key for the LRU map (ByteArray equals by reference by default). */
        private class BytesKey(val b: ByteArray) {
            override fun equals(other: Any?): Boolean = other is BytesKey && other.b.contentEquals(b)
            override fun hashCode(): Int = b.contentHashCode()
        }

        /** Insertion-ordered (LinkedHashMap) => `keys.first()` is the least-recently inserted live entry. */
        private val entries: MutableMap<BytesKey, Long> = linkedMapOf()
    }

    // ---- AAD / IV construction ----
    private fun aadOf(version: Int, flags: Int, nonce: ByteArray, senderId: ByteArray, epk: ByteArray): ByteArray =
        byteArrayOf(version.toByte(), flags.toByte()) + nonce + senderId + epk

    /** GCM IV = 0x11 ‖ dir ‖ nonce ‖ 0x00 0x00 (12 B) — #08 §2.1/§2.2, ADR-0002 §3. */
    fun iv(dir: Direction, nonce: ByteArray): ByteArray =
        byteArrayOf(0x11, dir.wire.toByte()) + nonce + byteArrayOf(0x00, 0x00)

    /** Build a 60 B air frame; for A2 pass the verified A1 wire to transcript-bind its AAD. */
    fun buildFrame(
        dir: Direction, version: Int, nonce: ByteArray, senderId: ByteArray, flags: Int,
        epk: ByteArray, kGmac: ByteArray, a1Wire: ByteArray? = null,
    ): ByteArray {
        val aad = if (a1Wire != null) aadOf(version, flags, nonce, senderId, epk) + WireFrame.parse(a1Wire).aad
        else aadOf(version, flags, nonce, senderId, epk)
        val mac = Gmac.gmacTag(kGmac, iv(dir, nonce), aad)
        return byteArrayOf(version.toByte()) + nonce + senderId + byteArrayOf(flags.toByte()) + epk + mac
    }

    /** Verify a wire frame: format → version → nonce cache (replay) → IV dir-byte + GMAC. null = OK. */
    fun verifyFrame(
        wire: ByteArray, dir: Direction, kGmac: ByteArray, cache: ReplayCache, a1Wire: ByteArray? = null,
    ): Reject? {
        if (wire.size != FRAME_SIZE) return Reject.BAD_FORMAT
        if (wire[0].toInt() and 0xff != VERSION) return Reject.BAD_FORMAT   // §4 DoS step 1 (before any crypto)
        val wf = WireFrame.parse(wire)
        cache.recordOrReject(dir, wf.nonce)?.let { return it }         // REPLAY (DoS gate, #15)
        val aad = if (a1Wire != null) wf.aad + WireFrame.parse(a1Wire).aad else wf.aad
        val expected = Gmac.gmacTag(kGmac, iv(dir, wf.nonce), aad)
        return if (ctEquals(expected, wf.mac)) null else Reject.GMAC_FAIL
    }

    fun gmacKey(netKey: ByteArray): ByteArray = Hkdf.extract(GMAC_LABEL, netKey)

    fun transcriptHash(a1: ByteArray, a2: ByteArray): ByteArray =
        Keccak.sha3_256(TR_LABEL + a1 + a2)

    fun kSeed(ss: ByteArray, netKey: ByteArray, a1: ByteArray, a2: ByteArray): ByteArray {
        val t = transcriptHash(a1, a2)
        return Hkdf.extract(t, ss + netKey)                           // salt=T, IKM=ss‖NetKey
    }

    /** (d, z, m) from T ‖ K_seed: d,z = SHAKE-256("HMB1-DZ"‖T‖K_seed,64); m = SHAKE-256("HMB1-EM"‖T‖K_seed,32). */
    fun derivedSecrets(a1: ByteArray, a2: ByteArray, kSeed: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val t = transcriptHash(a1, a2)
        val dz = Keccak.shake256(DZ_LABEL + t + kSeed, 64)
        val m = Keccak.shake256(EM_LABEL + t + kSeed, 32)
        return Triple(dz.copyOfRange(0, 32), dz.copyOfRange(32, 64), m)
    }

    /** #13 sole call-site gate into Deterministic Encaps (c* handed to decapsSelfCheck only). */
    fun selfEncapKdf(pk: ByteArray, m: ByteArray): Pair<ByteArray, ByteArray> =
        MlKem512.encapsulate(pk, m)

    /** Full E1' derivation for one peer; CT-aborts (SS_ZERO) before ML-KEM on all-zero ss. */
    fun deriveKeys(
        ephPrivLocal: ByteArray, epkRemote: ByteArray, netKey: ByteArray,
        a1: ByteArray, a2: ByteArray, sidI: ByteArray, sidR: ByteArray,
    ): DeriveResult {
        val ss = X25519.scalarMult(ephPrivLocal, epkRemote)
        if (ctAllZero(ss)) return DeriveResult.Err(Reject.SS_ZERO)    // PFS gate (#08 §3/#11)
        val ks = kSeed(ss, netKey, a1, a2)
        val (d, z, m) = derivedSecrets(a1, a2, ks)
        val (pk, sk) = MlKem512.keygen(d, z)                          // local only, never on air
        val (kDf, cStar) = selfEncapKdf(pk, m)                         // #13 gate; c* never on air
        val keyAB = Hkdf.expand(kDf, KAB_LABEL + sidI + sidR, 32)
        val keyBA = Hkdf.expand(kDf, KBA_LABEL + sidI + sidR, 32)
        return DeriveResult.Ok(
            Derived(ss, transcriptHash(a1, a2), ks, d, z, pk, sk, m, kDf, cStar, keyAB, keyBA)
        )
    }

    /**
     * Phase-A orchestrator enforcing the #08 §4 DoS ordering on the handshake path:
     *   GMAC(A1) → GMAC(A2; transcript) → X25519 → ML-KEM.
     * Both verified, authenticated frames must be accepted *before* any DH/ML-KEM
     * work; a reject short-circuits with DeriveResult.Err(reason) (no secret derived).
     */
    fun runHandshake(
        a1Wire: ByteArray, a2Wire: ByteArray, netKey: ByteArray,
        ephPrivLocal: ByteArray, epkRemote: ByteArray, sidI: ByteArray, sidR: ByteArray,
        cache: ReplayCache,
    ): DeriveResult {
        val kGmac = gmacKey(netKey)
        verifyFrame(a1Wire, Direction.INIT, kGmac, cache)?.let { return DeriveResult.Err(it) }             // GMAC(A1) (#15 freshness + signer)
        verifyFrame(a2Wire, Direction.RESP, kGmac, cache, a1Wire)?.let { return DeriveResult.Err(it) }    // GMAC(A2; A1 transcript) — splice/reflection closed
        return deriveKeys(ephPrivLocal, epkRemote, netKey, a1Wire, a2Wire, sidI, sidR)                    // only then: X25519 → ML-KEM
    }

    /** Constant-time byte-array equality (ADR-0002 §5.2: GMAC tag compare is CT). */
    private fun ctEquals(a: ByteArray, b: ByteArray): Boolean {
        var d = a.size xor b.size
        val n = minOf(a.size, b.size)
        for (i in 0 until n) d = d or (a[i].toInt() xor b[i].toInt())
        return d == 0
    }

    /** Constant-time all-zero test (ss==0 CT-abort, no data-dependent branch). */
    private fun ctAllZero(a: ByteArray): Boolean {
        var acc = 0
        for (b in a) acc = acc or (b.toInt() and 0xff)
        return acc == 0
    }
}
