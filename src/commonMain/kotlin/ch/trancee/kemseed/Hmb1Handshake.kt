/*
 * HMB1-E1′ handshake orchestrator — derivation + GMAC frame verify layer.
 *
 * Pure-Kotlin, KMP commonMain (no java.*). Wires the committed 0c primitives
 * (X25519, Keccak, Hkdf, Gmac, MlKem512) per ADR-0002 §3/§O3 + #08 §3/§6:
 *
 *   epk  = X25519.scalarMult(ephPriv, BASE9 = u=9)        // scalar clamped inside
 *   K_gmac = HKDF-Extract("hmb1-gmac-v1", NetKey)         // signer key (#06/#15)
 *   wire = version ‖ nonce ‖ senderId ‖ flags ‖ epk ‖ GMAC(16)             (60 B)
 *   IV   = 0x11 ‖ dir ‖ nonce ‖ 0x00 0x00                                   (12 B)
 *   AAD_A1 = version ‖ flags ‖ nonce ‖ senderId ‖ epk                       (44 B)
 *   AAD_A2 = version ‖ flags ‖ nonce_r ‖ senderId_r ‖ epk_r ‖ AAD_A1        (76 B, transcript-bound)
 *   GMAC verified BEFORE X25519/ML-KEM (DoS gate, #15).
 *   ss      = X25519.scalarMult(ephPriv_local, epk_remote)  // CT-abort if all-zero
 *   T       = SHA3-256("HMB1-TR" ‖ wire_A1 ‖ wire_A2)
 *   K_seed  = HKDF-Extract(salt=T, IKM=ss ‖ NetKey)
 *   (d,z)   = SHAKE-256("HMB1-DZ" ‖ T ‖ K_seed, 64)
 *   (pk,sk) = ML-KEM-512.keygen(d, z)                         // local only
 *   m       = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)           // bound coin
 *   (K_df,c*)= ML-KEM-512.encapsulate(pk, m)                  // c* never on air
 *   key_AB  = HKDF-Expand(K_df, "HMB1-K-AB" ‖ sid_i ‖ sid_r, 32)
 *   key_BA  = HKDF-Expand(K_df, "HMB1-K-BA" ‖ sid_i ‖ sid_r, 32)
 *
 * E2E self-consistency + Decaps(sk,c*)==K_df are asserted in Hmb1HandshakeTest;
 * the upstream chain (epk/IV/AAD/GMAC/T/ss/K_seed/d/z/m) is pinned to an
 * independent Python (cryptography + hashlib) oracle — see test header.
 */
package ch.trancee.kemseed

internal object Hmb1Handshake {

    internal const val VERSION: Int = 1
    internal const val DIR_INIT: Int = 0xA0   // initiator direction byte (wire IV / cache)
    internal const val DIR_RESP: Int = 0xA1   // responder
    internal const val FRAME_SIZE: Int = 60
    internal const val MAC_SIZE: Int = 16

    internal val GMAC_LABEL: ByteArray = "hmb1-gmac-v1".encodeToByteArray()
    internal val TR_LABEL: ByteArray = "HMB1-TR".encodeToByteArray()
    internal val DZ_LABEL: ByteArray = "HMB1-DZ".encodeToByteArray()
    internal val EM_LABEL: ByteArray = "HMB1-EM".encodeToByteArray()
    internal val KAB_LABEL: ByteArray = "HMB1-K-AB".encodeToByteArray()
    internal val KBA_LABEL: ByteArray = "HMB1-K-BA".encodeToByteArray()

    /** X25519 base point u=9 (RFC 7748), little-endian 32 bytes. */
    internal val BASE9: ByteArray = ByteArray(32).apply { this[0] = 9 }

    class Derived(
        val ss: ByteArray, val T: ByteArray, val kSeed: ByteArray,
        val d: ByteArray, val z: ByteArray, val pk: ByteArray, val sk: ByteArray,
        val m: ByteArray, val kDf: ByteArray, val cStar: ByteArray,
        val keyAB: ByteArray, val keyBA: ByteArray,
    )

    /** Why a frame/derivation was rejected (before any ML-KEM work on ss==0 / GMAC fail). */
    enum class Reject { REPLAY, GMAC_FAIL, BAD_DIR, SS_ZERO }

    sealed interface DeriveResult {
        data class Ok(val derived: Derived) : DeriveResult
        data class Err(val reason: Reject) : DeriveResult
    }

    /** #15 freshness cache keyed by `dir ‖ nonce`; records on first sight. */
    class ReplayCache {
        private val entries = mutableListOf<ByteArray>()
        fun recordOrReject(dir: Int, nonce: ByteArray): Reject? {
            val key = byteArrayOf(dir.toByte()) + nonce
            for (e in entries) if (e.contentEquals(key)) return Reject.REPLAY
            entries.add(key)
            return null
        }
    }

    // ---- frame layout: version(1) ‖ nonce(8) ‖ senderId(2) ‖ flags(1) ‖ epk(32) ‖ mac(16) ----
    private fun aadBody(version: Int, flags: Int, nonce: ByteArray, senderId: ByteArray, epk: ByteArray): ByteArray =
        byteArrayOf(version.toByte(), flags.toByte()) + nonce + senderId + epk

    /** GCM IV = 0x11 ‖ dir ‖ nonce ‖ 0x00 0x00 (12 B). */
    fun iv(dir: Int, nonce: ByteArray): ByteArray =
        byteArrayOf(0x11, dir.toByte()) + nonce + byteArrayOf(0x00, 0x00)

    /** A1 (initiator) wire; for A2 pass the verified A1 wire to bind its AAD. */
    fun buildFrame(
        dir: Int, version: Int, nonce: ByteArray, senderId: ByteArray, flags: Int,
        epk: ByteArray, kGmac: ByteArray, a1Wire: ByteArray? = null,
    ): ByteArray {
        val aad = if (a1Wire != null) aadBody(version, flags, nonce, senderId, epk) + aadBodyOf(a1Wire)
        else aadBody(version, flags, nonce, senderId, epk)
        val mac = Gmac.gmacTag(kGmac, iv(dir, nonce), aad)
        return byteArrayOf(version.toByte()) + nonce + senderId + byteArrayOf(flags.toByte()) + epk + mac
    }

    private fun aadBodyOf(wire: ByteArray): ByteArray =
        aadBody(wire[0].toInt(), wire[11].toInt(), wire.copyOfRange(1, 9), wire.copyOfRange(9, 11), wire.copyOfRange(12, 44))

    /** Verify a wire frame: cache (replay) + IV dir-byte + GMAC. null = OK. */
    fun verifyFrame(
        wire: ByteArray, dir: Int, kGmac: ByteArray, cache: ReplayCache, a1Wire: ByteArray? = null,
    ): Reject? {
        check(wire.size == FRAME_SIZE) { "frame must be $FRAME_SIZE bytes" }
        val nonce = wire.copyOfRange(1, 9)
        cache.recordOrReject(dir, nonce)?.let { return it }           // REPLAY (DoS gate, #15)
        val aad = if (a1Wire != null) aadBodyOf(wire) + aadBodyOf(a1Wire) else aadBodyOf(wire)
        val expected = Gmac.gmacTag(kGmac, iv(dir, nonce), aad)
        val mac = wire.copyOfRange(44, 60)
        return if (ctEquals(expected, mac)) null else Reject.GMAC_FAIL
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

    /** Full E1′ derivation for one peer; CT-aborts (SS_ZERO) before ML-KEM on all-zero ss. */
    fun deriveKeys(
        ephPrivLocal: ByteArray, epkRemote: ByteArray, netKey: ByteArray,
        a1: ByteArray, a2: ByteArray, sidI: ByteArray, sidR: ByteArray,
    ): DeriveResult {
        val ss = X25519.scalarMult(ephPrivLocal, epkRemote)
        if (ctAllZero(ss)) return DeriveResult.Err(Reject.SS_ZERO)    // PFS gate (#08 §3/#11)
        val ks = kSeed(ss, netKey, a1, a2)
        val (d, z, m) = derivedSecrets(a1, a2, ks)
        val (pk, sk) = MlKem512.keygen(d, z)                          // local only
        val (kDf, cStar) = MlKem512.encapsulate(pk, m)                // c* discarded on air
        val keyAB = Hkdf.expand(kDf, KAB_LABEL + sidI + sidR, 32)
        val keyBA = Hkdf.expand(kDf, KBA_LABEL + sidI + sidR, 32)
        return DeriveResult.Ok(
            Derived(ss, transcriptHash(a1, a2), ks, d, z, pk, sk, m, kDf, cStar, keyAB, keyBA)
        )
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
