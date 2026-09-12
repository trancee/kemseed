package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Phase-0d integration: the E1′ handshake composition (#08 §3/§6).
 *
 * The key tree upstream of ML-KEM (epk, K_gmac, the GMAC frame tags, the
 * transit transcript T, the X25519 shared secret ss, HKDF-Extract K_seed,
 * and the SHAKE-256 (d,z,m) derivations) is cross-checked against an INDEPENDENT
 * oracle — Python `cryptography` (X25519 + AESGCM) + `hashlib` (SHA3-256,
 * SHAKE-256) + `cryptography` HKDF(SHA3_256) — so a wrong HKDF label, frame
 * field order, or IV dir-byte cannot pass (self-consistency alone wouldn't catch
 * a shared-by-both-peers label error). ML-KEM's deterministic internal path
 * `(d,z)->(pk,sk)->(K_df,c*)` is not exposed by any oracle, so key_AB/key_BA are
 * pinned by (i) both peers reproducing the identical Derived tree, and (ii)
 * `Decaps_internal(sk, c*) == K_df` (the NIST-FIPS-203-KAT-validated ops).
 *
 * ADR-0002 §O3 records the GHASH/HKDF conventions this phase depends on.
 */
internal class Hmb1HandshakeTest {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    // ---- fixed E2E fixtures (chosen, deterministic) ----
    private val netKey = ByteArray(32) { it.toByte() }                  // 0x00..0x1f
    private val ephPrivI = ByteArray(32) { (0x10 + it).toByte() }       // 0x10..0x2f
    private val ephPrivR = ByteArray(32) { (0x30 + it).toByte() }       // 0x30..0x4f
    private val nonceI = ByteArray(8) { (0x50 + it).toByte() }          // 0x50..0x57
    private val nonceR = ByteArray(8) { (0x60 + it).toByte() }          // 0x60..0x67
    private val senderIdI = h("aaab")
    private val senderIdR = h("bbbc")
    private val sidI = h("cccd")
    private val sidR = h("eeef")
    private val base9 = h("09" + "00".repeat(31))
    private val zeroPub = ByteArray(32)                                // low-order point -> ss=0

    // ---- externally-validated goldens (cryptography + hashlib, see file header) ----
    private val epkGoldenI = h("d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66")
    private val epkGoldenR = h("34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847")
    private val kGmacGolden = h("7ec4c43c6a9caebe9d6affc74fe6e441be33087f84ad03be383c1bbf72661c96")
    private val wireGoldenA1 = h(
        "015051525354555657aaab00" +
        "d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66" +
        "4222a96c1a2261ae86ad69b5cbe65e44"
    )
    private val wireGoldenA2 = h(
        "016061626364656667bbbc00" +
        "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847" +
        "bc55bfe548a76ca5019f962f92c40e30"
    )
    private val transcriptGolden = h("34e820e3c74b938cd90fce6e08181eaded007f5ba04fb2d9a5aad70254175804")
    private val ssGolden = h("6e3c33b4c96fcb38dfa7862eae5bb902fe66cc2a41ca553280ded9dc363c852f")
    private val kSeedGolden = h("a5bacadafa5db25b2853991e78bc9e6d2cdb84a4abb883480caa0c34bd7d189f")
    private val dGolden = h("56ba8507cec85061761233278e751fa1cdcfee4196bf06e8f8b31640ce3ce73c")
    private val zGolden = h("bb643ba22921d3a11a6e32ec3f250c2c3dac5b211afd8b58d5d4cdfe8b1b76e7")
    private val mGolden = h("b70ca7d2c15c285ba59224a9017d7573b401742b8e3f5b7b0537b431ffbecf36")

    private fun buildHonestFrames(): Triple<ByteArray, ByteArray, ByteArray> {
        val kGmac = Hmb1Handshake.gmacKey(netKey)
        val epkI = X25519.scalarMult(ephPrivI, base9)
        val epkR = X25519.scalarMult(ephPrivR, base9)
        val a1 = Hmb1Handshake.buildFrame(Hmb1Handshake.DIR_INIT, 1, nonceI, senderIdI, 0, epkI, kGmac)
        val a2 = Hmb1Handshake.buildFrame(Hmb1Handshake.DIR_RESP, 1, nonceR, senderIdR, 0, epkR, kGmac, a1)
        return Triple(kGmac, a1, a2)
    }

    @Test
    fun ephem_public_keys_match_oracle() {
        assertContentEquals(epkGoldenI, X25519.scalarMult(ephPrivI, base9))
        assertContentEquals(epkGoldenR, X25519.scalarMult(ephPrivR, base9))
    }

    @Test
    fun gmac_signer_key_matches_oracle() {
        assertContentEquals(kGmacGolden, Hmb1Handshake.gmacKey(netKey))
    }

    @Test
    fun a1_frame_matches_oracle() {
        val kGmac = Hmb1Handshake.gmacKey(netKey)
        val epkI = X25519.scalarMult(ephPrivI, base9)
        assertContentEquals(wireGoldenA1, Hmb1Handshake.buildFrame(Hmb1Handshake.DIR_INIT, 1, nonceI, senderIdI, 0, epkI, kGmac))
    }

    @Test
    fun a2_frame_transcript_bound_matches_oracle() {
        val (kGmac, a1, _) = buildHonestFrames()
        val epkR = X25519.scalarMult(ephPrivR, base9)
        assertContentEquals(wireGoldenA2, Hmb1Handshake.buildFrame(Hmb1Handshake.DIR_RESP, 1, nonceR, senderIdR, 0, epkR, kGmac, a1))
    }

    @Test
    fun transcript_hash_matches_oracle() {
        val (_, a1, a2) = buildHonestFrames()
        assertContentEquals(transcriptGolden, Hmb1Handshake.transcriptHash(a1, a2))
    }

    @Test
    fun shared_secret_matches_oracle_and_is_symmetric() {
        val (_, _, a2) = buildHonestFrames()
        val epkI = X25519.scalarMult(ephPrivI, base9)
        val epkR = X25519.scalarMult(ephPrivR, base9)
        val (_, a1, _) = buildHonestFrames()
        val si = X25519.scalarMult(ephPrivI, epkR)
        val sr = X25519.scalarMult(ephPrivR, epkI)
        assertContentEquals(ssGolden, si)
        assertContentEquals(sr, si)   // commutativity
    }

    @Test
    fun k_seed_matches_oracle() {
        val (_, a1, a2) = buildHonestFrames()
        val ss = X25519.scalarMult(ephPrivI, X25519.scalarMult(ephPrivR, base9))
        assertContentEquals(kSeedGolden, Hmb1Handshake.kSeed(ss, netKey, a1, a2))
    }

    @Test
    fun shake_derived_dz_m_match_oracle() {
        val (_, a1, a2) = buildHonestFrames()
        val ss = X25519.scalarMult(ephPrivI, X25519.scalarMult(ephPrivR, base9))
        val kSeed = Hmb1Handshake.kSeed(ss, netKey, a1, a2)
        val (d, z, m) = Hmb1Handshake.derivedSecrets(a1, a2, kSeed)
        assertContentEquals(dGolden, d)
        assertContentEquals(zGolden, z)
        assertContentEquals(mGolden, m)
    }

    @Test
    fun both_peers_reproduce_full_key_tree_and_decaps_confirms_kdf() {
        val (kGmac, a1, a2) = buildHonestFrames()
        val init = Hmb1Handshake.deriveKeys(ephPrivI, X25519.scalarMult(ephPrivR, base9), netKey, a1, a2, sidI, sidR)
        val resp = Hmb1Handshake.deriveKeys(ephPrivR, X25519.scalarMult(ephPrivI, base9), netKey, a1, a2, sidI, sidR)
        assertTrue(init is Hmb1Handshake.DeriveResult.Ok, "initiator must derive")
        assertTrue(resp is Hmb1Handshake.DeriveResult.Ok, "responder must derive")
        val di = (init as Hmb1Handshake.DeriveResult.Ok).derived
        val dr = (resp as Hmb1Handshake.DeriveResult.Ok).derived
        // both peers reproduce every field identically
        assertContentEquals(di.ss, dr.ss); assertContentEquals(di.kSeed, dr.kSeed)
        assertContentEquals(di.d, dr.d); assertContentEquals(di.z, dr.z)
        assertContentEquals(di.pk, dr.pk); assertContentEquals(di.sk, dr.sk)
        assertContentEquals(di.m, dr.m); assertContentEquals(di.kDf, dr.kDf)
        assertContentEquals(di.cStar, dr.cStar)
        assertContentEquals(di.keyAB, dr.keyAB); assertContentEquals(di.keyBA, dr.keyBA)
        // key directions differ
        assertFalse(di.keyAB.contentEquals(di.keyBA), "key_AB must not equal key_BA")
        // deterministic self-encap consistency: Decaps(sk, c*) == K_df
        assertContentEquals(di.kDf, MlKem512.decapsulate(di.sk, di.cStar))
    }

    @Test
    fun gmac_before_dh_rejects_bit_flipped_a1() {
        val (kGmac, a1, a2) = buildHonestFrames()
        val flipped = a1.copyOf()
        flipped[12] = (flipped[12].toInt() xor 0x01).toByte()   // flip one epk bit in A1
        val cache = Hmb1Handshake.ReplayCache()
        assertEquals(Hmb1Handshake.Reject.GMAC_FAIL, Hmb1Handshake.verifyFrame(flipped, Hmb1Handshake.DIR_INIT, kGmac, cache))
    }

    @Test
    fun replay_cache_rejects_duplicate_nonce() {
        val (kGmac, a1, _) = buildHonestFrames()
        val cache = Hmb1Handshake.ReplayCache()
        assertEquals(null, Hmb1Handshake.verifyFrame(a1, Hmb1Handshake.DIR_INIT, kGmac, cache))  // first: fresh
        assertEquals(Hmb1Handshake.Reject.REPLAY, Hmb1Handshake.verifyFrame(a1, Hmb1Handshake.DIR_INIT, kGmac, cache))  // dup -> replay
    }

    @Test
    fun a2_as_a1_reflection_is_rejected() {
        val (kGmac, a1, a2) = buildHonestFrames()
        val cache = Hmb1Handshake.ReplayCache()
        // present the responder A2 (dir 0xA1, nonce_r) as an initiator A1 (dir 0xA0):
        // the cached dir + GCM IV dir-byte no longer match the tag -> GMAC_FAIL.
        assertEquals(Hmb1Handshake.Reject.GMAC_FAIL, Hmb1Handshake.verifyFrame(a2, Hmb1Handshake.DIR_INIT, kGmac, cache, a1))
    }

    @Test
    fun all_zero_shared_secret_aborts_before_mlkem() {
        val (_, a1, a2) = buildHonestFrames()
        // peer presents epk = 0^32 (low-order) that *would* pass a frame check;
        // the derivation must still abort (no ML-KEM call) on ss == 0.
        val res = Hmb1Handshake.deriveKeys(ephPrivI, zeroPub, netKey, a1, a2, sidI, sidR)
        assertTrue(res is Hmb1Handshake.DeriveResult.Err)
        assertEquals(Hmb1Handshake.Reject.SS_ZERO, (res as Hmb1Handshake.DeriveResult.Err).reason)
    }

    @Test
    fun honest_frames_verify_ok() {
        val (kGmac, a1, a2) = buildHonestFrames()
        val cache = Hmb1Handshake.ReplayCache()
        assertEquals(null, Hmb1Handshake.verifyFrame(a1, Hmb1Handshake.DIR_INIT, kGmac, cache))
        assertEquals(null, Hmb1Handshake.verifyFrame(a2, Hmb1Handshake.DIR_RESP, kGmac, cache, a1))
    }
}
