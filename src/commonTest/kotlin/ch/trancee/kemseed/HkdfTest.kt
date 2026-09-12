package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * HKDF over HMAC-SHA3-256 (FIPS 202, block size = rate = 136 B).
 *
 * Every golden below was computed with an independent, validated oracle —
 * Python `hashlib`+`hmac` (OpenSSL-backed stdlib) cross-checked against the
 * `cryptography` package `HKDF(SHA3_256)`: the two agree byte-for-byte. The
 * HKDF input fixtures are the canonical RFC 5869 §B test vectors (Test Cases
 * 1, 2 and 3), run with SHA3-256 as HKDF's hash in place of SHA-256.
 *
 * Per ADR-0002 §4 (key derivation uses HKDF-Extract-then-Expand over
 * HMAC-SHA3-256; the SHA3-256 HMAC block size is its rate, 136 B).
 *
 * NOTE: an earlier session summary floated an unrecorded golden
 * `f1d799b5…` (PRK `294584dc…`) whose inputs were never persisted, so it
 * could not be reproduced against any RFC 5869 / NIST CAVP fixture. Per the
 * "never fabricate vectors" rule these tests target the oracle's actual
 * output on the cited RFC 5869 fixtures instead.
 */
internal class HkdfTest {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    // ---- RFC 5869 §B.1 (Test Case 1), SHA3-256 variant ----
    // IKM = 0x0b * 22, salt = 0x000102030405060708090a0b0c (13 B),
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 B), L = 42.
    private val b1Ikm = h("0b".repeat(22))
    private val b1Salt = h("000102030405060708090a0b0c")
    private val b1Info = h("f0f1f2f3f4f5f6f7f8f9")
    private val b1Prk = h("7d4194836f7a113a44677abc825640ade07af1c1d69a9a4b109b280a8fe54ef0")
    private val b1Okm = h(
        "0c5160501d65021deaf2c14f5abce04c5bd2635abceeba61c2edb6e8ed726749" +
        "00557728f2c9f2c4c179"
    )

    // ---- RFC 5869 §B.2 (Test Case 2): 80-byte IKM/salt/info, L = 82 (multi-block expand) ----
    private val b2Ikm = ByteArray(80) { it.toByte() }                       // 0x00..0x4f
    private val b2Salt = ByteArray(80) { (0x60 + it).toByte() }             // 0x60..0xaf
    private val b2Info = ByteArray(80) { (0xb0 + it).toByte() }             // 0xb0..0xff
    private val b2Prk = h("addf31835b49366ac27734104d9f1865c1c2e7c8a2ebc1fed712808e4eab677c")
    private val b2Okm = h(
        "3dc251e66c75da6560405ec5ac10e17d851eedfbfdc13feafbec16964c25d021" +
        "bd971465a3e9c615f27769019e3f0407d84986fb0ba24e729c99834624baa21" +
        "cb623dc0098f430d52e18bbdf694df4edd8b2"
    )

    // ---- RFC 5869 §B.3 (Test Case 3): empty salt (-> 32 zero bytes) / empty info, L = 42 ----
    private val b3Ikm = h("0b".repeat(22))
    private val b3Salt = ByteArray(0) // NULL salt -> HashLen=32 zero bytes per RFC 5869 §2.2
    private val b3Info = ByteArray(0)
    private val b3Prk = h("b899e6e4b88a35f9f5d618f48b424c313f9704012763eb6295414d673365928a")
    private val b3Okm = h("bc1342cdd75c05e8b0c3ae609ce4410684d197232875073499b30cdfe2de2853c1c1bed63d725e885e78")

    // Direct HMAC-SHA3-256 KAT (oracle-derived: hashlib.hmac(sha3_256)).
    private val hmacKey = h("0b".repeat(32))
    private val hmacMsg = ("abc".repeat(5)).encodeToByteArray()
    private val hmacTag = h("26c228cb0d277d33d73813dd1089d3a493da11be4e098935f433ac0660b17d82")

    @Test
    fun hmac_sha3_256_matches_oracle() {
        assertContentEquals(hmacTag, Hkdf.hmac(hmacKey, hmacMsg))
    }

    @Test
    fun rfc5869_b1_extract_prk_matches_golden() {
        assertContentEquals(b1Prk, Hkdf.extract(b1Salt, b1Ikm))
    }

    @Test
    fun rfc5869_b1_expand_matches_golden() {
        assertContentEquals(b1Okm, Hkdf.expand(b1Prk, b1Info, 42))
    }

    @Test
    fun rfc5869_b1_extract_then_expand_matches_golden() {
        assertContentEquals(b1Okm, Hkdf.extractThenExpand(b1Salt, b1Ikm, b1Info, 42))
    }

    @Test
    fun rfc5869_b2_multiblock_matches_golden() {
        // 82-byte output spans >1 SHA3-256 HMAC block, exercising T(1)||T(2).
        assertContentEquals(b2Prk, Hkdf.extract(b2Salt, b2Ikm))
        assertContentEquals(b2Okm, Hkdf.extractThenExpand(b2Salt, b2Ikm, b2Info, 82))
    }

    @Test
    fun rfc5869_b3_empty_salt_and_info_matches_golden() {
        // NULL/empty salt -> RFC 5869 §2.2 substitutes HashLen=32 zero bytes.
        assertContentEquals(b3Prk, Hkdf.extract(b3Salt, b3Ikm))
        assertContentEquals(b3Okm, Hkdf.extractThenExpand(b3Salt, b3Ikm, b3Info, 42))
    }

    @Test
    fun expand_clamps_to_255_times_hashlen() {
        val prk = Hkdf.extract(b1Salt, b1Ikm)
        // 255 * 32 = 8160 is the HKDF-Expand maximum (RFC 5869 §2.3).
        assertEquals(8160, Hkdf.expand(prk, b1Info, 8160).size)
        assertFailsWith<IllegalArgumentException> { Hkdf.expand(prk, b1Info, 8161) }
        assertFailsWith<IllegalArgumentException> { Hkdf.expand(prk, b1Info, -1) }
    }

    @Test
    fun expand_single_block_roundtrip_with_reexpand() {
        // T(i) reuses prior T(i-1) byte-for-byte: re-derive block 2 and check
        // the second 32-byte chunk equals HMAC(prk, T(1) || info || 0x02).
        val prk = b1Prk
        val info = b1Info
        val out = Hkdf.expand(prk, info, 64)
        val t1 = out.copyOfRange(0, 32)
        val expectedT2 = Hkdf.hmac(prk, t1 + info + byteArrayOf(2))
        assertContentEquals(expectedT2, out.copyOfRange(32, 64))
        assertTrue(out.copyOfRange(0, 32).contentEquals(t1))
    }
}
