package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

internal class GmacTest {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    // All goldens produced by the AES-256-GMAC oracle
    //   AESGCM(key).encrypt(iv, b"", aad)   (Python `cryptography`, OpenSSL-backed)
    // and cross-checked against 400 random GCM vectors + the GHASH single-multiply
    // identity (see ADR-0002 §3: GMAC over the airborne epk). AES-256-ECB and
    // ENC(J0) verified independently via `openssl enc -aes-256-ecb`.
    //
    // NOTE on iv: the ADR draft text listed iv=00 01 … 09 10 11, but the tag below
    // is the oracle's output for the contiguous 00..0b sequence (0x0a0b, not 0x1011)
    // — "1011" was a transcription of "0a0b". This vector's tag is the oracle's.

    // A1 — single-block AAD; the canonical GMAC KAT.
    private val a1Key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val a1Iv = h("000102030405060708090a0b")
    private val a1Aad = h("00112233445566778899aabbccddeeff")
    private val a1Tag = h("b399331ea4d8694509a45ce7316a4450")

    // A2 — two-block AAD (exercises the GHASH chain + length block, lenA=256).
    private val a2Key = h("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c")
    private val a2Iv = h("000000000000000000000001")
    private val a2Aad = h("0102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff")
    private val a2Tag = h("09442d7731aaaa9eb3dafc0debcd3784")

    // A3 — empty AAD (exercises the all-zero length block, lenA=0).
    private val a3Key = a2Key
    private val a3Iv = h("000000000000000000000002")
    private val a3Tag = h("4112e5eaddb044afcc021c361bce94f1")

    @Test
    fun gmac_single_block_aad_matches_golden() {
        assertContentEquals(a1Tag, Gmac.gmacTag(a1Key, a1Iv, a1Aad), "GMAC A1 known-answer")
    }

    @Test
    fun gmac_two_block_aad_matches_golden() {
        assertContentEquals(a2Tag, Gmac.gmacTag(a2Key, a2Iv, a2Aad), "GMAC A2 known-answer")
    }

    @Test
    fun gmac_empty_aad_matches_golden() {
        assertContentEquals(a3Tag, Gmac.gmacTag(a3Key, a3Iv, ByteArray(0)), "GMAC A3 known-answer")
    }

    @Test
    fun gmac_tag_is_16_bytes() {
        assertEquals(16, Gmac.gmacTag(a1Key, a1Iv, a1Aad).size, "GMAC tag must be 16 bytes")
    }

    @Test
    fun gmac_rejects_non_96_bit_iv() {
        // GCM-GMAC is defined only for a 96-bit IV; the ADR freezes 96-bit IVs
        // (ADR-0002 §3: 0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00).
        assertFailsWith<IllegalArgumentException> { Gmac.gmacTag(a1Key, ByteArray(8), a1Aad) }
        assertFailsWith<IllegalArgumentException> { Gmac.gmacTag(a1Key, ByteArray(13), a1Aad) }
    }
}
