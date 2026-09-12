package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * AES-256-GCM (NIST SP 800-38D Algorithms 4 & 5) known-answer tests.
 *
 * Goldens are produced by the AES-256-GCM oracle
 *   `cryptography.hazmat.AESGCM(key).encrypt(iv, pt, aad)` (OpenSSL-backed),
 * the same oracle backing [GmacTest]'s GMAC KATs. Vectors cover: empty plaintext
 * (tag-only, cross-checked against `Gmac.gmacTag`), a non-block-aligned plaintext,
 * a block-aligned plaintext with AAD, and a 80-byte plaintext with hybrid AAD.
 * Tampering and malformed-input rejection are also covered.
 */
internal class Aes256GcmTest {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private val zeroIv = h("000102030405060708090a0b")
    private val zeroKey = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    // V1 — empty pt, empty aad: ciphertext is "" + 16-byte tag (the GMAC tag).
    @Test
    fun seal_empty_matches_oracle() {
        assertContentEquals(h("f4c2db1dc38805a37b92171c5d0a81cc"), Aes256Gcm.seal(zeroKey, zeroIv, h(""), h("")))
    }

    // V2 — pt "abc", empty aad: 3-byte ciphertext + 16-byte tag.
    @Test
    fun seal_short_pt_matches_oracle() {
        assertContentEquals(h("2660b5539677125a571f571ada456e85769a43"), Aes256Gcm.seal(zeroKey, zeroIv, h("616263"), h("")))
    }

    // V3 — one-block pt, aad "xyz".
    @Test
    fun seal_block_pt_aad_matches_oracle() {
        assertContentEquals(
            h("4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead80acdb6fd638181dc8716009fb2c88e0"),
            Aes256Gcm.seal(
                zeroKey, zeroIv,
                h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                h("78797a")
            )
        )
    }

    // V6 — 80-byte pt, key 01..20, iv 10..1b, aad "hybrid-pqble-mesh"+00..0f.
    @Test
    fun seal_large_matches_oracle() {
        assertContentEquals(
            h("b2eab81b8f7e1aa2435995906ac7d8659d9b0b8ac32ae3ce59d76ecdb5498e6adac413850c099cd61bb8c392a5206f28fa8a87f170e5e22306bd5c0161df933ea89d350765144b6fd9f5d8a7341a641dc43e8adf0101c22377aa6c8a97ab1625"),
            Aes256Gcm.seal(
                h("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                h("101112131415161718191a1b"),
                h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                h("6879627269642d7071632d626c652d6d657368") + h("000102030405060708090a0b0c0d0e0f")
            )
        )
    }

    // Cross-primitive: seal with empty plaintext yields ct="" + tag == GMAC key/aad.
    @Test
    fun seal_empty_pt_tag_matches_gmac_tag() {
        assertContentEquals(
            Gmac.gmacTag(zeroKey, zeroIv, h("00112233445566778899aabbccddeeff")),
            Aes256Gcm.seal(zeroKey, zeroIv, h(""), h("00112233445566778899aabbccddeeff"))
        )
    }

    @Test
    fun open_recovers_plaintext() {
        val pt = h("616263")
        val sealed = Aes256Gcm.seal(zeroKey, zeroIv, pt, h(""))
        assertContentEquals(pt, Aes256Gcm.open(zeroKey, zeroIv, sealed, h("")))
    }

    @Test
    fun open_empty_recovers_empty() {
        val sealed = Aes256Gcm.seal(zeroKey, zeroIv, h(""), h(""))
        assertContentEquals(h(""), Aes256Gcm.open(zeroKey, zeroIv, sealed, h("")))
    }

    @Test
    fun open_roundtrips_large_with_aad() {
        val k = h("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val iv = h("101112131415161718191a1b")
        val pt = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
        val aad = h("78797a")
        val sealed = Aes256Gcm.seal(k, iv, pt, aad)
        assertContentEquals(pt, Aes256Gcm.open(k, iv, sealed, aad))
    }

    @Test
    fun tamper_ciphertext_rejected() {
        val sealed = Aes256Gcm.seal(zeroKey, zeroIv, h("616263"), h(""))
        val tampered = sealed.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertNull(Aes256Gcm.open(zeroKey, zeroIv, tampered, h("")))
    }

    @Test
    fun tamper_aad_rejected() {
        val sealed = Aes256Gcm.seal(zeroKey, zeroIv, h("616263"), h(""))
        assertNull(Aes256Gcm.open(zeroKey, zeroIv, sealed, h("deadbeef")))
    }

    @Test
    fun tamper_tag_rejected() {
        val sealed = Aes256Gcm.seal(zeroKey, zeroIv, h("616263"), h(""))
        val tampered = sealed.copyOf()
        val last = tampered.size - 1
        tampered[last] = (tampered[last].toInt() xor 0x80).toByte()
        assertNull(Aes256Gcm.open(zeroKey, zeroIv, tampered, h("")))
    }

    @Test
    fun reject_short_key() {
        assertFailsWith<IllegalArgumentException> {
            Aes256Gcm.seal(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"), h(""), h(""), h(""))
        }
    }

    @Test
    fun reject_short_iv() {
        assertFailsWith<IllegalArgumentException> {
            Aes256Gcm.seal(zeroKey, h("00010203040506070809"), h("616263"), h(""))
        }
    }

    @Test
    fun reject_short_ciphertext_and_tag() {
        assertFailsWith<IllegalArgumentException> {
            Aes256Gcm.open(zeroKey, zeroIv, h("00112233445555"), h(""))
        }
    }
}
