package ch.trancee.kemseed.pdu

import ch.trancee.kemseed.Hmb1Handshake
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** (rawHex, expected version, pduType, reserved) — 4-tuple (Triple holds only 3). */
private data class FieldRow(val rawHex: String, val version: Int, val pduType: Int, val reserved: Int)

/**
 * Phase-1b AD-PDU envelope tests (`#08` §1.6 §3 Phase D; ADR-0003).
 *
 * Two axes, each Arrange-Act-Assert:
 *  - **kompact bit-packing** — Layer 1 (hand-written `encodeAdPduHeader` via
 *    `KompactWriter`) pinned to bit-exact byte goldens; Layer 2 (hand-written
 *    `KompactRuntime.readBits` read accessors on `AdPduHeader`) pinned by round-trip
 *    reads.
 *  - **AES-256-GCM AEAD** — `AdPduCrypto` (⇢ `Aes256Gcm` ⇢ `Hmb1Handshake.iv` frozen
 *    IV) pinned to an **independent OpenSSL `cryptography.AESGCM` oracle**. Vectors use a
 *    test key `0x00..1f` (NOT a real session key) and `aad = EMPTY`, matching #08 §1.6
 *    (direction + seqno authenticate via the IV, not AAD).
 *
 * GMAC-before-X25519-before-ML-KEM does not apply to the data PDU: it runs
 * post-handshake under `keyAB`/`keyBA`, so these vectors exercise the symmetric envelope only.
 */
internal class AdPduTest {

    // --- Shared fixtures (Arrange baseline) ---

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    /** Test key 0x00..1f — NOT a session key; mirrors the AESGCM oracle's key. */
    private val key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    /** The 8-byte LE nonce that #08 §1.6 slots into the frozen IV. */
    private fun seqnoLe(seqno: Long): Long = seqno

    // ---- Layer 1: kompact encode determinism (independent of KSP codegen) ----

    @Test
    fun encodeHeader_versions_matchBitGoldens() {
        // Arrange — the three bit-packing variants (version=1, varying pduType/reserved).

        // Act + Assert — one per row; layout is version(4) | pduType(3) | reserved(1), LSB-first.
        assertContentEquals(h("01"), encodeAdPduHeader(1, PduType.DATA, 0), "DATA")      // v1|pt0|0
        assertContentEquals(h("21"), encodeAdPduHeader(1, PduType.CONTROL, 0), "CONTROL") // v1|pt2|0
        assertContentEquals(h("b1"), encodeAdPduHeader(1, PduType.NACK, 1), "NACK+rsv")   // v1|pt3|1
    }

    // ---- Layer 2: hand-written KompactRuntime.readBits read accessors round-trip ----

    @Test
    fun headerAccessors_roundtripDecodedFields() {
        // Arrange — (raw byte, expected version, pduType, reserved).
        val rows = listOf(
            FieldRow("01", 1, 0, 0), // DATA
            FieldRow("21", 1, 2, 0), // CONTROL
            FieldRow("b1", 1, 3, 1), // NACK + reserved
        )

        // Act + Assert — decode each golden byte via the read accessors.
        for ((rawHex, v, pt, r) in rows) {
            val header = AdPduHeader(h(rawHex))
            assertEquals(v, header.version, "$rawHex version")
            assertEquals(pt, header.pduType, "$rawHex pduType")
            assertEquals(r, header.reserved, "$rawHex reserved")
        }
    }

    @Test
    fun pduTypeEnum_resolvesRoundtrip() {
        // Arrange
        val byRaw = listOf(
            h("01") to PduType.DATA,
            h("21") to PduType.CONTROL,
            h("b1") to PduType.NACK,
        )

        // Act + Assert
        for ((raw, expected) in byRaw) {
            assertEquals(expected, PduType.fromWire(AdPduHeader(raw).pduType), "raw=$raw")
        }
    }

    @Test
    fun pduTypeEnum_rejectsReservedWireValues() {
        // Arrange — 3-bit field, canonical enum covers 0..3; 4..7 are reserved.

        // Act + Assert — decoding a reserved ordinal must fail fast (post-auth path).
        assertFailsWith<IllegalArgumentException> { PduType.fromWire(4) }
        assertFailsWith<IllegalArgumentException> { PduType.fromWire(7) }
    }

    @Test
    fun headerLayout_isOneByte() {
        // Arrange + Act
        val header = AdPduHeader(h("01"))

        // Assert — 8 bits (4+3+1) pack into exactly 1 byte.
        assertEquals(8, AD_PDU_HEADER_BITS)
        assertEquals(1, header.raw.size)
    }

    // ---- Independent OpenSSL `cryptography.AESGCM` goldens for AdPduCrypto.seal ----

    @Test
    fun seal_G1_INIT_matchesOracle() {
        // Arrange — dir=INIT(0xA0), seqno=0x0102030405060708, plain = hdr(0x01) ‖ "abc".
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))

        // Act
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 0x0102030405060708L, key,
            header, h("616263"))

        // Assert — independent OpenSSL cryptography.AESGCM oracle golden.
        assertContentEquals(h("ab867eecc94312d585e4152c49dfbded0b28e167"), sealed)
    }

    @Test
    fun seal_G2_RESP_matchesOracle() {
        // Arrange — dir=RESP(0xA1), seqno=5, plain = hdr(0x21) ‖ aabbccdd.
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.CONTROL, 0))

        // Act
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.RESP, seqnoLe(5), key,
            header, h("aabbccdd"))

        // Assert
        assertContentEquals(h("d40e2ce6916b5ddb60a7665f8dc9714c64d7d9d38b"), sealed)
    }

    @Test
    fun seal_G3_NACK_reserved_matchesOracle() {
        // Arrange — dir=INIT(0xA0), seqno=7, plain = hdr(0xB1) ‖ 0102.
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.NACK, 1))

        // Act
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, seqnoLe(7), key,
            header, h("0102"))

        // Assert
        assertContentEquals(h("b7b74f02df679f2b9a0ba5c6d2bb94b602a556"), sealed)
    }

    // ---- AdPduCrypto.unseal: verify-then-decrypt + field recovery ----

    @Test
    fun unseal_G1_recoversHeaderAndPayload() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 0x0102030405060708L, key,
            header, h("616263"))

        // Act
        val unsealed = assertNotNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 0x0102030405060708L, key, sealed))

        // Assert
        assertEquals(1, unsealed.header.version)
        assertEquals(0, unsealed.header.pduType)
        assertEquals(0, unsealed.header.reserved)
        assertContentEquals(h("616263"), unsealed.payload)
    }

    @Test
    fun unseal_G3_recoversNackReservedAndPayload() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.NACK, 1))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, seqnoLe(7), key,
            header, h("0102"))

        // Act
        val unsealed = assertNotNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 7L, key, sealed))

        // Assert
        assertEquals(1, unsealed.header.version)
        assertEquals(PduType.NACK, PduType.fromWire(unsealed.header.pduType))
        assertEquals(1, unsealed.header.reserved)
        assertContentEquals(h("0102"), unsealed.payload)
    }

    // ---- Rejection surface (constant-time tag verify ⇒ null, no plaintext leak) ----

    private fun flip(b: ByteArray, i: Int): ByteArray = b.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }

    @Test
    fun tamperCiphertext_rejected() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))

        // Act + Assert — flipping a ciphertext byte breaks the tag → null.
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 1L, key, flip(sealed, 0)))
    }

    @Test
    fun tamperTag_rejected() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))

        // Act + Assert — flipping the trailing tag byte → null.
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 1L, key, flip(sealed, sealed.lastIndex)))
    }

    @Test
    fun wrongSeqno_rejected() {
        // Arrange — seqno is bound into the IV by #08 §1.6; reusing the sealed PDU
        // under a different seqno must fail (IV differs → tag mismatch).
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))

        // Act + Assert
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 2L, key, sealed))
    }

    @Test
    fun wrongDirection_rejected() {
        // Arrange — wrong direction ⇒ different IV direction byte ⇒ tag mismatch.
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))

        // Act + Assert
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.RESP, 1L, key, sealed))
    }

    @Test
    fun wrongKey_rejected() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))
        val badKey = h("42".repeat(32))

        // Act + Assert
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 1L, badKey, sealed))
    }

    @Test
    fun aadMismatch_rejected() {
        // Arrange — sealed with EMPTY aad (#08 §1.6); opening with non-empty aad must fail.
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val sealed = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))

        // Act + Assert
        assertNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 1L, key, sealed, aad = h("deadbeef")))
    }

    // ---- Monotonic seqno: distinct nonces ⇒ distinct ct‖tag, both verifiable ----

    @Test
    fun monotonicSeqno_yieldsDistinctCiphertexts() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))

        // Act
        val a = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, key, header, h("6162"))
        val b = AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 2L, key, header, h("6162"))

        // Assert — distinct nonces ⇒ distinct ct‖tag; each round-trips under its own seqno.
        assertFalse(a.contentEquals(b), "distinct seqno must yield distinct sealed PDU")
        assertNotNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 1L, key, a))
        assertNotNull(AdPduCrypto.unseal(Hmb1Handshake.Direction.INIT, 2L, key, b))
    }

    @Test
    fun rejectShortKey() {
        // Arrange
        val header = AdPduHeader(encodeAdPduHeader(1, PduType.DATA, 0))
        val shortKey = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d")

        // Act + Assert — 31-byte key must be rejected before any crypto.
        assertFailsWith<IllegalArgumentException> {
            AdPduCrypto.seal(Hmb1Handshake.Direction.INIT, 1L, shortKey, header, h("61"))
        }
    }
}
