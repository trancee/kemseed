package ch.trancee.kemseed.pdu

import ch.trancee.kemseed.Aes256
import ch.trancee.kemseed.Aes256Gcm
import ch.trancee.kemseed.Hmb1Handshake

/**
 * Phase-1b secured-AD-PDU AEAD (`#08` §1.6 / §3 Phase D; ADR-0003).
 *
 * On-wire PDU = AES-256-GCM(key, IV, plain = header ‖ payload, aad = EMPTY) →
 * `ciphertext ‖ tag` (16-byte tag). This is the symmetric-session layer that
 * `#08` Phase D ("AES-256-GCM bidirectional; monotonic AEAD nonce") wraps each
 * AD-PDU in, under the session keys derived by `Hmb1Handshake`:
 *
 * - **key** = `Hmb1Handshake.Derived.keyAB` (A→B) / `keyBA` (B→A) (`#08` §3 Phase B).
 * - **IV** = `Hmb1Handshake.iv(dir, nonce)` = `0x11 ‖ dir(1) ‖ nonce(8) ‖ 0x00 0x00`
 *   (`#08` §1.6 frozen GCM IV). `dir` = `Direction.INIT(0xA0)` | `RESP(0xA1)`; `nonce`
 *   is an 8-byte monotonic per-direction seqno, encoded **little-endian** (BLE +
 *   kompact LE convention; both peers construct the IV identically).
 * - **aad = EMPTY**: direction + seqno are authenticated via the IV (per `#08` §1.6),
 *   **not** duplicated into AAD. The data-flight AAD is deliberately empty.
 *
 * `open` delegates tag verification to `Aes256Gcm.open`, which constant-time-compares
 * the tag **before** exposing plaintext, so a forged/tampered PDU yields `null` with no
 * length oracle on the plaintext path (`#08` §6 CT posture; first GCM data packet
 * failing open ⇒ abort, §3 Phase A).
 *
 * Pure commonMain (KMP: android + iosArm64). No `java.*`, no `clone()`.
 *
 * `internal` because it binds to `Hmb1Handshake` (internal) primitives; becomes a
 * public PDU API once the Phase-1b contract graduates.
 */
internal object AdPduCrypto {

    /** Empty AAD for the data PDU: per `#08` §1.6 the IV authenticates dir+seqno. */
    internal val EMPTY_AAD: ByteArray = ByteArray(0)

    /** Encode a monotonic per-direction seqno into the 8-byte LE nonce slot of the frozen IV. */
    private fun Long.leNonce(): ByteArray = ByteArray(8) { i -> ((this ushr (i * 8)) and 0xffL).toByte() }

    /**
     * Seal an AD-PDU: GCM(key, IV, header ‖ payload, aad) → `ct ‖ tag`.
     *
     * @param dir     flow direction (selects keyAB/keyBA and the IV direction byte).
     * @param seqno   monotonic per-direction nonce (must not repeat under [key]).
     * @param key     32-byte session key (`keyAB` for A→B, `keyBA` for B→A).
     * @param header  bit-packed AD-PDU header (1 byte).
     * @param payload PDV payload bytes that follow the header.
     * @param aad     authenticated additional data (default EMPTY per `#08` §1.6).
     * @return        on-wire secured PDU = `ciphertext ‖ tag`.
     */
    fun seal(
        dir: Hmb1Handshake.Direction,
        seqno: Long,
        key: ByteArray,
        header: AdPduHeader,
        payload: ByteArray,
        aad: ByteArray = EMPTY_AAD,
    ): ByteArray {
        require(key.size == Aes256.KEY_SIZE) { "AD-PDU key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }
        val iv = Hmb1Handshake.iv(dir, seqno.leNonce())           // #08 §1.6 frozen IV
        val plain = header.raw + payload                         // AD-PDU plaintext = header ‖ payload
        return Aes256Gcm.seal(key, iv, plain, aad)               // → ct ‖ tag (16-byte tag)
    }

    /**
     * Unseal (verify-then-decrypt) a secured AD-PDU. The tag is verified
     * constant-time by `Aes256Gcm.open` **before** plaintext exposure; returns
     * `null` on any tampering (ct/tag/aad/IV/key mismatch).
     *
     * The public pairing is `seal`/`unseal` (libsodium-style AEAD), internally
     * delegating to `Aes256Gcm.open` (NIST SP 800-38D "Algorithm 5" terminology),
     * which stays unchanged at that lower layer.
     */
    fun unseal(
        dir: Hmb1Handshake.Direction,
        seqno: Long,
        key: ByteArray,
        securedPdu: ByteArray,
        aad: ByteArray = EMPTY_AAD,
    ): UnsealedAdPdu? {
        require(key.size == Aes256.KEY_SIZE) { "AD-PDU key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }
        val iv = Hmb1Handshake.iv(dir, seqno.leNonce())
        val plain = Aes256Gcm.open(key, iv, securedPdu, aad) ?: return null
        val headerSize = AD_PDU_HEADER_BITS / 8                  // 1 byte
        val header = AdPduHeader(plain.copyOf(headerSize))      // kompact view over raw bytes
        val payload = plain.copyOfRange(headerSize, plain.size)
        return UnsealedAdPdu(header, payload)
    }
}

/** Unsealed AD-PDU: the reconstructed [header] plus the recovered [payload]. */
internal class UnsealedAdPdu(
    val header: AdPduHeader,
    val payload: ByteArray,
)
