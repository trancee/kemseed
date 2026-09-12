package ch.trancee.kemseed

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (NIST SP 800-38D
 * Algorithms 4 & 5). Produces the symmetric session-protection layer that Phase-1
 * wraps AD PDUs in (E1′ `key_AB`/`key_BA` from `Hmb1Handshake`, #08 §3 Phase D).
 *
 * Layout — `seal` returns `ciphertext ‖ tag` (tag = 16 bytes):
 *   H    = AES-256(key, 0^128)            // hash subkey
 *   J0   = iv ‖ 0x00000001               // 96-bit IV ⇒ single counter block (ADR-0002 §3)
 *   C_i  = P_i ⊕ AES-256(key, Inc32^i(J0))  // counter starts at Inc32(J0), byte[15] LSB
 *   T    = GHASH_H(pad(AAD) ‖ pad(C) ‖ lenBlock) XOR AES-256(key, J0)
 *
 * `open` constant-time-compares the tag (branchless [ctEquals]) *before* returning
 * plaintext, so a forged/mallet tag yields `null` with no length oracle on the
 * plaintext path. GHASH reuse: the field multiply lives once in [Gmac.ghashMul]
 * (byte-checked against 2000 pairs + 400 GCM vectors — see [Gmac]).
 *
 * Pure-Kotlin, commonMain (KMP: android + iosArm64). No `java.*`, no `clone()`.
 * Correctness pinned to the OpenSSL-backed `cryptography.AESGCM` oracle in
 * [Aes256GcmTest] (NIST-style + a large AAD/CT vector cross-checked against
 * `Gmac.gmacTag` for the empty-plaintext case).
 */
internal object Aes256Gcm {

    private const val IV_SIZE: Int = 12
    internal const val TAG_SIZE: Int = Gmac.TAG_SIZE            // 16
    private val EMPTY: ByteArray = ByteArray(0)

    /** Seal: AEAD-encrypt `plain` under (key, iv) with `aad`. Returns `ciphertext ‖ tag`. */
    fun seal(key: ByteArray, iv: ByteArray, plain: ByteArray, aad: ByteArray = EMPTY): ByteArray {
        require(key.size == Aes256.KEY_SIZE) { "GCM key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }
        require(iv.size == IV_SIZE) { "GCM IV must be $IV_SIZE bytes; got ${iv.size}" }

        val j0 = Gmac.j0(iv)
        val ct = ctrTransform(key, j0, plain)              // AES-256-CTR keystream: ct = plain ⊕ AES(Inc32(J0))^…
        val tag = Gmac.gcmAuthTag(key, iv, aad, ct)
        return ct + tag                                     // ciphertext ‖ tag
    }

    /** Open: verify-then-decrypt `ciphertext ‖ tag`. Returns plaintext, or `null` on tag failure (CT). */
    fun open(key: ByteArray, iv: ByteArray, ctAndTag: ByteArray, aad: ByteArray = EMPTY): ByteArray? {
        require(key.size == Aes256.KEY_SIZE) { "GCM key must be ${Aes256.KEY_SIZE} bytes; got ${key.size}" }
        require(iv.size == IV_SIZE) { "GCM IV must be $IV_SIZE bytes; got ${iv.size}" }
        require(ctAndTag.size >= TAG_SIZE) { "GCM ciphertext+tag must be at least $TAG_SIZE bytes; got ${ctAndTag.size}" }

        val tagOff = ctAndTag.size - TAG_SIZE
        val ct = ctAndTag.copyOfRange(0, tagOff)
        val tag = ctAndTag.copyOfRange(tagOff, ctAndTag.size)

        val expect = Gmac.gcmAuthTag(key, iv, aad, ct)
        if (!ctEquals(expect, tag)) return null             // reject BEFORE any plaintext exposure
        return ctrTransform(key, Gmac.j0(iv), ct)           // CTR decrypt == encrypt (keystream XOR)
    }

    /** AES-256-CTR keystream over [src] seeded from J0 (first block = AES(Inc32(J0))).
     *  CTR is a symmetric XOR, so one primitive both encrypts (seal) and decrypts (open). */
    private fun ctrTransform(key: ByteArray, j0: ByteArray, src: ByteArray): ByteArray {
        val out = ByteArray(src.size)
        var ctr = Gmac.inc32(j0)
        var off = 0
        while (off < src.size) {
            val ks = Aes256.encryptBlock(key, ctr)
            val take = minOf(BLOCK_SIZE, src.size - off)
            for (j in 0 until take) out[off + j] = (src[off + j].toInt() xor ks[j].toInt()).toByte()
            ctr = Gmac.inc32(ctr)
            off += take
        }
        return out
    }

    /** Branchless constant-time 16-byte equality (no early return on mismatch). */
    private fun ctEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var acc = 0
        for (i in a.indices) acc = acc or (a[i].toInt() xor b[i].toInt())
        return acc == 0
    }

    private const val BLOCK_SIZE: Int = Aes256.BLOCK_SIZE
}
