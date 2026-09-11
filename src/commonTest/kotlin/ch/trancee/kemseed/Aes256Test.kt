package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

internal class Aes256Test {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    // FIPS 197 Appendix C.3 — AES-256 known-answer (key 00..1f, pt 001122..ff).
    // Oracle: openssl enc -aes-256-ecb == python cryptography (both agree).
    private val key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val pt = h("00112233445566778899aabbccddeeff")
    private val ct = h("8ea2b7ca516745bfeafc49904b496089")

    @Test
    fun fips197_c3_aes256_encrypt() {
        val got = Aes256.encryptBlock(key, pt)
        assertContentEquals(ct, got, "AES-256-ECB(FIPS C.3) ciphertext must match")
    }

    @Test
    fun aes256_decrypt_roundtrip() {
        // Decrypting the known ciphertext must recover the known plaintext.
        val got = Aes256.decryptBlock(key, ct)
        assertContentEquals(pt, got, "AES-256 decrypt(K, encrypt(K, m)) must equal m")
    }

    @Test
    fun aes256_encrypt_decrypt_inverse() {
        val r = Aes256.encryptBlock(key, pt)
        assertContentEquals(pt, Aes256.decryptBlock(key, r), "encrypt then decrypt must be identity")
        assertEquals(Aes256.BLOCK_SIZE, r.size)
    }
}
