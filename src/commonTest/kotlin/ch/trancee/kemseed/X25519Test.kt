package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/*
 * Phase 0a — X25519 TDD.
 * Red: the stub returns 0^32, so the RFC 7748 known-answer asserts FAIL.
 * Green: real impl (radix-2^26 ladder reusing the #10 verified GF(2^255-19) field).
 */
class X25519Test {
    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // RFC 7748 §5.2 X25519 test vectors (gold standard, 32 bytes each, lowercase hex).
    private val a     = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private val aPub  = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private val b     = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private val bPub  = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private val K     = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    private val base9 = ByteArray(32).apply { this[0] = 9 }
    private val zero  = ByteArray(32)

    @Test
    fun rfc7748AlicePublic() = assertContentEquals(aPub, X25519.scalarMult(a, base9))

    @Test
    fun rfc7748BobPublic() = assertContentEquals(bPub, X25519.scalarMult(b, base9))

    @Test
    fun rfc7748SharedSecret() {
        assertContentEquals(K, X25519.scalarMult(a, bPub))
        assertContentEquals(K, X25519.scalarMult(b, aPub))   // == Bob's view (commutativity)
    }

    @Test
    fun allZeroPointIsAbortSignal() =
        assertTrue(X25519.scalarMult(a, zero).contentEquals(zero),
            "low-order input must yield all-zero so the protocol CT-aborts ss before any ML-KEM (per #08 §3/#11)")
}
