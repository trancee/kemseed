package ch.trancee.kemseed

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

internal class MlKem512PropertyTest {

    /** Build a canonical polynomial (coeffs in [0, Q)) that exercises the full mod-3329 range. */
    private fun canonicalPoly(seed: Int): IntArray {
        val p = IntArray(MlKem512.N)
        for (i in 0 until MlKem512.N) p[i] = ((i * 131) + seed) % MlKem512.Q
        return p
    }

    @Test
    fun ntt_intt_is_identity() {
        val p = canonicalPoly(seed = 97)
        val q = p.copyOf()
        MlKem512.ntt(q, 0)           // forward NTT (in place)
        MlKem512.intt(q, 0)         // inverse NTT (in place) — must restore p
        assertContentEquals(p, q, "intt(ntt(p)) must equal p in Z_q")
    }

    @Test
    fun intt_ntt_is_identity() {
        val p = canonicalPoly(seed = 409)
        val q = p.copyOf()
        MlKem512.intt(q, 0)
        MlKem512.ntt(q, 0)
        assertContentEquals(p, q, "ntt(intt(p)) must equal p in Z_q")
    }

    @Test
    fun byteCodec_roundTrip_for_all_l() {
        // For each field width l used by ML-KEM, Encode then Decode must be the identity
        // (Decode(l=12) reduces mod q, so coeffs are kept < Q; other widths keep coeffs < 2^l).
        for (l in listOf(1, 4, 10, 12)) {
            val poly = IntArray(MlKem512.N)
            for (i in 0 until MlKem512.N) {
                val bound = (1 shl l)
                poly[i] = (i % bound)  // always < 2^l  (and < Q for l = 12 since i < 256 < 3329)
            }
            val encoded = ByteArray(MlKem512.N * l / 8)
            MlKem512.encode(l, poly, 0, encoded, 0)
            val decoded = IntArray(MlKem512.N)
            MlKem512.decode(l, encoded, 0, decoded, 0)
            assertContentEquals(poly, decoded, "ByteEncode/ByteDecode must invert for l=$l")
        }
    }

    @Test
    fun encapsulate_then_decapsulate_on_fresh_keypair() {
        // Strengthening: a non-KAT (random) message must round-trip on a freshly generated
        // keypair. Keccak.shake256 serves as the deterministic PRNG (no external deps).
        val d = Keccak.shake256("mlkem-property-d".repeat(8).encodeToByteArray(), 32)
        val z = Keccak.shake256("mlkem-property-z".repeat(8).encodeToByteArray(), 32)
        val (pk, sk) = MlKem512.keygen(d, z)
        val m = Keccak.shake256("mlkem-property-msg".repeat(8).encodeToByteArray(), 32)
        val (ss, ct) = MlKem512.encapsulate(pk, m)
        val recovered = MlKem512.decapsulate(sk, ct)
        assertContentEquals(ss, recovered, "decapsulate(sk, encaps(pk,m)) must equal ss")
        assertTrue(ss.isNotEmpty() && ct.size == 768, "shared secret and ciphertext have expected lengths")
    }
}
