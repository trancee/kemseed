package ch.trancee.kemseed

/**
 * Pure-Kotlin AES-256 block cipher (FIPS 197). Used by GMAC/GCM (E1′ DoS-gate
 * signer verification, ADR-0002 §5.2). Common source set only — KMP-safe for
 * iosArm64 (no `java.*`, no `clone()`).
 *
 * Structure: key expansion (Nk=8, Nr=14 → 60 words / 15 round keys), forward
 * cipher (SubBytes → ShiftRows → MixColumns → AddRoundKey ×13, then
 * SubBytes → ShiftRows → AddRoundKey) and the FIPS-197 inverse cipher
 * (InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns ×13, then
 * InvShiftRows → InvSubBytes → AddRoundKey). GF(2^8) multiply is the branchless
 * Russian-peasant form (fixed 8 iterations; multipliers are public constants).
 *
 * CT posture: control flow is data-independent (no secret-dependent branches).
 * S-box lookups are secret-indexed table reads (a documented cache-timing
 * surface on JVM/VMs) and are covered by the ADR-0002 §5.2 native CT
 * fast-path opt-in for production device use; the default Pure-Kotlin path is
 * correctness-gated by the FIPS-197 / NIST GCM KATs.
 */
internal object Aes256 {

    internal const val BLOCK_SIZE: Int = 16
    internal const val KEY_SIZE: Int = 32

    private const val NK: Int = 8
    private const val NR: Int = 14

    private val AES_SBOX = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    )
    private val AES_INV_SBOX = intArrayOf(
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    )
    // Rcon[j] for j=1..7 (AES-256 uses j up to 7). Index 0 is a dummy so the
    // array maps directly to the AES Rcon indexing Rcon[i/Nk] (Rcon[1]={01}).
    private val RCON = intArrayOf(
        0x00000000,
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000.toInt(),
        0x1b000000, 0x36000000,
    )

    /** Precompute the AES-256 key schedule (60 words / 15 round keys) for a 32-byte [key].
     *
     * Reusable across many blocks: GCM expands once per (key, iv) and applies it to every
     * CTR keystream block + both the H and S AES blocks, so hoisting the schedule out of
     * the per-block path is the single biggest AES win here (ADR-0002 §5.2 perf note).
     * Correctness-gated by the FIPS-197 KATs in [Aes256Test] — this is the *same*
     * `keyExpansion` math, just computed once and reused. */
    internal fun expandKey(key: ByteArray): Aes256Key {
        require(key.size == KEY_SIZE) { "AES-256 key must be $KEY_SIZE bytes; got ${key.size}" }
        return Aes256Key(keyExpansion(key))
    }

    /** Run the 14 AES encryption rounds, mutating [target] in place. */
    private fun encryptRounds(target: ByteArray, schedule: IntArray) {
        addRoundKey(target, schedule, 0)
        for (r in 1..(NR - 1)) {
            subBytes(target)
            shiftRows(target)
            mixColumns(target)
            addRoundKey(target, schedule, r * 4)
        }
        subBytes(target)
        shiftRows(target)
        addRoundKey(target, schedule, NR * 4)
    }

    /** Encrypt a 16-byte block with a precomputed [Aes256Key.schedule]. Returns 16 bytes. */
    internal fun encryptBlock(block: ByteArray, schedule: IntArray): ByteArray {
        val s = block.copyOf()
        encryptRounds(s, schedule)
        return s
    }

    /** Encrypt into a caller-provided 16-byte [out] (reuse across blocks to avoid a per-
     *  block allocation). [out] may alias [block] (in-place). No allocation on the hot path. */
    internal fun encryptBlock(block: ByteArray, out: ByteArray, schedule: IntArray) {
        block.copyInto(out, 0, 0, BLOCK_SIZE)
        encryptRounds(out, schedule)
    }

    /** Encrypt a single 16-byte block with a raw 32-byte key. Returns 16 bytes.
     *  Convenience for one-shot/KAT use — re-expands the key each call. Hot GCM/CTR paths
     *  must call [expandKey] once and reuse the [Aes256Key] instead. */
    internal fun encryptBlock(key: ByteArray, block: ByteArray): ByteArray = expandKey(key).encryptBlock(block)

    /** Run the 14 AES inverse rounds, mutating [target] in place. */
    private fun decryptRounds(target: ByteArray, schedule: IntArray) {
        // Inverse of final round (SubBytes, ShiftRows, AddRoundKey): self-inverse AddRoundKey, then InvShiftRows, InvSubBytes.
        addRoundKey(target, schedule, NR * 4)
        invShiftRows(target)
        invSubBytes(target)
        // Inverse of inner round (SubBytes, ShiftRows, MixColumns, AddRoundKey(r)):
        // reverse order with each op inverted.
        for (r in (NR - 1) downTo 1) {
            addRoundKey(target, schedule, r * 4)
            invMixColumns(target)
            invShiftRows(target)
            invSubBytes(target)
        }
        // Inverse of initial AddRoundKey(0).
        addRoundKey(target, schedule, 0)
    }

    /** Decrypt a 16-byte block with a precomputed [Aes256Key.schedule]. Returns 16 bytes. */
    internal fun decryptBlock(block: ByteArray, schedule: IntArray): ByteArray {
        val s = block.copyOf()
        decryptRounds(s, schedule)
        return s
    }

    /** Decrypt into a caller-provided 16-byte [out] (reuse across blocks). [out] may alias [block]. */
    internal fun decryptBlock(block: ByteArray, out: ByteArray, schedule: IntArray) {
        block.copyInto(out, 0, 0, BLOCK_SIZE)
        decryptRounds(out, schedule)
    }

    /** Decrypt with a raw 32-byte key (re-expands — one-shot/KAT use only). */
    internal fun decryptBlock(key: ByteArray, block: ByteArray): ByteArray = expandKey(key).decryptBlock(block)

    // ---- GF(2^8) over x^8 + x^4 + x^3 + x + 1; branchless (public multiplier) ----
    private fun gmul(a: Int, b: Int): Int {
        var p = 0
        var aa = a
        var bb = b
        repeat(8) {
            p = p xor (aa and -(bb and 1))            // -(x): 0 -> 0x00000000, 1 -> 0xFFFFFFFF
            val carry = aa and 0x80
            aa = ((aa shl 1) and 0xFF) xor ((carry ushr 7) * 0x1B)
            bb = bb ushr 1
        }
        return p
    }

    private fun xtime(a: Int): Int = gmul(a, 2)

    // ---- state is column-major 4x4: byte index = row + 4*col ----
    private fun subBytes(s: ByteArray) {
        for (i in s.indices) s[i] = AES_SBOX[s[i].toInt() and 0xFF].toByte()
    }

    private fun invSubBytes(s: ByteArray) {
        for (i in s.indices) s[i] = AES_INV_SBOX[s[i].toInt() and 0xFF].toByte()
    }

    private fun shiftRows(s: ByteArray) {
        val t = s.copyOf()
        for (r in 0..3) for (c in 0..3) s[r + 4 * c] = t[r + 4 * ((c + r) % 4)]
    }

    private fun invShiftRows(s: ByteArray) {
        val t = s.copyOf()
        for (r in 0..3) for (c in 0..3) s[r + 4 * c] = t[r + 4 * ((c + (4 - r)) % 4)]
    }

    private fun mixColumns(s: ByteArray) {
        for (c in 0..3) {
            val i = 4 * c
            val a0 = s[i].toInt() and 0xFF
            val a1 = s[i + 1].toInt() and 0xFF
            val a2 = s[i + 2].toInt() and 0xFF
            val a3 = s[i + 3].toInt() and 0xFF
            val t0 = xtime(a0); val t1 = xtime(a1); val t2 = xtime(a2); val t3 = xtime(a3)
            s[i] = (t0 xor t1 xor a1 xor a2 xor a3).toByte()            // 2a0 + 3a1 + a2 + a3
            s[i + 1] = (a0 xor t1 xor t2 xor a2 xor a3).toByte()        // a0 + 2a1 + 3a2 + a3
            s[i + 2] = (a0 xor a1 xor t2 xor t3 xor a3).toByte()        // a0 + a1 + 2a2 + 3a3
            s[i + 3] = (t0 xor a0 xor a1 xor a2 xor t3).toByte()        // 3a0 + a1 + a2 + 2a3
        }
    }

    private fun invMixColumns(s: ByteArray) {
        for (c in 0..3) {
            val i = 4 * c
            val a0 = s[i].toInt() and 0xFF
            val a1 = s[i + 1].toInt() and 0xFF
            val a2 = s[i + 2].toInt() and 0xFF
            val a3 = s[i + 3].toInt() and 0xFF
            s[i] = (gmul(a0, 0x0E) xor gmul(a1, 0x0B) xor gmul(a2, 0x0D) xor gmul(a3, 0x09)).toByte()
            s[i + 1] = (gmul(a0, 0x09) xor gmul(a1, 0x0E) xor gmul(a2, 0x0B) xor gmul(a3, 0x0D)).toByte()
            s[i + 2] = (gmul(a0, 0x0D) xor gmul(a1, 0x09) xor gmul(a2, 0x0E) xor gmul(a3, 0x0B)).toByte()
            s[i + 3] = (gmul(a0, 0x0B) xor gmul(a1, 0x0D) xor gmul(a2, 0x09) xor gmul(a3, 0x0E)).toByte()
        }
    }

    private fun addRoundKey(s: ByteArray, w: IntArray, wordOff: Int) {
        for (i in 0..15) {
            val word = w[wordOff + (i ushr 2)]
            val sh = (3 - (i and 3)) * 8
            val kb = (word ushr sh) and 0xFF
            s[i] = (s[i].toInt() xor kb).toByte()
        }
    }

    private fun keyExpansion(key: ByteArray): IntArray {
        val w = IntArray(4 * (NR + 1))
        for (i in 0 until NK) {
            var v = 0
            for (t in 0..3) v = (v shl 8) or (key[4 * i + t].toInt() and 0xFF)
            w[i] = v
        }
        for (i in NK until w.size) {
            var temp = w[i - 1]
            if (i % NK == 0) temp = subWord(rotWord(temp)) xor RCON[i / NK]
            else if (NK > 6 && i % NK == 4) temp = subWord(temp)
            w[i] = w[i - NK] xor temp
        }
        return w
    }

    private fun rotWord(word: Int): Int {
        val b0 = (word ushr 24) and 0xFF
        val b1 = (word ushr 16) and 0xFF
        val b2 = (word ushr 8) and 0xFF
        val b3 = word and 0xFF
        return (b1 shl 24) or (b2 shl 16) or (b3 shl 8) or b0
    }

    private fun subWord(word: Int): Int {
        val b0 = AES_SBOX[(word ushr 24) and 0xFF]
        val b1 = AES_SBOX[(word ushr 16) and 0xFF]
        val b2 = AES_SBOX[(word ushr 8) and 0xFF]
        val b3 = AES_SBOX[word and 0xFF]
        return (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    }
}

/**
 * Pre-expanded AES-256 key schedule (60 words / 15 round keys), reusable across many
 * blocks. Created once via [Aes256.expandKey]; every GCM seal/open reuses a single
 * schedule for the CTR keystream blocks + the GHASH H and S blocks, eliminating the
 * per-block key-expansion that the naive `Aes256.encryptBlock(key, …)` path performs
 * (ADR-0002 §5.2 perf note). A lightweight carrier over the underlying [IntArray]
 * schedule; no boxing beyond the array itself on JVM/iOS.
 */
internal class Aes256Key internal constructor(private val schedule: IntArray) {

    /** Encrypt a 16-byte block using the precomputed schedule (no re-expansion). */
    fun encryptBlock(block: ByteArray): ByteArray = Aes256.encryptBlock(block, schedule)

    /** In-place variant: writes 16 bytes into [out] (reuse one buffer across many blocks
     *  to drop per-block allocations). [out] may alias [block] (in-place). */
    fun encryptBlock(block: ByteArray, out: ByteArray): Unit = Aes256.encryptBlock(block, out, schedule)

    /** Decrypt a 16-byte block using the precomputed schedule (no re-expansion). */
    fun decryptBlock(block: ByteArray): ByteArray = Aes256.decryptBlock(block, schedule)

    /** In-place variant (see [encryptBlock]). */
    fun decryptBlock(block: ByteArray, out: ByteArray): Unit = Aes256.decryptBlock(block, out, schedule)
}
