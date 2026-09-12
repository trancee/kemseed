# ADR-0002: Airborne KEM binding (#11) + Deterministic Self-Encasulation-as-KDF (#13)
<!-- O3 (crypto/protocol decision record) -->

- **Status:** Accepted — ratified by expert sign-off packet 6 (2026-09-11). **Owner decision recorded 2026-09-11: adopt true-PFS E1′ ("allow X25519")**, reversing the packet-5 preference. Closes #11 and #13.
- **Context:** Architecture B local FIPS 203 ML-KEM-512 state engine with a ≤60 B airborne element (#10 retired CSIDH-over-air; #05/#07 re-scoped). Crypto-expert gates #11 (airborne→`K_seed` binding + #06 substitution) and #13 (deterministic self-encap as `K_df`).
- **Deciders:** #06 (symmetric signer), #07 (Architecture B goals incl. PFS), #15 (DoS gate), #17 (at-rest), FIPS 203 (ML-KEM), RFC 7748 (X25519 — now ON-path), RFC 5869 (HKDF), #10 (verified Pure-Kotlin CT field arithmetic).
- **Tags:** O3 (crypto/protocol), E7 (Q1 gate), Q5 (ABI/API), T3 (TDD/conformance).

> This ADR previously recorded an **integrity flag**: packet 5 asserted PFS for E2; packet 6 **confirmed that assertion was overstated** (*"the claim in the previous review that PFS was fully preserved was overstated on this point"*). That flag is now **resolved by design change** — E1′ (ephemeral↔ephemeral X25519) delivers true PFS. The flag is closed, not suppressed.

## Context & Problem

After #10 retired CSIDH-over-air, the airborne element shrank to a ≤60 B seed driving a local FIPS 203 ML-KEM-512 state engine shared by both peers. Two crypto gates blocked the #08 freeze:

- **#11** — what is the airborne element, how does it bind to `K_seed`, and how is the #06 key-replacement (substitution) threat closed once a *public* ephemeral X25519 key travels on the air?
- **#13** — is deterministic ML-KEM self-encapsulation usable as the `K_df` KDF (both peers share `(pk,sk)`; `c*` must never cross the air) — and does it remain sound when `K_seed` is now `ss`-bound?

A security-property gate surfaced during review: #07 asserts PFS, and the expert's packet-5 PFS reasoning for E2 was unsound (§5.2, now historical). **Resolved by switching the airborne element to E1′.**

## Options considered

- **E2 (REJECTED for PFS).** pre-shared `K_seed = f(NetKey, public transcript)` — single-flight 42 B, no X25519, no new long-term key. Structurally simple but **non-PFS**: `K_seed`, `(d,z)`, `(pk,sk)`, `m` are all deterministic in `(NetKey, public)`, so a post-session NetKey compromise recomputes every past session. (Packet 6 confirmed this — *"overstated"*.) Adopted only under E2-only; rejected here.
- **E1′ (CHOSEN).** ephemeral↔ephemeral X25519, 2 flights × 60 B (each ≤60 B, single ATT frame). `ss = X25519(eph_priv, eph_pub)` with both privates erased post-session ⇒ `ss` irreducible by later NetKey compromise ⇒ **true PFS**. GMAC over `epk` (both flights, transcript-bound) closes the #06 substitution attack that E2 avoided structurally by "no secret on air." NetKey (symmetric, #06/#17) carries auth + DoS-gate; X25519 ephemeral carries PFS — **no new long-term asymmetric key** (ephemeral ≠ identity).
- **E1-static (REJECTED).** receiver-static X25519 ⇒ a later static-key compromise breaks all past sessions (no PFS) + needs a provisioned long-term identity key (violates "no new long-term key"). Rejected.
- **Deterministic ML-KEM self-encap as KDF — APPROVED (conditions).** `c*` never transmitted; `(pk,sk)` local-only; `Decaps` on locally-computed `c*` only ⇒ no CCA oracle. Soundness **independent** of the #11 PFS choice. Still mandatory: bound `m`, `selfEncapKdf()` wall-off, test-only `Decaps`.

## Decision

### #11 — E1′ binding (frozen; 2 flights, 60 B each)
`Packet_A1`: `version(1) ‖ nonce_i(8) ‖ sender_id_i(2) ‖ flags(1) ‖ epk_i(32) ‖ GMAC(16)` = 60 B (≤60 B, single ATT_MTU=247 frame).  
`Packet_A2`: `version(1) ‖ nonce_r(8) ‖ sender_id_r(2) ‖ flags(1) ‖ epk_r(32) ‖ GMAC(16)` = 60 B.  
GMAC key `K_gmac = HKDF-Extract("hmb1-gmac-v1", NetKey)` (pre-shared symmetric signer #06/#15). A1 AAD = `version ‖ flags ‖ nonce_i ‖ sender_id_i ‖ epk_i`; A2 AAD = `version ‖ flags ‖ nonce_r ‖ sender_id_r ‖ epk_r ‖ (A1 fields)` — **transcript-bound** so A2 cannot be spliced onto a foreign A1. GCM IV `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00`.

Now a secret-bearing field (`epk`) is airborne ⇒ the #06 substitution attack is **no longer structurally absent** and is closed by **GMAC over `epk`** (an MITM swap of `epk_i`/`epk_r` yields an invalid GMAC ⇒ drop **before any X25519/DH or ML-KEM work**). Peer identity + key possession bound by (a) `sender_id` inside the GMAC AAD, (b) verified GMAC ⇒ peer holds NetKey.

Derivation (E1′, expert/owner-confirmed packet 6):
```
ss      = X25519(eph_priv_local, eph_pub_remote)            // reject all-zero ss (CT, no branch)
T       = SHA3-256("HMB1-TR" ‖ Packet_A1 ‖ Packet_A2)       // transcript of both frames
K_seed  = HKDF-Extract(salt = T, IKM = ss ‖ NetKey)         // ss → PFS; NetKey → auth-binding
(d, z)  = SHAKE-256("HMB1-DZ" ‖ T ‖ K_seed, 64)
(pk,sk) = ML-KEM-512.KeyGen(d, z)                           // local only, never on air
m       = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)             // bound coin
(K_df, c*) = ML-KEM-512.Encaps_internal(pk, m)             // c* NEVER transmitted
key_AB/key_BA = HKDF-Expand(K_df, "HMB1-K-AB"‖sid_i‖sid_r / "HMB1-K-BA"‖sid_i‖sid_r, 32)  // #07 labels
```
Replay: #15 cache `key = dir(1) ‖ nonce(8)`, 2^10 / 30 s TTL+LRU; dup ⇒ GMAC-gate drop before DH/ML-KEM. Pending caps (§1.6/#15): ≤1 per `sender_id`, ≤2 global, 30 s, freed on completion.

### #13 — Deterministic self-encap SOUND, with mandatory conditions
- `KeyGen_internal(d,z)` + `Encaps_internal(ek, m)` used **explicitly**; `Decaps` only on locally-computed `c*` as a **test self-check**.
- `m` **bound** — never a constant — to the transcript: `m = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)` (T = both frames; K_seed shares `ss`). Distinct sessions ⇒ distinct `T,K_seed` ⇒ distinct `m` ⇒ distinct `c*`/`K_df`. Under E1′ `m`'s inputs are not all on-air (K_seed carries the erased `ss`), reinforcing (not weakening) secrecy.
- `selfEncapKdf()` is the **only** caller of `Encaps_internal`; a lint/review gate prevents swapping in the randomized `Encaps` path.
- `(d,z)` never reused across distinct `K_seed` lines. ML-KEM-512 decap failure 2^−138.8 recorded (not on path).

### §5 tensions
- **5.1** Single-key reuse APPROVED under E1′: `NetKey` (32 B, #06 signer + #15 DoS-gate + §3 `K_seed`/`K_gmac` root + transcript auth), domain-separated by HKDF labels + GCM-IV `dir` prefix + AAD structure. **No new key** (X25519 is ephemeral, erased, not an identity). No per-role subkeys (NetKey stays keystore-resident for the #15 bg gate, #17).
- **5.2** CT scope = **X25519 Montgomery ladder (Pure-Kotlin CT, reusing the #10 spike's verified radix-2^26 GF(2^255−19) field — same prime as Curve25519) + AES-256-GMAC tag compare + SHAKE-256 input construction + branchless ML-KEM-512 field ops**. `ss==0` CT abort. (*Corrects the E2 §5.2 note "spike not reused / no X25519 ladder".*)
- **5.3** Handshake path: X25519 now ON path. Pure-Kotlin CT ladder mandated (cross-platform guarantee); native fast-path opt-in only if CT-disciplined + tested. No native on the default path; native only at-rest (#17).

### §4.6 [PFS + PQ — OWNER ACK CLOSED, achieved]
- **PFS: TRUE (achieved).** `ss = X25519(eph_priv, …)` — ephemeral private erased, never on air, **not** a function of NetKey. A future NetKey compromise + recorded A1/A2 cannot recompute `ss` ⇒ cannot recompute `K_seed` ⇒ cannot recover `session key` for past sessions. **Harvest-now-decrypt-later is OUT under the PFS threat model.**
- **PQ:** session-key strength = ML-KEM-512 (~128-bit quantum) via `K_df`; X25519 `ss` contributes PFS only (classical ~128-b). Break requires future-quantum AND NetKey AND reconstruction of erased `ss` (impossible). PQ-PSK optional 32 B pairwise slot (default off); KDF identical.

## Consequences
- **PFS-integrity-flag RESOLVED (not suppressed → fixed by design).** The packet-5/ADR-E2 assertion "PFS preserved" was overstated (packet 6 confirmed). E1′ delivers **true PFS**: `K_seed = HKDF(ss ‖ NetKey)` where `ss` is an erased, non-NetKey-derivable X25519 secret ⇒ `K_seed`, `(d,z)`, `(pk,sk)`, `m`, `K_df` are all irreducible by later NetKey compromise. `Decaps` on locally-computed `c*` only; `c*` never on air ⇒ no CCA oracle.
- **PQ-claim vindicated under E1′.** `K_seed` now mixes the erased `ss`, so a future quantum attacker with the NetKey still cannot re-derive `K_seed` ⇒ `K_df` retains ML-KEM-512 PQ strength. (The packet-5 "ML-KEM input derives from K_seed ⇒ not PQ" caveat does not apply: under E2 it *did* apply — see historical §5.2; under E1′ it does not.)
- **Substitution flaw (#06 Q3) closed.** GMAC over `epk` (transcript-bound across A1/A2) ⇒ MITM cannot splice/replace the on-air ephemeral pub; invalid tag ⇒ drop before any DH/ML-KEM work (DoS gate intact).
- **Residual risks (posture: true PFS + PQ; no open integrity flag):**
  1. Pure-Kotlin X25519 CT ladder (reusing #10's verified GF(2^255−19) field + new ladder/clamp/csel; CT = pattern + differential tests vs `BigInteger`, not runtime).
  2. Deterministic self-encap is non-standard use of FIPS-203's deterministic internal API — walled via `selfEncapKdf()` + lint.
  3. 2-flight latency (negligible vs ≥7.5 ms CI) + DoS surface bounded by caps ≤2 global / 30 s TTL.
- **Platform facts:** iOS CryptoKit `Curve25519.KeyAgreement` public since iOS 13 (not private — corrects packet-5 §5.3 "private CryptoKit X25519" error); Android `X25519` API 28+. No platform crypto on the default handshake path (Pure-Kotlin CT baseline).

## O3 — 0c implementation notes (AES-256-GMAC + HKDF-SHA3-256)

Recorded to pin the bit-order / transcription conventions that bit this review, so
implementers never re-derive them from prose.

### AES-256 block cipher — `Aes256.kt`
- `internal object Aes256 { encryptBlock(key, block): ByteArray }`. Key schedule, S-box/inv-S-box, `RCON` (1-indexed; `RCON[0]=0x00` dummy) match `tiny-AES-c` (256/256) index-for-index; cross-checked against `/opt/homebrew/opt/openssl@3` `enc -aes-256-ecb -nopad` and CPython `cryptography`. KAT: FIPS 197 C.3 (key=`0001…1f`, pt=`00112233…eeff` → ct=`8ea2b7ca516745bfeacf49904b496089`). All CT by construction (table-driven S-box, no data-dependent branches).

### AES-256-GMAC / GHASH — `Gmac.kt`
- `Gmac.gmacTag(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray` with `TAG_SIZE=16`.
- **GHASH field multiply = NIST SP 800-38D Algorithm 2 in *byte-array* form** (the convention this review got wrong once). 16-byte big-endian blocks; byte 0 = leftmost bit = x⁰ in the NIST bit convention. Per iteration: right-shift the 128-bit `v` by x; on carry (rightmost bit of byte 15) XOR reduction `0xE1` into **byte 0 (the top byte)** — `carry = v[15] & 1; v = v >> 1; if carry: v[0] ^= 0xE1`. Bit scan is MSB-first: bit `i` of block `x` = bit `(128 - i)` = `x[i >> 3] >> (7 - (i and 7)) & 1` (i=0 ⇒ byte 0 MSB).
- **Equivalent to the textbook schoolbook multiply** `bitrev(naive_int_mul(bitrev(X), bitrev(Y)))`. Proven on 2000 random `(X, Y)` pairs (0 mismatches) and reproduces 400/400 random AES-GCM vectors (OpenSSL-backed `cryptography.AESGCM`, varied AAD/ciphertext lengths incl. non-block-aligned).
- **GHASH structure = the standard NIST GCM ordering** (fold `pad(aad) ‖ pad(ct) ‖ [len block]`, then `T = Y ⊕ AES-256-ECB(J0)`, J0 = IV‖0x00000001 for 96-bit IV). The earlier "GHASH fails" was a *test-harness/IV bug*, not a multiply/ordering bug: (a) the KAT IV is the contiguous `00..0b` sequence (0x0a0b), **not** `…1011` — the ADR §3 draft text transcribed `0a0b` as `1011`; (b) the harness at times fed *plaintext* into GHASH instead of AES-GCM's *ciphertext* and/or passed a raw 20-byte AAD as one unpadded block instead of `pad(aad)+pad(ct)+[len]`. The golden `b399331ea4d8694509a45ce7316a4450` is the oracle output for IV `0001020304050607 08090a0b`. The protocol GCM IV (ADR-0002 §3: `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00`) is a separate 96-bit value fed as the IV; GMAC is over `epk` (both flights, transcript-bound).
- `Gmac.kt` uses exactly the verified byte-array multiply (`ghashMul` / `ghostBit` / `ghashRightShift1`); `ghashRightShift1` shifts byte 15→0 right by one bit position, `ghashBit` is MSB-first, reduction XORs `0xE1` into byte 0.
- **KAT goldens (OpenSSL-backed `AESGCM(key).encrypt(iv, b"", aad)`):** A1 key=`00…1f`, iv=`000102030405060708090a0b`, aad=`00112233445566778899aabbccddeeff`, tag=`b399331ea4d8694509a45ce7316a4450`; A2 key=`2b7e1516…cf4f`×2, iv=`000000000000000000000001`, aad=`0102…ef 0011…ff`(2 blks), tag=`09442d7731aaaa9eb3dafc0debcd3784`; A3 same key, iv=`…00000002`, aad=empty, tag=`4112e5eaddb044afcc021c361bce94f1`.

### HKDF over HMAC-SHA3-256 — `Hkdf.kt`
- `internal object Hkdf { HASH_SIZE=32, BLOCK_SIZE=136 (SHA3-256 rate); hmac(key,msg); extract(salt,ikm); expand(prk,info,outputLen); extractThenExpand(...) }`. HMAC = RFC 2104 over `Keccak.sha3_256` (FIPS 202, domain sep `0x06`), block size = rate = 136 B. Keys > 136 B are pre-hashed; shorter keys zero-padded to 136; `ipad`=0x36, `opad`=0x5c.
- `extract`: `PRK = HMAC-Hash(salt, IKM)`; a NULL/empty salt is replaced by `HASH_SIZE=32` zero bytes (RFC 5869 §2.2 — note: HMAC with a 32-zero key and a 136-zero block key are identical because HMAC left-pads short keys to the block, so the empty-key and 32-zero-key cases collapse — verify, don't assume).
- `expand`: `T(0)=ε`, `T(i)=HMAC(PRK, T(i-1)‖info‖[i])` with `[i]` a single byte 1..255; `outputLen ≤ 255·HASH_SIZE` else `IllegalArgumentException` (RFC 5869 §2.3).
- **KAT goldens:** RFC 5869 §B Test Cases 1/2/3 fixtures with SHA3-256 as HKDF's hash (inputs cited from RFC 5869; outputs computed by the validated oracle = hand-rolled HKDF ≡ Python `hashlib`+`hmac` and `cryptography.HKDF(SHA3_256)`, byte-for-byte). NB an earlier session summary cited an unrecorded golden `f1d799b5…` (PRK `294584dc…`) whose inputs were never persisted; it matches no RFC 5869 §B SHA3-256 fixture, so it is *not* a reproducible vector — do not use it. The committed `HkdfTest` targets the oracle's actual output on the cited RFC fixtures.

## Notes / follow-ups (documented, not stale TODOs)
- Back-annotate §4.6/§5.3 corrections + the "PFS-achieved under E1′" status into `issues/05`/`issues/16`/`issues/17` so those files don't carry superseded "ML-KEM = non-PQ" / "PFS flag open" claims.
- `#10` Pure-Kotlin CT spike (`CsidhCtFieldSpike.kt`, p=2^255−19) is now **reused** as the X25519 Montgomery-ladder arithmetic base (repurposed, not dead).
- Codegen gates (TDD): **RFC 7748 X25519 KAT** (incl. all-zero-`ss` CT-reject path) + NIST ACVP AES-GCM/SHAKE-256/ML-KEM-512 deterministic KATs + E2E composite vector (#08 §6) + negatives (bit-flip→GMAC drop, replay→cache drop, A2/A1 reflection→transcript drop, all-zero-ss→abort). `Decaps(sk,c*) == K_df` self-check in tests only.
```
