# Grill: Review airborne KEM binding & GMAC key-replacement resistance (crypto design)

Status: resolved — DECIDED **E1′** (ephemeral↔ephemeral X25519, 2 flights × 60 B, **true PFS**). Owner decision 2026-09-11: **allow X25519** — explicitly reverses the packet-5 preference ("X25519 not needed under E2" / "do not revert to E1′"). Expert packet 6 confirmed pure E2 is non-PFS (*"the claim that PFS was fully preserved was overstated on this point"*), making E1′ the only ≤60 B true-PFS option. No new *long-term* key (X25519 keys are ephemeral, erased post-session). Expert sign-off **packet 6, 2026-09-11** (authoritative; supersedes packets 1–5). `Blocked by: (none)`.

> Historical note: this ticket was framed around "CSIDH-as-KEM" (the original PROMPT "Architecture B" used CSIDH-512 over the air). CSIDH-over-air was ruled infeasible by #10 (>200 ms Pure-Kotlin; and CSIDH-512 offers only ~64-bit quantum). The airborne KEM is now ML-KEM-512-local, and the *airborne seed* is an **ephemeral X25519 public key** (E1′). The original Question block is preserved for traceability but is now answered in the E1′ terms below — the CSIDH framing is superseded.

Type: grilling
Blocked by: (none)

## Question (historical CSIDH framing — superseded; answered in E1′ terms)

Spawned by #06 (Q3) and the non-standard CSIDH framing flagged in #04 (CSIDH is a *non-interactive key exchange*, not a textbook KEM).

1. **Is "CSIDH-as-KEM" valid?** — Moot: CSIDH-over-air is ruled infeasible (#10). The airborne element is now an ephemeral X25519 public key (#11 Resolution); CSIDH is gone from the air.
2. **Key-replacement (Tampering) resistance:** originally asked for the CSIDH 64-byte public key in Packet A. Rephrased for E1′: an **ephemeral** 32-byte X25519 public key (`epk_i`/`epk_r`) now travels on the air. Can an MITM splice/replace `epk`? → **No**, if and only if GMAC covers `epk` (see Resolution).
3. **Packet budget:** originally asked whether binding fits the 244-byte budget. → Yes: 2 flights × 60 B, each single-frame at `ATT_MTU=247` (zero fragmentation).

**Requires crypto-expert review — answered by expert sign-off packet 6 (2026-09-11).**

Sources/context: derives from #06 (Q3) + #04; see `docs/adr/0001` (Pure-Kotlin, zero external deps) and `docs/adr/0002` (E1′ decision).

## Resolution (E1′, packet 6 + owner "allow X25519", 2026-09-11 — authoritative)
- **Airborne element (#11):** two flights, each 60 B:
  `Packet_A1 = ver(1) ‖ nonce_i(8) ‖ sender_id_i(2) ‖ flags(1) ‖ epk_i(32) ‖ GMAC(16)`, AAD1 = `ver ‖ flags ‖ nonce_i ‖ sender_id_i ‖ epk_i`.
  `Packet_A2 = ver(1) ‖ nonce_r(8) ‖ sender_id_r(2) ‖ flags(1) ‖ epk_r(32) ‖ GMAC(16)`, AAD2 = `ver ‖ flags ‖ nonce_r ‖ sender_id_r ‖ epk_r ‖ (A1 fields)` — **transcript-bound** so A2 cannot be spliced onto a different A1 (reflection / splice rejection).
  GMAC key `K_gmac = HKDF-Extract("hmb1-gmac-v1", NetKey)` (pre-shared symmetric signer #06/#15). GCM IV `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00`.
- **Substitution fix (#06 Q3 — the substantive #11 resolution):** because `epk` is airborne, GMAC **covers `epk`** on both flights. An MITM swap of `epk_i`/`epk_r` ⇒ invalid GMAC ⇒ **drop before any X25519-DH or ML-KEM work** (DoS gate intact). Peer identity bound by (a) `sender_id` inside the GMAC AAD, (b) GMAC-verify ⇒ peer holds NetKey. Under E2 (no secret airborne) this was structurally moot — under E1′ it is the central binding check.
- **Derivation (#11 + #13):** `ss = X25519(eph_priv_local, eph_pub_remote)`; reject all-zero `ss` via **constant-time** compare (no branch) → abort, no key derived. `T = SHA3-256("HMB1-TR" ‖ A1 ‖ A2)`; `K_seed = HKDF-Extract(salt=T, IKM = ss ‖ NetKey)`; `(d,z) = SHAKE("HMB1-DZ" ‖ T ‖ K_seed, 64)`; `(pk,sk) = ML-KEM-512.KeyGen(d,z)` (local only); `m = SHAKE("HMB1-EM" ‖ T ‖ K_seed, 32)`; `(K_df, c*) = ML-KEM-512.Encaps_internal(pk, m)`; `c*` discarded; `key_AB/key_BA = HKDF-Expand(K_df, …)`. (See ADR-0002 §Decision for the full chain.)
- **DoS gate (§1.6/#15):** GMAC(A1) ⇒ GMAC(A2; transcript) ⇒ X25519 ⇒ ML-KEM — **GMAC before X25519 before ML-KEM**, every flight. Caps ≤1 pending per `sender_id`, ≤2 global, 30 s TTL+LRU, freed on completion.
- **CT posture (§5.2):** X25519 Montgomery ladder in **Pure-Kotlin, constant-time, reusing the #10 spike's verified radix-2^26 GF(2^255−19) field** (`p = 2^255−19` = the Curve25519 prime — the #10 CSIDH spike is repurposed, not wasted): `feMul`/`feSqr`/`feReduce` bit-exact vs `BigInteger`; clamp + `csel`-based branchless ladder; all-zero-`ss` CT abort. Plus AES-256-GMAC const-time tag compare + SHAKE input construction + branchless ML-KEM-512 field ops (Kyber-reference discipline). No native on the default handshake path (native only at-rest #17).
- **Key-reuse (#5.1 / §5.1):** reusing the single NetKey (signer + DoS-gate + `K_gmac` + `K_seed` root) domain-separated by HKDF labels + GCM-IV `dir` + AAD structure is **ACCEPTED under E1′** — no new long-term key is added (X25519 is ephemeral/erased). Packet-5 §1.e `sk_static` reuse discussion: moot (no static X25519 identity; the responder's ephemeral is also erased ⇒ PFS, unlike E1-static).
- **PFS — ACHIEVED (integrity flag CLOSED, not certified-via-label):** `ss` is an erased, non-NetKey-derivable X25519 shared secret; `K_seed = f(ss, NetKey)` ⇒ a future NetKey compromise cannot recompute `ss` ⇒ cannot recompute `K_seed` or any downstream `(d,z)/(pk,sk)/m/K_df`. **True forward secrecy.** (Packet 5's "ephemeral (pk,sk) discarded ⇒ PFS" was the erased-from-device ≠ unreconstructible-from-later-compromised-key error; under E2 it was fatal — under E1′ the irreducible `ss` fixes it.) Code-gen may now assert PFS for E1′ sessions.
- **iOS/native (§5.3):** X25519 now ON path. iOS CryptoKit `Curve25519.KeyAgreement` available since iOS 13 (public, not private — corrects packet-5's "private CryptoKit" error); Android `X25519` API 28+. Spec mandates the Pure-Kotlin CT ladder as the baseline (cross-platform CT guarantee); native fast-path opt-in only if CT-disciplined + tested.

<!-- #11 resolved E1′ (owner "allow X25519", 2026-09-11; expert packet 6 confirmed E2 non-PFS). Frozen into #08. PFS INTEGRITY FLAG CLOSED — PFS achieved via ephemeral↔ephemeral X25519 (ss erased, irreducible by NetKey). #06 substitution closed by GMAC-over-epk (both flights, transcript-bound). -->
