# Grill: ML-KEM deterministic self-encapsulation as KDF (crypto design review)

Status: resolved — **SOUND**, with mandatory conditions. Expert sign-off **packet 6, 2026-09-11** (authoritative; supersedes packet 3). Deterministic self-encap-as-`K_df` is sound because the ML-KEM-512 instance is never exposed to a CCA oracle: `c*` is never transmitted, `(pk,sk)` are locally-derived and never leave the device, and `Decaps` runs only on locally-computed `c*` as a test self-check. **Soundness is independent of the #11 airborne KEM choice** — including the E1′ PFS posture (now *achieved*, see §PF).

Type: grilling
Blocked by: 07 → resolved (Q1/Q2 confirmed; #11 airborne binding DECIDED E1′)

## Resolution (E1′, packet 5→6, 2026-09-11)
- **CCA-oracle absence ⇒ soundness:** under E1′, `K_seed = HKDF-Extract(salt=T, ss ‖ NetKey)` where `ss = X25519(eph_priv, eph_pub)` is an **erased, non-on-air, non-NetKey-derivable** secret; `(d,z)` are derived from `K_seed`; `(pk,sk) = ML-KEM-512.KeyGen(d,z)` are local-only and `pk` never appears on the air; `Decaps` is invoked only on the locally-computed `c*` (a test self-check, #08 §6). An attacker therefore has no adaptive decryption oracle → the eprint-2026/1117 "fixed-coin / RNG-leak ⇒ `K_df` recovery" failure class is structurally excluded. Secrecy is an extract-then-expand chain (SP 800-56C shape) over the secret root `K_seed` + bound `m`.
- **Mandatory conditions (soundness, enforced):**
  1. `KeyGen_internal(d,z)` + `Encaps_internal(ek, m)` used **explicitly** — walled behind a dedicated `selfEncapKdf()` that is the **only** caller of `Encaps_internal`; a lint/review gate prevents swapping it with the randomized `Encaps` path.
  2. **`m` is bound — never a constant:** `m = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)` where `T = SHA3-256("HMB1-TR" ‖ Packet_A1 ‖ Packet_A2)`. `T` includes both authenticated frames (GMAC-verified) and `K_seed` carries the erased `ss` ⇒ `m` is bound to the live transcript **and** to the PFS secret; two distinct sessions ⇒ distinct `T` ⇒ distinct `K_seed,m` ⇒ distinct `c*`/`K_df`.
  3. `K_seed` high-entropy (`ss` is 32 bytes of X25519 DH; NetKey is a 32-byte symmetric key — both ≥128 bits).
  4. `(d,z)` never reused across different `K_seed` lines.
- Under E1′, `m`'s inputs are **not all on-air** (K_seed embeds the erased `ss`) — the packet-5/ADR-E2 note "m is public-derived ⇒ fine for soundness, reinforces non-PFS" is therefore **strengthened here**: the same binding that closes #11 (GMAC+transcript) also makes `m` transcript+secret-bound, which is strictly stronger.
- `ML-KEM-512` decapsulation failure rate 2^−138.8 recorded (not on the protocol path — `Decaps` is a test self-check only).

## PFS-integrity-flag — RESOLVED (achieved, not merely documented)
Under E2, deterministic self-encap was **sound but non-PFS** (packet 5/ADR-0002 §5.2): `m`/`(d,z)/(pk,sk)` were deterministic in `K_seed=f(NetKey, public)`, so a later NetKey compromise recomputed every past session. Under **E1′ this is fixed at the root**: `K_seed = HKDF(ss ‖ NetKey)` and `ss` is an erased, non-NetKey-derivable X25519 secret — so the packet-5/ADR-E2 "PFS" error (`ephemeral (pk,sk) discarded ⇒ PFS`) no longer applies, because the irreducibility now comes from `ss` (not from `(pk,sk)` being deterministically re-derivable). **`m` and `(d,z)/(pk,sk)` are now irreducible by NetKey compromise ⇒ true PFS.** `Decaps(sk, c*) == K_df` self-check in tests only (no CCA oracle on the path). Code-gen may assert PFS for E1′ sessions.

## Test-vector recipe (#08 §6) — E1′ composite (deterministic, reproducible both peers)
Fixed: `eph_priv_i`, `eph_priv_r` (RFC 7748 vectors), `NetKey` (32 B), `nonce_i`, `nonce_r`, `sender_id_i`, `sender_id_r`. → assert `ss (RFC 7748 known-answer)`, `T`, `K_seed`, `(d,z) = SHAKE("HMB1-DZ"‖T‖K_seed,64)`, `(pk,sk) = ML-KEM-512.KeyGen_internal(d,z)` (NIST deterministic KAT), `m = SHAKE("HMB1-EM"‖T‖K_seed,32)`, `(K_df, c*) = Encaps_internal(pk, m)`; **assert both peers reproduce identical** `(d,z),(pk,sk),m,K_df,c*`; **assert `Decaps_internal(sk, c*) == K_df`** (tests only). Concrete hex filled by the RFC 7748 + NIST ML-KEM deterministic KAT runs (TDD red→green).

## Follow-ups (documented, not stale TODOs)
- Wire `selfEncapKdf()` as the **only** caller of `Encaps_internal` (lint gate) — #13 condition 1.
- Back-annotate "bound m + no CCA oracle ⇒ soundness" into #08 §6 conformance + the ML-KEM spike; annotate E1′ PFS-achieved into #11/#08/#05.
- **X25519 KAT** (RFC 7748) now a required Tier-1 conformance gate alongside ML-KEM (`ss` carries PFS; must be tested for the all-zero abort path too).

<!-- #13 resolved SOUND (packet 6, 2026-09-11). Deterministic self-encap-as-KDF sound (bound m, selfEncapKdf wall, Decaps self-check); E1′ is TRUE-PFS (PFS-integrity-flag CLOSED — ss erased, irreducible by NetKey; the E2 non-PFS posture no longer applies). -->
