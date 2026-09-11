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

## Notes / follow-ups (documented, not stale TODOs)
- Back-annotate §4.6/§5.3 corrections + the "PFS-achieved under E1′" status into `issues/05`/`issues/16`/`issues/17` so those files don't carry superseded "ML-KEM = non-PQ" / "PFS flag open" claims.
- `#10` Pure-Kotlin CT spike (`CsidhCtFieldSpike.kt`, p=2^255−19) is now **reused** as the X25519 Montgomery-ladder arithmetic base (repurposed, not dead).
- Codegen gates (TDD): **RFC 7748 X25519 KAT** (incl. all-zero-`ss` CT-reject path) + NIST ACVP AES-GCM/SHAKE-256/ML-KEM-512 deterministic KATs + E2E composite vector (#08 §6) + negatives (bit-flip→GMAC drop, replay→cache drop, A2/A1 reflection→transcript drop, all-zero-ss→abort). `Decaps(sk,c*) == K_df` self-check in tests only.
```
