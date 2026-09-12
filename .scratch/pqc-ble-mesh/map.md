# Wayfinder Map — KEM-Seed Hybrid PQC over BLE Mesh

> Tracked in local markdown (`.scratch/pqc-ble-mesh/issues/<NN>-<slug>.md`).
> Child tickets: see `issues/`. Open tickets are **not** listed here (find them by scan); only closed decisions live in "Decisions so far".

## Destination

Produce `hybrid_pqc_ble_mesh_spec.md`: a single, resolved, implementable specification for a zero-fragmentation hybrid post-quantum secure protocol over BLE mesh — a small airborne seed/nonce (well within the 244-byte non-fragmentation budget at `ATT_MTU = 247`) drives a *local* FIPS 203 ML-KEM-512 state engine (deterministic KeyGen from `SHAKE-256(K_seed,64)`, shared by both peers per #07) → AES-256-GCM authenticated sessions; the airborne KEM-binding is crypto-expert-gated (#11), and deterministic self-encap-as-K_df soundness is #13. **CSIDH-512-over-air is ruled out** (#10: >200 ms at both 512/1024-bit, infeasible in Pure-Kotlin). Suitable for an AI code-generation agent to implement.

## Notes

- **Domain:** Post-Quantum Cryptography over Bluetooth Low Energy (mesh) on iOS & Android mobile devices operating in the background.
- **Stack & dependency constraints (ADR-0001):** Kotlin Multiplatform (KMP) targeting **Android + iOS only**. Zero external dependencies unless strictly approved; Pure-Kotlin fallbacks where native primitives are unavailable (e.g., ML-KEM is not in the platform keystores; X25519 must be a Pure-Kotlin CT ladder — see #05/#10). See `docs/adr/0001-stack-and-dependency-constraints.md`.
- **Skills every session should consult:** `/research` for external facts & primary sources; `/triage` for issue state; `/falcon-fn-dsa` and `/nist-cavp` for crypto conformance; `/kotlin-multiplatform` and `/kotlin-native-apple-interop` if native mobile code is needed.
- **Stacking:** (i) the airborne element is now an **ephemeral X25519 public key** (E1′, true PFS); (ii) the verified #10 CSIDH radix-2^26 GF(2^255−19) field arithmetic is **repurposed** as the X25519 Montgomery-ladder base (same prime); (iii) ML-KEM-512 KeyGen/Encaps runs locally, never on the air.

## Decisions so far

- [Verify CSIDH-512 64-byte public/ciphertext sizes (`issues/01`)](issues/01-research-csidh-key-sizes.md): PROMPT.md's 64-byte sizes are **accurate** (ePrint 2023/793). **Moot** — CSIDH-over-air ruled out #10.
- [Verify FIPS 203 ML-KEM-512 deterministic KeyGen from SHAKE-256(K_seed,64) (`issues/02`)](issues/02-research-fips203-mlkem-keygen.md): **valid** (Federal Register confirms seed regeneration).
- [Verify BLE background ATT_MTU zero-fragmentation (`issues/03`)](issues/03-research-ble-background-mtu.md): **holds** — E1′'s two 60 B frames fit single frames at `ATT_MTU=247`; `requestMtu(247)` mandatory on Android.
- [Survey constant-time CSIDH on ARM (`issues/04`)](issues/04-research-csidh-constant-time.md): CT spiral found — and the **radix-2^26 GF(2^255−19) field is now reused** as the X25519 Montgomery-ladder arithmetic base (#05/#10 spike: bit-exact vs `BigInteger`).
- [Resolve KEM contradiction (`issues/05`)](issues/05-grill-kem-contradiction.md): **Architecture B confirmed** with airborne element = **ephemeral X25519** (E1′); CSIDH-over-air ruled out #10. Security level 128-bit quantum (ML-KEM-512) + 128-bit classical (X25519, ephemeral).
- [Confirm session-layer auth model (`issues/06`)](issues/06-grill-auth-model.md): **symmetric-only** (AES-256-GMAC signer; non-repudiation out of scope, per PROMPT §Repudiation + ADR-0001). Binding correctness → #11. OOB provisioning UX → #12.
- [Clarify ML-KEM state engine & session-key derivation (`issues/07`)](issues/07-grill-mlkem-state-engine.md): Engine = per-session ephemeral (pk,sk) = deterministic KeyGen(SHAKE-256(K_seed,64)) shared by both peers (#02 FIPS 203) → K_df via deterministic self-encaps → HKDF → AES-256-GCM keys (#07 labels). Deterministic Encap-as-KDF soundness → **#13** (crypto-expert). **PFS confirmed under E1′** (ephemeral X25519 `ss` erased, irreducible by NetKey); non-PFS under E2 (rejected, see ADR-0002 §5.2 historical).
- [Scaffold repo + library name (`issues/09`)](issues/09-task-scaffold-repo.md): **Scaffold complete & verified; library module renamed to `kemseed`.** Single-project Gradle, package + AGP namespace `ch.trancee.kemseed`. KMP `android` + `iosArm64("ios")` device-only (no iOS simulator). Zero runtime deps. Build green (Gradle 9.7.1 / Kotlin 2.4.10 / AGP 9.4.0 / Xcode 26.6).
- [Pure-Kotlin CSIDH feasibility spike (`issues/10`)](issues/10-prototype-csidh-pure-kotlin-spike.md): **CSIDH-over-air INFEASIBLE (latency)** — but the **radix-2^26 GF(2^255−19) CT field is reused for X25519** under E1′ (p = 2^255−19 = Curve25519 base field). Spike repurposed, not discarded.
- [Research: BLE mesh routing (`issues/14`)](issues/14-research-ble-mesh-routing.md): **RESOLVED — p2p GATT connection-graph relay.**
- [Research: DoS pre-validation before ML-KEM (`issues/15`)](issues/15-research-dos-prevalidation.md): **RESOLVED — GMAC-before-X25519-before-ML-KEM, caps ≤1/sender_id + ≤2 global, 30s TTL.**
- [Research: iOS background constraints (`issues/16`)](issues/16-research-ios-background-peripheral.md): **RESOLVED — iOS relays over pre-existing links only.**
- [Research: OOB provisioning feasibility (`issues/17`)](issues/17-research-oob-provisioning.md): **RESOLVED — envelope closed; mechanism choice → #12 (HITL).**
- [Grill: choose OOB mechanism (`issues/12`)](issues/12-grill-oob-provisioning.md): **RESOLVED — library channel-agnostic; `OobProvisioner` injected; no in-library UI.**
- [Decide airborne KEM binding (#11)](issues/11-grill-csidh-kem-binding.md): **DECIDED E1′** (ephemeral↔ephemeral X25519, 2 flights × 60 B, **true PFS**) — owner "allow X25519" (2026-09-11) reversing packet-5; expert packet-6 confirmed E2 non-PFS. GMAC over `epk` (both flights, transcript-bound) closes the #06 substitution attack. **[PFS-integrity-flag CLOSED — PFS achieved via erased, non-NetKey-derivable `ss`.]**
- [Validate deterministic self-encap-as-K_df (#13)](issues/13-grill-mlkem-deterministic-encap-kdf.md): **DECIDED SOUND** (`selfEncapKdf()` wall; bound `m` over transcript+T+K_seed; `Decaps` self-check only); **PFS achieved under E1′** (ss irreducible by NetKey).

## Frontier (open, unblocked, unclaimed)

All gates resolved: #05, #06, #07, #09, #10, #11, #12, #13, #14, #15, #16, #17 closed. The airborne KEM is **E1′ (ephemeral X25519, true PFS, 2×60 B)**; deterministic self-encap-as-K_df is sound; **PFS is achieved** (flag closed). `#08` is **FROZEN** to E1′ (no `[EXPERT TBD]` except final HKDF direction-label strings pending #07). **Code-gen is the next phase (TDD).**

(Frontier is empty at the design level — #11/#13 resolved & frozen into #08; the only remaining owner action was the PFS posture, now decided: true-PFS E1′.)

## Implementation frontier (Phase-0 codegen, TDD — tracked in `issues/19`)
- **0a X25519: DONE** (red→green; RFC 7748 §5.2 exact, 4/4 host tests; base gate GREEN). Field = #10 spike radix-2^26 GF(2^255−19), ladder = Don-Davis (golang/crypto).
- **0b-preq Keccak (FIPS 202 SHA3-256 + SHA3-512 + SHAKE-128 + SHAKE-256): DONE** (red→green; 13/13 NIST-FIPS-202 known-answer vectors incl. multi-block squeeze + empty-input pad10*; base gate GREEN incl. `compileKotlinIos`). SHA3-512 added as the ML-KEM KeyGen `G = d ↦ (ρ ‖ σ̂)` hash (FIPS 203 §7.1). Foundation for 0b ML-KEM GFU (`G`=SHA3-512, `H`=SHA3-256, `J`=SHAKE-256 (32-byte squeeze → `K_df`), XOF=`SHAKE-128` (SampleNTT), PRF=`SHAKE-256` (CBD noise)) + E1′ `m`/`(d,z)`/`T` derivations. (No phantom `K` — `K_df` is the 32-byte `J`-squeeze output; corrects the stale GFU line that listed `K=SHAKE-256` and `J=SHAKE-128`.) CT by construction (24 fixed rounds, data-independent ρ offsets, no table lookups).
- **0b ML-KEM-512: DONE** — Pure-Kotlin, byte-exact vs NIST FIPS-203 deterministic KAT (q=3329, NOT 8380417). 6/6 KAT + 4 property tests + `compileKotlinIos` GREEN. Defects bisected & fixed: η=2 CBD loop bound (128, not 64 → coeffs 128–255 were zero) and `ByteEncode(10)` byte1 shift restored to reference `shl 2`. Scaffolding + NTT/invNTT/polyvec/CBD/ByteCodec/Compress/GFU impl complete; base gate preserved; zero external deps. KAT from `itzmeanjan/ml-kem` (100 vectors) corroborated by OpenSSL 3.6.4 `ML-KEM-512 CONFORMING TO FIPS 203`.
- **0c AES-256 block + AES-256-GMAC + HKDF-SHA3-256: DONE.** AES-256 block cipher committed (`64bdee3`, FIPS-197 C.3 KAT, 3 tests). GMAC committed (`f5f28e7`): GHASH field multiply per NIST SP 800-38D Alg. 2 (rightshift + `0xE1` reduction into byte 0, MSB-first scan) over `Aes256.encryptBlock` + J0; 3 GMAC goldens (single/two-block AAD, empty AAD) from the OpenSSL-backed `cryptography.AESGCM` oracle + 400 random GCM + 2000-pair GHASH single-mul equivalence; 5 GmacTest tests. HKDF committed (`e291098`): RFC 2104 HMAC-SHA3-256 (block = SHA3-256 rate = 136 B via `Keccak.sha3_256`), HKDF-Extract (NULL salt → HashLen=32 zero bytes, RFC 5869 §2.2), HKDF-Expand (1-byte counter, 255·32 clamp, §2.3); 8 HkdfTest tests over RFC 5869 §B Test Cases 1/2/3 SHA3-256 variants (goldens = hand-rolled ≡ `cryptography.HKDF(SHA3_256)` byte-for-byte). Full gate: `:testAndroidHostTest` **43/43 green** + `:compileKotlinIos` **GREEN**; zero new runtime deps (only `kotlin-stdlib`/`kotlin-test`). GHASH convention + GMAC IV `0a0b` transcription correction + HKDF parameters recorded in ADR-0002 §O3.
- **0d integration E2E + negatives: pending** (composite #08 §6 vector; AES-GMAC/HKDF needed first).

## Downstream (blocked on a resolved / not-yet-run ticket)

- **#08 Prototype: spec draft — FROZEN to E1′ (true PFS).** The frozen `hybrid_pqc_ble_mesh_spec.md` specifies: (1) **transport** = p2p GATT connection-graph relay, ATT_MTU=247, foreground bootstrap, degree ≤5, app-layer seqno+ACK+retransmit (#14); (2) **airborne** = 2 flights × 60 B (`Packet_A1`/`Packet_A2`, ≤60 B each, single frame per #14) carrying ephemeral X25519 pubs `epk_i`/`epk_r`, GMAC-bound (signer = NetKey, #06/#15) over the transcript (§2) — nothing else secret on the air; (3) **shared secret** `ss = X25519(eph_priv, eph_pub)` (all-zero CT-abort), `K_seed = HKDF-Extract(ss ‖ NetKey)` (ss→PFS, NetKey→auth); (4) **DoS gate** = format→nonce cache→GMAC(A1)→GMAC(A2; transcript)→X25519→ML-KEM, caps ≤1/sender_id ≤2 global 30s (#15); (5) **ML-KEM-512 state engine** local (deterministic KeyGen from `SHAKE-256(K_seed,64)`, #02/#07; `m=SHAKE("HMB1-EM"‖T‖K_seed,32)` bound; `Encaps_internal`→K_df, c* discarded); (6) **session** = AES-256-GCM (#07); **PFS achieved** (§4.6); (7) **platform** = iOS relays over pre-existing links / Android seeds+maintains from background (#16); (8) **enrollment** at-rest = iOS Keychain `AfterFirstUnlockThisDeviceOnly` / Android Keystore+StrongBox, atomic rotation (#17). **PFS-integrity-flag CLOSED.** Crypto-expert handoff packet complete → `issues/18`. Remaining `[EXPERT TBD]`: none (only the #07 HKDF direction-label strings).
- **#05/#10 reuse:** the #10 CSIDH spike's verified Pure-Kotlin CT GF(2^255−19) field is the X25519 ladder base — repurpose in Phase 0 (Montgomery ladder + clamp + csel) rather than new CT field code.

## Not yet specified

Coarse questions now all ticketed, not fog:
- #11 (airborne binding — **resolved E1′, true PFS**), #13 (deterministic self-encap-as-K_df — **resolved SOUND, PFS achieved**), #08 (spec details — **frozen E1′**; HKDF direction-label strings pending #07). **No unscheduled fog remains.**

## Out of scope

Work ruled beyond this effort:
- Architecture A — custom small-LWE + Falcon-512 (PROMPT §1–3). Superseded.
- Falcon-512 / ML-DSA live asymmetric session signing — rejected (symmetric-only).
- LE Audio / ISO / 2M PHY throughput tuning.
- Full SIG Bluetooth Mesh profile — out of scope (peer-to-peer GATT + optional relay).
