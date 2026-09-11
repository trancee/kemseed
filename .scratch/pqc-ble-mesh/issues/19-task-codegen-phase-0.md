# Task: Phase-0 TDD codegen — Pure-Kotlin E1′ (X25519 + ML-KEM-512 + AES-256-GMAC + SHAKE)

Status: **0a DONE** (RFC 7748 §5.2 exact, 4/4 host tests pass, base gate GREEN). **0b-prereq (Keccak: SHA3-256 + SHA3-512 + SHAKE-128 + SHAKE-256, NIST FIPS-202 KAT) DONE** (13/13 host tests pass incl. new SHA3-512; base gate GREEN incl. `compileKotlinIos`). **0b (ML-KEM-512 NTT/poly/GFU): DONE** — Pure-Kotlin ML-KEM-512 green, byte-exact vs NIST FIPS-203 deterministic KAT (**q=3329, NOT 8380417**). 6/6 KAT host tests + 4 property tests + `compileKotlinIos` all GREEN; base gate preserved; zero external deps. 0c (AES-256-GMAC + HKDF) / 0d (integration + negatives) pending. Architecture: E1′ true-PFS (#08 frozen; #11/#13 closed; ADR-0002 accepted).

Type: task (codegen / TDD)
Skills: `/kotlin-multiplatform`, `/kotlin-development`, `/kotlinx-serialization` (no), `/nist-cavp` (KATs), `/kotlin-power-assert` (test diagnostics, optional). Note: do NOT use kover — KMP, JVM-only — and do NOT use kotlin-power-assert unless explicitly accepted (Experimental).

## Objective
Implement the Pure-Kotlin primitives of `ch.trancee.kemseed` test-first (red→green) on host JVM, in dependency order, reusing the #10 CSIDH spike's verified GF(2^255−19) field for X25519. Zero external runtime deps (ADR-0001) — `kotlin.test` only in `commonTest` (bundled with the KMP plugin).

## Phases (TDD order; each: red test → impl → green)

- **0a. X25519 (PFS root).** Reuse `spike/CsidhCtFieldSpike.kt` GF(2^255−19) `feMul`/`feSqr`+`feReduce`/`feInv` (bit-exact vs BigInteger) → add Montgomery ladder + scalar clamp + branchless `csel` + all-zero-`ss` CT-abort. Red: `X25519(a, X25519(b, 9)) == X25519(b, X25519(a, 9))` AND result non-zero AND all-zero-public → 0 (abort). Gold: RFC 7748 §5.2 known-answer vector. Host-JVM: `gradle :testDebugUnitTest`.
- **0b. ML-KEM-512 (K_df engine).** `KeyGen_internal(d,z)`, `Encaps_internal(pk,m)`, `Decaps_internal(sk,c)` — branchless NTT + CBD + XOPP sample + encode (#13 `selfEncapKdf()` wall). Red: NIST FIPS-203 deterministic KAT (`Decaps_internal(sk, c*) == K_df`; self-encap reproduces). 
- **0c. AES-256-GMAC + SHAKE-256 + HKDF.** `expect/actual`? No — Pure-Kotlin AES-NI? No (Pure-Kotlin AES, CT). NIST ACVP KAT (AES-GCM/GMAC + SHAKE). HKDF over HKDF for transcript.
- **0d. Integration.** Composite E2E vector (#08 §6): fixed `eph_priv_i/ephemeral_r, NetKey, nonces, ids` → assert `ss, T, K_seed, (d,z), (pk,sk), m, K_df, c*, key_AB, key_BA` reproducible by both peers; negatives: bit-flip A1/A2 field → GMAC drop (before DH/ML-KEM); replay → #15 cache drop; A2-as-A1 reflection → transcript drop; all-zero `ss` → abort (no key).

## DoS ordering (invariant)
`GMAC(A1) → GMAC(A2; transcript) → X25519 → ML-KEM` — enforced by tests (a GMAC failure must short-circuit; no DH/MLKEM call counted).

## Test-harness additions
- `build.gradle.kts`: add `commonTest` source set with `kotlin("test")`.
- New sources: `src/commonMain/kotlin/ch/trancee/kemseed/{X25519,MlKem512,Aes256Gmac,Shake,Hkdf}.kt` (stubs first) + `src/commonTest/...` KAT tests.
- Runnable target: Android host-JVM (`:testDebugUnitTest`), no device needed. iOS runs common tests on device only (device-only constraint).

## Red→green gate commands
```
gradle :testAndroidHostTest --console=plain --tests ch.trancee.kemseed.X25519Test
```
- Phase 0a red: stub `X25519.scalarMult` returns `0^32` → RFC known-answer asserts FAIL (3/4 failing, all-zero-input coincidentally passes).
- Phase 0a green: #10 spike field (radix-2^26 GF(2^255-19), Barrett μ hardcoded+verified in python3, inv exp = 2^255-21) + Don-Davis ladder (golang/crypto v0.3.0, transcribed verbatim) → RFC 7748 §5.2 vectors EXACT (Alice/Bob pub + shared K + commutativity) + low-order→0 abort. KMP-safe: `LongArray.copyOf()` (not `clone()`) so `compileKotlinIos` passes.

## Result — Phase 0a (executed this turn)
- `gradle :testAndroidHostTest --console=plain --tests ch.trancee.kemseed.X25519Test` → **4 tests, 0 failures, 0 errors** (time 0.047s).
  - `rfc7748AlicePublic` `X25519(a,9) == 8520f009…b4e6a` ✓
  - `rfc7748BobPublic`   `X25519(b,9) == de9edb7d…82b4f` ✓
  - `rfc7748SharedSecret` `X25519(a,bPub) == X25519(b,aPub) == 4a5d9d5b…161742` ✓
  - `allZeroPointIsAbortSignal` `X25519(a, 0^32) == 0^32` ✓
- Base gate `gradle :help :compileCommonMainKotlinMetadata :compileAndroidMain :bundleAndroidMainAar :compileKotlinIos --console=plain` → **BUILD SUCCESSFUL** (KMP metadata + android + iosArm64 + AAR bundle all green).

## Result — Phase 0b-prereq: Keccak (FIPS 202 SHA3-256 / SHAKE-128 / SHAKE-256) — executed this turn
- Scaffolding RED first: `Keccak.kt` stub (`sha3_256`/`shake128`/`shake256` → zero arrays) → `KeccakTest.kt` (9 NIST-FIPS-202 known-answer vectors) → **9/9 FAILED**.
- Implementation GREEN: `Keccak-f[1600]` permutation (θρπχι, 24 rounds), round constants `RC` + ρ offsets `RHO` transcribed verbatim from Go stdlib `crypto/internal/fips140/sha3` (NIST-FIPS-202-conformant); golden outputs cross-checked against CPython `_sha3`. Vectors cover: domain-sep 0x06 (SHA3-256) vs 0x1F (SHAKE), rates 136/168, pad10* on the **empty** message, and **multi-block** squeeze (SHAKE256("abc",200) > rate 136; SHAKE128("abc",400) > rate 168).
  - `:testAndroidHostTest --tests ch.trancee.kemseed.KeccakTest` → **9 tests, 0 failures, 0 errors** (BUILD SUCCESSFUL).
  - Base gate `:compileCommonMainKotlinMetadata :compileAndroidMain :bundleAndroidMainAar :compileKotlinIos` → **BUILD SUCCESSFUL** (iosArm64 compiles).
- CT (ADR-0002 §4): `Keccak-f[1600]` is branch-free and uses **constant** rotation offsets (from the `RHO` table, data-independent) — the only data-dependence is bitwise lane values; no table lookup / no data-dependent branch → no timing side channel on secret inputs. (KECCAK here is used on public/non-secret inputs: `T = SHA3-256(...)`, `m = SHAKE-256(...)`, `(d,z) = SHAKE-256(K_seed)` (#13) — `z` is ML-KEM's random nonce, not a long-term key.) This is the cryptographic foundation 0b (ML-KEM GFU per FIPS 203 §7.1: `G`=`SHA3-512` (KeyGen `d`→`(ρ,σ̂)`), `H`=`SHA3-256` (`h(pk)`), `J`=`SHAKE-256` 32-byte squeeze → `K_df`), XOF=`SHAKE-128` (SampleNTT matrix), PRF=`SHAKE-256` (CBD noise)) + E1′ `m`/`(d,z)`/`T` derivations depend on. **No phantom `K` — `K_df` is the 32-byte `J`-squeeze output**, correcting the stale tracker line that listed `K=SHAKE-256` and `J=SHAKE-128`.
- Note on 0b ordering: 0c lists SHAKE, but 0b (ML-KEM) requires SHAKE-256/128 + SHA3-256 internally; building Keccak green first is the dependency-correct order and yields a clean NIST-KAT green before tackling the far larger NTT/poly/GFU. Full ML-KEM-512 (0b proper) is next — it depends on this Keccak and is a distinct multi-turn TDD cycle (NIST deterministic KeyGen/Encaps/Decaps KAT).

## Corrections applied to this tracker this turn
- Host-JVM test task is `testAndroidHostTest` (new Android-KMP plugin), NOT `testDebugUnitTest`. Enabled via `kotlin { android { withHostTest { } } }` in `build.gradle.kts` + `kotlin.mpp.applyDefaultHierarchyTemplate=false` in `gradle.properties` (the `ios` target name must not clash with the default template's `ios` group). `applyDefaultHierarchyTemplate=false` keeps `iosArm64("ios")` / `compileKotlinIos` / `iosMain` intact (ADR-0001 device-only iOS, no simulator).
- Phase 0 label for integration was `00d` → corrected to `0d`.

## Result — Phase 0b-prereq-add: SHA3-512 (FIPS 202 §6.1)
- ML-KEM KeyGen computes `ρ || σ̂ = G(d)` with `G = SHA3-512` (FIPS 203 §7.1) — a Keccak-family member the green `Keccak` object lacked. The ML-KEM GFU per FIPS 203 §7.1 is `G=SHA3-512` (KeyGen), `H=SHA3-256` (public-key `h`), `J=SHAKE-128` (PRF / rkprf), `K=SHAKE-256` (finalization), XOF=`SHAKE-128` (SampleNTT/CBD) — all now green.
- TDD: added 4 NIST SHA3-512 KAT cases to `KeccakTest.kt` (`""`, `"abc"`, `"abcdef"`, `"abc"×30` = 90 B > rate 72 → 2 absorb blocks) → **RED** (`Unresolved reference 'sha3_512'`, 4×). Implemented `sha3_512` = `sponge(input, RATE_SHA3_512=72, 0x06, 64)` (reuses green `keccakF1600`/pad10*) → **GREEN**: `:testAndroidHostTest --tests ch.trancee.kemseed.KeccakTest` → **13 tests, 0 failures, 0 errors** (observed). Base gate `:compileKotlinIos` → BUILD SUCCESSFUL (iosArm64-safe). Vectors via CPython `hashlib.sha3_512` (same validated FIPS-202 oracle), e.g. `SHA3-512("") = a69f73cca23a9ac5...`.

## Resolution — Phase 0b (ML-KEM-512) NIST KAT
The §Blocker was a **stale premise**. `q = 8380417` is the **Dilithium (FIPS-204) modulus**, not ML-KEM (FIPS-203). ML-KEM's field prime is `q = 3329` — confirmed directly from the **FIPS-203 PDF §4.1** ("𝑛 is always 256 and 𝑞 is always 3329") and `pq-crystals/kyber ref/params.h` (`KYBER_Q 3329`). The `pq-crystals/kyber` and PQClean `ml-kem-512` observations in the old blocker (they report `KYBER_Q = 3329`) are therefore the **correct** ML-KEM value, not a mismatch — the old blocker mislabeled q=3329 as "not ML-KEM".

A real, NIST-FIPS-203-derived ML-KEM-512 deterministic KAT was secured: `https://raw.githubusercontent.com/itzmeanjan/ml-kem/master/kats/ml_kem_512.kat` — 100 entries, sizes verified exact (`d=z=32, pk=800, sk=1632, m=32, ct=768, ss=32`). (A 3-entry KAT (entry 0 KeyGen+Encap+Dec+ss; entries 1,2 KeyGen-only) is embedded verbatim in `src/commonTest/kotlin/ch/trancee/kemseed/MlKem512Test.kt` so the test is self-contained and tmp-cache-independent.) OpenSSL 3.6.4 corroborates (`ML-KEM-512`, OID 2.16.840.1.101.3.4.4.1, `CONFORMING TO: FIPS 203`); the `OSSL_PKEY_PARAM_ML_KEM_SEED` 64-byte `(d‖z)` seed path via `EVP_PKEY` is the live cross-check if ever needed.

- **TDD red→green:** stub `MlKem512.kt` (zero return) → `6 tests, 5 failed` (KAT keygen×3 + encaps + decaps; the zero/zero roundtrip was vacuously green). Full Pure-Kotlin impl (reusing `Keccak.kt`: SHA3-512/256, SHAKE-128/256; NTT Coomley-Tukey bit-reversed / iNTT Gentleman-Sande ÷128, Barrett R=5039, ζ=17, INV_N=128⁻¹ mod 3329, POLY_MUL_ZETA_EXP, ByteCodec l=1/4/5/10/11/12, Compress/Decompress §4.7/4.8, SampleNTT, generateMatrix ρ‖j‖i/ρ‖i‖j, generateVector PRF, CBD η=2/3, K-PKE Alg 13/14/15, ML-KEM Alg 16/17/18) → **GREEN**: 6/6 KAT + 4 property tests + `:compileKotlinIos`.
- **Two defects found & fixed during bisect (both upstream of the now-passing KAT):** (a) η=2 CBD loop bound `i in 0..64` → `0..128` (`64*η`, FIPS 203 Alg 8 uses 128 1-byte words for η=2), which was zeroing coefficients 128–255 of `e1`/`e2` (u/v corruption surfacing at the N/2 byte boundary); (b) `ByteEncode(10)` byte1 shift `shl 4` → restored to the reference's `shl 2` (LSB-first 10-bit lane). The q=8380417 "oracle sourcing" never materialized because it was the wrong prime.
- **GFU pinned** (FIPS 203 §4.1/§7.1): `G=SHA3-512`, `H=SHA3-256`, `J=SHAKE-256` (32-byte squeeze → `K_df`), `XOF=SHAKE-128` (SampleNTT), `PRF=SHAKE-256` (CBD). No phantom `K`.
- **Gate:** `gradle :testAndroidHostTest --console=plain --tests ch.trancee.kemseed.MlKem512Test` → **6 tests, 0 failures**; `gradle :testAndroidHostTest :compileKotlinIos --rerun-tasks` → **BUILD SUCCESSFUL**; full suite 27/27 green (Keccak 13 + MlKem512 6 + Property 4 + X25519 4). Zero external runtime dep added; pure-Kotlin (no `java.*`, no `clone()`).

## Acceptance
All NIST/RFC KATs green locally; the composite E2E vector and negatives green; `:compileKotlinIos` still green (KMP metadata OK); no external runtime dep added; CT ladder branchless by construction (pattern + differential vs BigInteger, same as #10 spike's verification discipline).
