# D11.2: Android native AES-256-ECB backend (arm64 AES-ACLE)

- **Type:** `task` — D11=B part 2 (HW backend)
- **Status:** BLOCKED — architecturally gated this session: adding `androidNativeArm64("androidArm64")`
  fails Gradle dependency resolution for the `:androidArm64CInterop` configuration
  (`Could not resolve ch.trancee.kompact:kompact:0.1.6` — and 0.1.7 has the same gap).
  The kompact-AD-PDU surface (`AdPduHeader.kt` + `Hmb1Handshake.kt`) lives in **commonMain**
  and imports `ch.trancee.kompact.annotations`/`.runtime`; KMP compiles commonMain for **every**
  target, so every target inherits the kompact dependency — and kompact 0.1.6/0.1.7 publish
  **only** `metadata` + `iosArm64` klib variants (no `androidNativeArm64` variant; verified by
  inspecting `kompact-0.1.7.module`). The D11.2 attempt was therefore **reverted to green**
  (`build.gradle.kts` + `src/nativeInterop/` removed). Still requires an arm64 Android device for
  R1 KAT once the blocker clears (see Decision required).
- **Blocked by:** D11 (dispatch seam `b351dc9`); R1 (arm64 AES-ACLE, not Android Keystore);
  **NEW this session: kompact has no `androidNativeArm64` variant + the kompact-AD-PDU layer is
  in `commonMain`** (see Attempt log).
- **Blocked by:** D11 (dispatch seam `b351dc9`); R1 (Android path = arm64 AES-ACLE, **not**
  Android Keystore — per-key keygen/init overhead loses on tiny BLE PDUs).
- **Informs:** D5 (Android native CT posture), D7 (GHASH PMUL/CLMUL shares the native
  arm64 C shim — both use `<arm_acle.h>`/`<arm_neon.h>`).

## Question

Land the Android HW AES backend behind the D11=B seam: an arm64 AES-ACLE single-block C
shim on a new `androidNativeArm64` Kotlin/Native target. The key schedule stays
software (arm64 exposes block-encrypt/decrypt instructions but no AES keygen assist), so
the schedule is expanded once in-software per `Aes256Native` instance and the per-block
encrypt is the HW AES-ACLE instruction.

## Recommendation

Yes, device-gated + NDK:

- Add `androidNativeArm64("androidArm64")` to `kotlin { … }` in `build.gradle.kts`
  (currently the library exposes only the `android()` JVM target).
- `src/androidNativeArm64Main/kotlin/ch/trancee/kemseed/Aes256Native.kt`: the `actual`
  calls into the ACLE C shim (`<arm_acle.h>` `__builtin_arm_aesecb128` over the software
  round keys; the existing `Aes256.keyExpansion` feeds it).
- `src/nativeInterop/cinterop/AesArm64.def` (`headers = arm_acle.h`).
- Test gate (needs an Android device): byte-exactness vs FIPS-197 / NIST-GCM KATs + CT
  smoke. The JVM `androidMain` actual (pure `Aes256Key`) stays the host CT-correctness
  oracle. The new native ARM64 target is **not** added to CI until device tests land.

## Assets

- R1/R2 (arm64 AES-ACLE + PMUL feasibility via cinterop).
- ADR-0002 §5.2.

## Attempt log (2026-09-24 — reverted to green)

**Probe:** added `androidNativeArm64("androidArm64") { compilations.all { cinterops {
create("Arm64Crypto") } } }` + `src/nativeInterop/cinterop/Arm64Crypto.def`
(`headers = arm_acle.h, arm_neon.h`). Ran `:cinteropArm64CryptoAndroidArm64 --rerun-tasks`:

```
> Task :cinteropArm64CryptoAndroidArm64 FAILED
> Could not resolve all files for configuration ':androidArm64CInterop'.
   > Could not resolve ch.trancee.kompact:kompact:0.1.6.
```

**Root cause (confirmed, not a wiring bug):** commonMain depends on kompact
(`import ch.trancee.kompact.annotations` / `.runtime` in `AdPduHeader.kt`, `Hmb1Handshake.kt`;
both in `src/commonMain/...`). KMP compiles commonMain for a Native target's `commonMain`
intermediate, so `androidNativeArm64` pulls `kompact` 0.1.6 — which declares **no
`androidNativeArm64`/`android-arm64-v8a` klib variant** (verified: `kompact-0.1.6.module` and
`kompact-0.1.7.module` list only `metadata*` + `iosArm64` variants; no arm64-native). kompact
0.1.7 (2026-09-17) did **not** add it.

**Green gate after revert:** `:testAndroidHostTest :compileKotlinIos spotlessCheck --rerun-tasks`
→ `BUILD SUCCESSFUL in 26s` (94/94). Repo clean.

## Decision required (owner)

D11.2 cannot ship until one of these resolves. None is a KMP wiring fix I can apply solo:

1. **kompact upstream ships an `androidNativeArm64` variant** (preferred — unblocks D11.2 + the
   future Android-Native BLE transport path with the AD-PDU layer intact). kompact 0.1.7 doesn't
   have it; needs kompact 0.1.8. **Implementation prompt prepared** at
   `docs/wayfinder/kemseed-grok-review/tickets/11-2-0-kompact-androidarm64-variant-prompt.md`
   (hand to an AI working in the `ch.trancee.kompact` repo).
2. **Carve the kompact-AD-PDU layer off `commonMain`** into `androidMain`/`iosMain` (target-scoped)
   so `androidNativeArm64`'s shared commonMain is kompact-free, then add `androidNativeArm64` and
   `exclude group: "ch.trancee.kompact"` from its configs. ⚠️ Architectural: this **breaks** the
   "deterministic cross-platform bit-packing on all targets" rationale in ADR-0003 §"Usage"
   (`AdPduHeader`/`AdPduCrypto` would no longer be shared). Only pursue if the owner accepts
   re-duplicating the PDU encode/decode on androidArm64.
3. **Defer D11.2** (keep the arm64 AES reference below as a DRAFT). The arm64 HW AES block is not
   on the current happy path (the pure `Aes256Key` actual on the JVM `android()` target is
   byte-exact + host-KAT-gated); D11.2 only matters once BLE runs natively on Android arm64.

**Recommendation:** option 1 (kompact variant) or 3 (defer). Do not take option 2 unless the
owner explicitly accepts the ADR-0003 rationale change.

## arm64 AES-256 reference (canonical, UNPORTED — KMP-cinterop-verified)

The AES **block** is HW (arm64 AES-ACLE); the **key schedule** is software. Until the target is
viable, this is the canonical ARMv8-A Cryptography Extensions pattern the owner ports to
KMP cinterop once `arm_acle.h`/`arm_neon.h` bind (note: KMP cinterop's handling of arm_neon
`uint8x16_t` SIMD vector types via `neon_vector_type` attributes is **unverified** on this env
— the cinterop probe never reached symbol binding because kompact resolution failed first):

```c
/* AES-256-ECB single block, ARMv8-A. rk[] = 15 round keys (AES-256 schedule). */
#include <arm_acle.h>   /* __builtin_arm_aes* / AESKLE/AESDKE for the schedule */
#include <arm_neon.h>
static inline void aes256_enc_block(uint8x16_t *state, const uint8x16_t rk[15]) {
    *state = veorq_u8(*state, rk[0]);            /* AddRoundKey */
    for (int r = 1; r < 14; r++) {
        *state = vaeseq_u8(*state, rk[r]);       /* SubBytes+ShiftRows+AddRoundKey      (AES E)  */
        *state = vaesmcq_u8(*state);             /* MixColumns                          (AES MC) */
    }
    *state = vaeseq_u8(*state, rk[14]);          /* final round: no MixColumns */
}
```

- Intrinsics: `AES` (=`vaeseq_u8`, AddRoundKey+SubBytes+ShiftRows), `AESMC` (=`vaesmcq_u8`,
  MixColumns). AES-256 key schedule uses `AESIMC` (=`vaesimcq_u8`) + `ROR`/`EOR`/`RADD` on the
  last 4-byte word with the round `RCON` (no key-gen assist on arm64). The arm64 AES block is
  constant-time in hardware (no S-box table → avoids the ADR-0002 §5.2 cache-timing surface the
  pure path carries).
- R1 gate (once viable): port this to the `Aes256Native` `expect/actual` in
  `src/androidNativeArm64Main/...`, run `:compileKotlinAndroidArm64` (cross-compiles on darwin
  host), then KAT the AES block on an arm64 Android device via the existing `Aes256GcmTest` /
  `GmacTest` common suite (byte-exact FIPS-197 / NIST-GCM KAT through `Aes256Gcm.seal`/`open` +
  `Gmac.gmacTag`). Host matrix (JVM `androidMain` pure actual) stays the CT-correctness oracle on
  the 128-vector GCM Oracle + 20 goldens.
- Canonical refs: ARMv8-A Architecture Reference Manual (DDI 0487C.a) A6.7.2450 (AESE/AESMC);
  ARM infocenter "armv8-a-crypto-examples/aes".

---

## Status update (2026-09-24 — kompact 0.3.0 adopted; D11.2 part-1 foothold GREEN)

Owner directive was "kompact 0.3.0 has been released and should fix your suggestions, check it
out." Checked out and adopted (see ADR-0003 v1.7). **What 0.3.0 resolves + what still blocks:**

### RESOLVED by 0.3.0 (Decision-required #1 — kompact variant)

kompact 0.3.0 publishes the `androidNativeArm64` klib variant → the `Could not resolve kompact:0.1.6`
failure (Attempt log above) is gone. `:cinteropArm64CryptoAndroidArm64` now resolves `-library
…/kompact-androidNativeArm64Main-0.3.0.klib` from the cache; the target ADDS cleanly. The kompact-AD-PDU
`commonMain` dependency (the original blocker root cause) is no longer a resolution error — 0.3.0
ships the arm64-native klib. So owner Decision-required block #1 (kompact variant) is **green-cleared**
by 0.3.0; option 1 (defer to "kompact ships the variant") is satisfied.

### RESOLVED (D11.2 part-1 foothold GREEN): KSP → platform `AdPduHeader` actual = processor classpath bind

The prior "0.3.0 mode→emitter dispatch defect" diagnosis was **wrong**. Root cause: kompact-ksp was
**never loaded** on `kspKotlinAndroidArm64`. The `androidArm64` mode + `generateAndroidArm64Actual`
emitter ARE real (javap: `KompactGenerateMode` = {common,jvm,ios,androidArm64,all};
`ValueClassGenerator.generateAndroidArm64Actual` = real kotlinpoet `FileSpec` emitter —
`buildActual$` / `buildMutableActual` / `requireValidLayout`, non-stub) — they just never ran, because
KMP creates `kspKotlinAndroidArm64ProcessorClasspath` but (no eager `kspAndroidArm64(...)` accessor via
the Kotlin-DSL, mirroring ios per ADR-0003) kemseed never bound kompact-ksp to it → empty processor
classpath → the `kompact.generate=androidArm64` mode arg on `kspKotlinAndroidArm64` was inert → no
`AdPduHeaderGenAndroidArm64.kt` (empty dir) → `:compileKotlinAndroidArm64` failed ("no 'actual'").
**Fix (committed with the foothold):** bind the processor in `build.gradle.kts`'s
`afterEvaluate { dependencies { add("sspKotlinAndroidArm64ProcessorClasspath", libs.kompactKsp) } }`
— the same manual bind that makes iOS codegen work. Now the emitter fires →
`AdPduHeaderGenAndroidArm64.kt` (plain value class, `val` + `copy`, matches the migrated expect) →
`:compileKotlinAndroidArm64` → **BUILD SUCCESSFUL**, 0 generated-actual regressions. (Confirms
`kspKotlinAndroidArm64` is a `KspAATask` and `commandLineArgumentProviders` reaches it via the shared
`withType<KspAATask>` block; the `when(name)` routing is correct — the processor simply wasn't
class-loaded.)

### STILL DEFERRED (D11.2 part-2, device-KAT phase): arm_neon AES-ACLE cinterop binding

The committed foothold ships the **pure** `Aes256Native` actual (`src/androidArm64Main`) — NO cinterop,
NO `Arm64Crypto.def`. The KSP→actual gap above is closed; the *only* remaining blocker is binding the
arm_neon AES intrinsics. With the variant fixed, the cinterop probe (`Arm64Crypto.def` with
`headers = arm_acle.h arm_neon.h`, task `:cinteropArm64CryptoAndroidArm64`) RUNS → `BUILD SUCCESSFUL`,
but the knm is **only 4859 bytes** — it contains the *general* arm_acle intrinsics (`__rbit`/`__clz`/
`__rev`…) and **no** `vaeseq_u8`/`vaesmcq_u8`/`vaesimcq_u8` (AES) or `vmull_p64`/PMULL or the
`uint8x16_t`/`uint64x2_t` vector types. Those are `#ifdef __ARM_FEATURE_CRYPTO`-gated; the NDK
cinterop clang does **not** enable `+crypto`, and the `.def` `compilerOpts = -march=armv8-a+crypto` is
**not** honored by cinterop's header parse (knm unchanged). So the AES-ACLE intrinsics the HW actual
depends on are **not bound** to `platform.Arm64Crypto` — the same "KMP cinterop can't bind the
header's SIMD/crypto declarations" class as iOS D11.1. Follow-up: compile the AES-256 block in a
`.c` with `-march=armv8-a+crypto` + bind one plain C function (sidesteps the `uint8x16_t` gap);
canonical `vaesseq_u8`/… AES-256 reference in §"arm64 AES-256 reference".

### Q&A: "instead of `kspKotlinAndroidArm64` can we just call it `kspKotlinAndroid` like with iOS?"

**No — name conflict.** The KSP task name is `kspKotlin<targetName>`:
- iOS: `iosArm64("ios")` → target name `ios` → `kspKotlinIos`.
- android JVM: the existing AGP `android {}` target (build.gradle.kts §`kotlin { android { namespace;
  compileSdk; minSdk; withHostTest } }`) → its KSP task is `kspAndroidMain` (NOT `kspKotlinAndroid`).
- android arm64 native: `androidNativeArm64("androidArm64")` → target name `androidArm64` → KSP task
  `kspKotlinAndroidArm64`.

To produce `kspKotlinAndroid`, the target would have to be named `android` — but that name is
**already taken** by the AGP android JVM target above (KGP requires unique target names → error). So
`kspKotlinAndroid` is unavailable; the arm64 native target's task is `kspKotlinAndroidArm64` and must
be routed explicitly in the `when(name)` mode block (which is done; the routing is correct but
ineffective because of the 0.3.0 dispatch gap above, not the name).

### Current posture

The arm64 AES-256 intrinsic C-shim (canonical reference, §"arm64 AES-256 reference" above) is
**preserved as a DRAFT**; porting it to a `platform.Arm64Crypto`-consuming `actual` is gated on the
part-2 arm_neon cinterop blocker above (the KSP→actual gap is closed). Recommended follow-up: compile
the AES-256 block in a `.c` with `-march=armv8-a+crypto` + bind one plain C function (sidesteps the
`uint8x16_t` vector-type cinterop gap); the iOS CommonCrypto shim notes live in tickets `11-1`/
`11-2-0`.

**Green gate (D11.2 part-1 foothold, committed this session):**
`:testAndroidHostTest :compileKotlinIos :compileKotlinAndroidArm64 spotlessCheck --rerun-tasks` →
`BUILD SUCCESSFUL` (94 host tests; `AdPduHeaderGenAndroidArm64.kt` emitted; `compileKotlinAndroidArm64`
green). The `androidNativeArm64("androidArm64")` target + the `kspKotlinAndroidArm64ProcessorClasspath`
processor bind + the pure `Aes256Native` `androidArm64Main` actual are **committed green**; only the HW
arm_neon AES-ACLE `actual` + device KAT stay deferred to part-2 (no unproven crypto ships).

---

## D11.2 part-2b design: Aes256Native HW-actual swap (C-shim wired) — DRAFT

### State (committed `23979a7`)
`src/nativeInterop/cinterop/Aes256_arm64.{c,h}` + `Arm64CryptoCShim.def` are committed but
**inert** (not wired into any `cinterops {}` block; `compileKotlinAndroidArm64` still uses the pure
`Aes256Native` actual — `BUILD SUCCESSFUL` green gate intact). This realizes the §"Current posture"
recommended follow-up ("compile the AES-256 block in a `.c` with `-march=armv8-a+crypto` + bind one
plain C function").

### Host-verification of the C-shim (NDK-free)
- `clang -O2 -arch arm64 -march=armv8-a+crypto -S -emit-llvm` → IR `define @aes256_enc1block`
  lowering `vaeseq_u8`/`vaesmcq_u8` to `@llvm.aarch64.crypto.aese`/`aesmc` (real AES-ACLE hardware
  ops, not soft-float).
- `clang --target=aarch64-linux-android21 -march=armv8-a+crypto -c` → 1120-byte `.o`, symbol
  `aes256_enc1block` bound (`nm`/`llvm-nm` absent -> verified via `strings` + IR + `otool`).
- Intrinsic spelling byte-verified (`od`) vs §"arm64 AES-256 reference": `vaeseq_u8` + `vaesmcq_u8`
  — identical, no drift.

### The swap (R1: NOT committed to main until device KAT passes; pure fallback stays live)
```kotlin
// src/androidArm64Main/kotlin/ch/trancee/kemseed/Aes256Native.kt  (part-2b HW, DRAFT)
actual class Aes256Native actual constructor(key: ByteArray) {
    private val sched = Aes256.expandKey(key)      // pure key schedule, host-gated (R1)
    private val rkFlat = sched.roundKeysFlat240()   // 60 words -> 240 bytes (big-endian/word-major)
    actual fun encryptBlock(block: ByteArray, out: ByteArray): Unit =
        platform.Arm64CryptoCShim.aes256_enc1block(rkFlat, block, out)
}
// + on Aes256Key (commonMain, pure): roundKeysFlat240() — flatten IntArray(60) -> 240 bytes,
//   byte order == addRoundKey (Aes256.kt L217-224): w[i] -> (>>24,>>16,>>8,&0xFF), word-major.
```
**Byte-exactness (HW ≡ pure):** `schedule` is `IntArray(60)` = 4*(NR+1) = 15 round keys (240 B).
`addRoundKey` reads `w[wordOff + (i ushr 2)]` big-endian (`(word ushr (3-(i and 3))*8)`) →
rk[r*16+i] = `w[r*4 + i/4]` byte `(3-(i%4))*8`, exactly the FIPS-197 round-key layout the C-shim's
`vld1q_u8(rk + r*16)` consumes. AES state: pure `encryptRounds(target,…)` indexes `target[i]`,
`i = row + 4*col` (NIST column-major, byte 0 = s[0,0]) ≡ arm64 `vld1q_u8` state load order →
identical 14-round transform on identical bytes → identical ciphertext. Device KAT confirms
empirically; host goldens (128-vector GCM Oracle + 20 NIST + 2000 GHASH) pin the pure arithmetic.

### cinterop bind (UNVERIFIED on this host — needs NDK arm64 to run)
`Arm64CryptoCShim.def` uses `cSource = Aes256_arm64.c` + `compilerOpts = -march=armv8-a+crypto`
(cinterop compiles the `.c` into the klib, applying `+crypto` so the AES intrinsics bind). **Caveat
from §"STILL DEFERRED":** the prior `Arm64Crypto.def` probe showed KMP cinterop's **header-parse** did
*not* honor `compilerOpts = -march=armv8-a+crypto` (knm stayed 4859 B, no AES symbols;
`__ARM_FEATURE_CRYPTO` unset). If cinterop's `cSource` compile inherits that same gap, the `.c`
won't resolve `vaesseq_u8` → **fallback:** build `Aes256_arm64.a` with the NDK arm64 clang (`+crypto`)
via a Gradle `cpp`/CMake or `Exec` task, then switch the `.def` to:
`headers = Aes256_arm64.h` + `staticLibraries = Aes256_arm64` + `libraryPaths = <build-dir>`
(decouples the `+crypto` compile from cinterop's header parser entirely). Resolve on an arm64-HW
host before committing the HW `actual`.

### Remaining blockers (this host)
- NDK arm64 absent: `$ANDROID_HOME/ndk` empty; no gradle-managed NDK; the cinterop task cannot run.
- No arm64 Android device / `arm64-v8a` system image: device KAT (2c) pending real HW; the emulator
  is non-viable (no BLE peripheral/advertising, env-dependent `HWCAP_AES`).
