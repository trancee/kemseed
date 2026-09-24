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
   future Android-Native BLE transport path with the AD-PDU layer intact). kompact 0.1.7 does
   **not**; track a kompact issue / 0.1.8.
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
