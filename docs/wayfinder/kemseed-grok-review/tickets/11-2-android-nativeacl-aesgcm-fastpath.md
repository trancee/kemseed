# D11.2: Android native AES-256-ECB backend (arm64 AES-ACLE)

- **Type:** `task` — D11=B part 2 (HW backend)
- **Status:** OPEN — device-gated (requires the NDK + `androidNativeArm64`; not on CI yet)
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
