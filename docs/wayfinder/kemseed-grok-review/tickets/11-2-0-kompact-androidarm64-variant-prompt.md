# AI implementation prompt — add kompact `androidNativeArm64` variant (0.1.7 → 0.1.8)

> Hand this to an AI (or run it yourself, trancee — you own `kompact`) working in the
> **`ch.trancee.kompact`** repository. Goal: publish a `kompact` 0.1.8 that kemseed's
> `androidNativeArm64("androidArm64")` target can resolve, unlocking **D11.2** (arm64 HW AES)
> and the future native-Android BLE transport path.

You are working in the `ch.trancee.kompact` repository (the `kompact` runtime + `kompact-ksp`
processor that kemseed consumes). Add an `androidNativeArm64` (Kotlin/Native arm64) target
variant.

## Why (exact consumer failure this must fix)

kemseed (`/Users/phil/Projects/kemseed`) adds `androidNativeArm64("androidArm64")` + a
`cinterop("Arm64Crypto")` for `<arm_acle.h>`/`<arm_neon.h>`. Its `:cinteropArm64CryptoAndroidArm64`
task fails:

```
> Could not resolve all files for configuration ':androidArm64CInterop'.
   > Could not resolve ch.trancee.kompact:kompact:0.1.6.
```

because `kompact` 0.1.6 and 0.1.7 publish Gradle module metadata variants for `android` (JVM)
and `iosArm64` only — **no `androidNativeArm64`/`android-arm64-v8a` klib variant**. kemseed's
`commonMain` (`AdPduHeader.kt`, `Hmb1Handshake.kt`) imports `ch.trancee.kompact.annotations`
and `ch.trancee.kompact.runtime`, and KMP compiles commonMain for every target, so the
`androidNativeArm64` target inherits the `kompact` dependency and resolution breaks. This PR
resolves it. (Verified: `kompact-0.1.7.module` declares only `metadata*` + `iosArm64` variants.)

## Scope (two modules in THIS repo)

1. **`kompact` runtime** — add the Native arm64 target + publish its klib/metadata variants.
2. **`kompact-ksp` processor** — accept an `androidArm64` generate-mode and emit a **plain**
   (non-`@JvmInline`) `actual` value class, identical in shape to the existing `ios` mode
   (Kotlin/Native has no `@JvmInline`).

## Constraints

- Toolchain: Kotlin 2.4.20, Gradle 9.7.1, AGP — same versions kemseed pins (avoids KMP
  klib-metadata skew on `iosArm64`/`androidArm64`).
- `kompact` runtime stays **kotlin-stdlib only, zero transitive runtime deps** (ADR-0001
  posture — the single kemseed exception).
- `kompact-ksp` stays compile-time-only (kotlinpoet-jvm); not on the device runtime.
- kompact's `expect`/`actual` value-class API + `KompactRuntime.readBits`/`writeBits` +
  `KompactWriter` + `ScalarType` are unchanged (kemseed's hand-written + generated
  `AdPduHeader` consumes them verbatim — D-signature untouched).
- `androidNativeArm64` emits a **plain** `actual` (mirror of `ios`); do NOT use `@JvmInline`
  (invalid for Kotlin/Native value classes in this line; kompact's existing ios actual is
  plain — match it).
- ARM64 is the only Android Native target needed (BLE runs on arm64 devices; no x86 emulator
  target). Do **not** add `androidNativeX86`/`androidNativeX64`.

## Implementation

### 1. `kompact` runtime build (`build.gradle.kts`)

Add the target alongside the existing ones:

```kotlin
kotlin {
    android()                            // existing — JVM
    iosArm64("ios")                      // existing — Native arm64 (iOS)
    androidNativeArm64("androidArm64")   // NEW — Native arm64 (Android)
    // ... existing source-sets / variants unchanged
}
```

kompact's runtime is pure Kotlin (no cinterop/SIMD), so **no new `.def`** is required — mirror the
`iosArm64` source-set shape. Confirm the `expect` declaration's common source set + any
`actual`s compile against the `androidArm64` target (they should — identical to ios).

### 2. `kompact-ksp` processor mode

The processor is invoked via the `kompact.generate=<mode>` arg; kemseed routes
`kspAndroidMain → jvm`, `kspKotlinIos → ios`. Add a third mode `androidArm64` that reuses the
`ios` code path (plain `actual` value class). Concretely in `KompactSymbolProcessor` /
`ValueClassGenerator`:

```
mode "androidArm64" -> emit actual as a PLAIN value class (no @JvmInline),
                       identical structure to mode "ios".
```

If the existing logic is `if (mode == "jvm") @JvmInline else plain` (i.e. any non-`jvm`
mode is plain), then `"androidArm64"` already falls into the plain branch — in which case
**no generator change is required** and only step 3 + the build routing below are needed.
Confirm by reading `ValueClassGenerator.modeOf(...)` / the mode-switch in `KompactSymbolProcessor`.

### 3. `kompact` build routing (this repo's own KSP tasks, if any)

If `kompact`'s own build runs `kompact-ksp` over in-repo `@KommutModel` symbols, route
`kspKotlinAndroidArm64 → kompact.generate=androidArm64` in the existing
`afterEvaluate { KspAATask... commandLineArgumentProviders }` block (mirror the
`kspKotlinIos → ios` case). If kompact's runtime has no in-repo `@KommutModel` models,
this step is a no-op (kemseed's *consumer-side* routing is covered in Acceptance §2-3).

### 4. Publish + verify (this repo)

- `./gradlew publishToMavenLocal` → inspect `kompact-0.1.8.module` (Maven Local coords),
  confirm it lists variants:
  `androidApiElements`/`androidRuntimeElements` (JVM), `metadata*`, AND
  `androidArm64MainKlib`/`androidArm64MainMetadata` (or the equivalent KMP Native variant names).
- `./gradlew check` → GREEN (kompact's own test suite — `@KommutModel` round-trip goldens +
  `ValueClassGeneratorTest`).
- Bump the kompact version to **0.1.8** in this repo's `gradle/libs.versions.toml` (runtime +
  ksp) + any `mavenVersion`/Gradle `version` references.

## Acceptance (consumer-side proof — run from kemseed AFTER 0.1.8 is on Maven Central)

1. kemseed `gradle/libs.versions.toml`: bump `kompact = "0.1.6"` → `"0.1.8"` (+ `kompactKsp`).
2. kemseed `build.gradle.kts`: add `androidNativeArm64("androidArm64") { … }` with the
   `Arm64Crypto` cinterop, and route `kspKotlinAndroidArm64 → kompact.generate=androidArm64`
   in the existing `afterEvaluate { KspAATask... }` block (mirror `kspKotlinIos→ios`).
3. `./gradlew :cinteropArm64CryptoAndroidArm64 :compileKotlinAndroidArm64` → **GREEN**
   (proves kompact resolution + arm_acle/arm_neon cinterop bind).
4. `./gradlew :testAndroidHostTest :compileKotlinIos :compileKotlinAndroidArm64 spotlessCheck`
   → `BUILD SUCCESSFUL`, 94/94 host tests.
5. The AES-256-ECB block is **R1 device-KAT-pending**: run kemseed's common test suite
   (`Aes256GcmTest` / `GmacTest`, byte-exact FIPS-197 / NIST-GCM KAT) on an arm64 Android
   device with the arm_acle HW actual active. Host arithmetic (GHASH/CTR/tag, D7-pure) stays
   host-gated by the 128-vector GCM Oracle + 20 goldens.

## Exit criteria for this PR

- [ ] `ch.trancee.kompact:kompact:0.1.8` published to Maven Central.
- [ ] `kompact-0.1.8.module` declares `androidArm64` (androidNativeArm64) klib + metadata variants.
- [ ] `kompact-ksp` 0.1.8 accepts `kompact.generate=androidArm64` (plain actual) — or reuses the
      `ios` plain path unchanged.
- [ ] `kompact` repo `:check` is GREEN.
- [ ] (consumer) kemseed `:cinteropArm64CryptoAndroidArm64` resolves and `:compileKotlinAndroidArm64` compiles.
