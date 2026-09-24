# D11.1: iOS native AES-256-ECB backend (CommonCrypto CCCrypt)

- **Type:** `task` — D11=B part 2 (HW backend)
- **Status:** OPEN — attempted this session (env blocked on the cinterop binding); the CC shim
  source + the exact cinterop fix are preserved below for the owner to land on an arm64 iOS
  device (R1). The pure-Kotlin reference actual (committed `b351dc9`) stays the host matrix
  CT-correctness oracle; CI/goldens remain green.
- **Blocked by:** D11 (expect/actual seam shipped `b351dc9`); needs an iOS device for KAT + CT
  verification (R1: native AES cannot be host-KAT'd).
- **Informs:** D5 (iOS native CT posture), D7 (GHASH PMUL shares the CommonCrypto cinterop shim).

## Question

Land the iOS HW AES backend behind the D11=B dispatch seam: a CommonCrypto `CCCrypt`
AES-256-ECB single-block C shim via `cinterop("CommonCrypto")` on the `ios`
(`iosArm64`) target. This is the per-block AES primitive — keystream block
`AES(J0+ctr)`, H = `AES(0^16)`, S = `AES(J0)` — that the GCM path calls through
`Aes256Native.encryptBlock(block, out)`. HW AES is used on arm64 devices.

## Recommendation

Yes, but device-gated:

- `src/iosMain/kotlin/ch/trancee/kemseed/Aes256Native.kt`: replace the pure-Kotlin
  reference actual with a `CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCNoPadding, key,
  kCCKeySizeAES256, /*iv*/null, block, out, kCCBlockSizeAES128, &outLen)` single-block ECB
  path. (CryptoKit `AES.GCM` is Swift-only → CommonCrypto `CCCrypt` C shim, per R1.)
- Add `src/nativeInterop/cinterop/CommonCrypto.def` (`headers =
  CommonCrypto/CommonCrypto.h`).
- Test gate (cannot run here — **needs an iOS device**): `compileKotlinIos` + a device
  test asserting byte-exactness vs the FIPS-197 / NIST-GCM KATs through the GCMSealOpen
  round-trip, plus a non-leakage CT smoke (fixed-time block encrypt). The pure-Kotlin
  reference actual (current `iosMain`) stays the CT-correctness oracle on the host matrix.

## Assets

- R1 (iOS surface: `CCCrypt` C shim, not CryptoKit).
- `src/iosMain/.../Aes256Native.kt` (current pure reference actual; committed `b351dc9`).
- ADR-0002 §5.2 (native CT + dispatch slot).

## Attempt log (this session — reverted to green, kept as artifact)

D11.1 was implemented end-to-end this session in the green gate's exact form, then **reverted**
before committing: the CC shim, the `CommonCrypto.def`, and the compilation-scoped cinterop
registration were all wired, but `:cinteropCommonCryptoIos` emitted an **empty** `CommonCrypto`
package in this environment (Kotlin/Native 2.4.20 + Xcode 26.5 / `iPhoneOS26.5.sdk`) —
`cstubs.bc` compiles fine (2016 B of cinterop glue) but the `0_CommonCrypto.knm` is a 45-byte
empty-package stub, so `platform.CommonCrypto.{CCCrypt,CCStatus,…}` is `Unresolved reference`
in `compileKotlinIos`. Per the no-unproven-crypto rule, the uncompilable shim was NOT shipped;
`build.gradle.kts` (plain `iosArm64("ios")`) + `iosMain/Aes256Native.kt` (pure reference) were
`git checkout`-ed back to the committed green baseline, and `CommonCrypto.def` +
`src/nativeInterop/` were removed.
**Gate verified green after revert:** `:testAndroidHostTest :compileKotlinIos spotlessCheck
--rerun-tasks` → `BUILD SUCCESSFUL in 23s` (94 host tests + iOS compile + ktfmt).

## Ready-to-drop CC shim source

`src/iosMain/kotlin/ch/trancee/kemseed/Aes256Native.kt` (overwrite the pure actual in `b351dc9`
with this):

```kotlin
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package ch.trancee.kemseed

import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import platform.CommonCrypto.CCCrypt
import platform.CommonCrypto.CCStatus

actual class Aes256Native actual constructor(key: ByteArray) {
    private val ccKey = key

    actual fun encryptBlock(block: ByteArray, out: ByteArray) {
        block.usePinned { blockPin ->
            out.usePinned { outPin ->
                ccKey.usePinned { keyPin ->
                    memScoped {
                        val dataOutMoved = alloc<ULongVar>()
                        val status: CCStatus = CCCrypt(
                            0, // kCCEncrypt (CCOperation)
                            0, // kCCAlgorithmAES (CCAlgorithm)
                            2, // kCCOptionECBMode (CCOptions: ECB, PKCS7-padding bit clear)
                            keyPin.addressOf(0), Aes256.KEY_SIZE.toULong(), // key, 32 (size_t)
                            null, // iv (unused in ECB)
                            blockPin.addressOf(0), Aes256.BLOCK_SIZE.toULong(), // dataIn, 16 (size_t)
                            outPin.addressOf(0), Aes256.BLOCK_SIZE.toULong(), // dataOut, 16 (size_t)
                            dataOutMoved.ptr // dataOutMoved (size_t *)
                        )
                        // kCCSuccess == 0; CCStatus is int32_t. `status` is a public op
                        // status, not key material — branching on it is CT-safe.
                        require(status == 0) { "CommonCrypto AES-256-ECB failed: $status" }
                    }
                }
            }
        }
    }
}
```

Notes on the literals (re. §anon-enum binding instability found in run 1 — `kCCSuccess` did
not bind while `kCCEncrypt`/`kCCAlgorithmAES`/`kCCOptionNoPadding` did, inconsistently):
`0`=kCCEncrypt, `0`=kCCAlgorithmAES, `options=2`(=`kCCOptionECBMode`, PKCS7-padding bit 0x01
clear) with `iv=null` = AES-256-ECB on one 16-byte block. Single-block ECB ≡ CBC-with-zero-IV
on one block, so this is the exact block AES the GCM/CTR keystream + H + S need. `Aes256.KEY_SIZE`
=32 / `BLOCK_SIZE`=16 (Aes256.kt:23).

## `build.gradle.kts` wiring to re-apply

```kotlin
// Top-level (before `kotlin {`): pin the iOS SDK so libclang resolves the SDK-gated decls.
val iosSdk: String = java.io.ByteArrayOutputStream().use { out ->
    project.exec {
        commandLine("xcrun", "--sdk", "iphoneos", "--show-sdk-path")
        standardOutput = out
        isIgnoreExitValue = true
    }
    out.toString().trim()
}

kotlin {
    // ...
    iosArm64("ios") {
        compilations.all {
            cinterops {
                // CommonCrypto.def: headers = CommonCrypto/CommonCryptor.h  (the specific
                // header that declares CCCrypt/CCStatus/kCCEncrypt; the umbrella parsed empty
                // in this env).
                create("CommonCrypto") {
                    compilerOpts("-isysroot", iosSdk, "-framework", "CommonCrypto")
                }
            }
        }
    }
}
```

## cinterop findings / fix to try on the owner's box

- **Symptom (this env):** `:cinteropCommonCryptoIos` task runs and "succeeds" but emits a 45-byte
  `0_CommonCrypto.knm` (empty `package CommonCrypto`) → `platform.CommonCrypto.*` unresolved in
  `compileKotlinIos`. The `cstubs.bc` (2016 B) is just cinterop's C-glue; `strings cstubs.bc`
  shows **no** `CCCrypt`/`CCStatus`/`CommonCryptor` → the SDK header content did not reach
  libclang's decl extraction (libclang never had the iPhoneOS sysroot on its `-I`/clang args,
  so the `#include <CommonCrypto/…>` in the umbrella resolved to nothing).
- **Two `.def` variants tried:** `headers = CommonCrypto/CommonCrypto.h` (umbrella) and
  `headers = CommonCrypto/CommonCryptor.h` (specific) — both empty knm from a clean
  `:cinteropCommonCryptoIos --rerun-tasks`. The symbols that "resolved in run 1" were a
  **stale** knm from a prior session; a fresh clean regen is empty.
- **Root-cause hypothesis:** KMP 2.4.20 `iosArm64` cinterop passes `-target ios_arm64` but does
  **not** forward the iOS SDK sysroot into libclang here (the `SDKROOT`/`SDK_DIR_iphoneos*` env
  vars present in `--debug` are not picked up by the cinterop clang front-end). Pinning
  `-isysroot <iPhoneOS.sdk>` via `compilerOpts` (above) is the fix to validate.
- **Kotlin-DSL note:** the `val iosSdk` + `project.exec { }` block (top-level build-script) did
  **not** compile in this env ("Unresolved reference 'io'" / `'exec'` at the `val` site) — a
  kotlin-Dsl-script classpath anomaly unrelated to cinterop. Try `import java.io.ByteArrayOutputStream`
  at the top of `build.gradle.kts`, or move the xcrun resolution to a `by lazy { }` / a
  `providers.exec` provider to defer it out of script-compile scope.

## Device-KAT instructions (R1)

Drop the CC shim + the `build.gradle.kts` wiring above, then run the **existing** common suite
on an arm64 iOS device (no new test code needed — the CC AES block is exercised transitively):

1. `./gradlew clean :compileKotlinIos` → must be compile-green (`platform.CommonCrypto` resolves).
2. `./gradlew :testAndroidHostTest` → host matrix stays byte-exact (128-vector OpenSSL GCM Oracle
   `Gcm_random_vectors_match_oracle` + 20 GMAC/GCM goldens + 2000-pair schoolbook cross-check).
   This gates the **surrounding** GHASH/CTR/tag arithmetic (the D7-pure rewrite); the AES block
   itself is not host-KAT-able.
3. On-device: run the `commonTest` suite (`Aes256GcmTest` + `GmacTest`) on an arm64 iOS device
   with the CC shim active → byte-exact FIPS-197 / NIST-GCM KAT round-trip through
   `Aes256Gcm.seal`/`open` + `Gmac.gmacTag`. The CC path must reproduce the host oracle's ct‖tag
   bit-for-bit. This is the only way to close R1 for the AES block.
