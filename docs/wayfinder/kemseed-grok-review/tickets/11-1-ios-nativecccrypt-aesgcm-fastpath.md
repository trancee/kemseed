# D11.1: iOS native AES-256-ECB backend (CommonCrypto CCCrypt)

- **Type:** `task` — D11=B part 2 (HW backend)
- **Status:** OPEN — device-gated (no iOS device in this CI matrix)
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
- `src/iosMain/.../Aes256Native.kt` (current pure reference actual).
- ADR-0002 §5.2 (native CT + dispatch slot).
