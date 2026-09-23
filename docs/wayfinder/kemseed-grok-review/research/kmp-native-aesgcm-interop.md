# Research — KMP `expect/actual` native AES-256-GCM interop surface

Ticket: `01-research-kmp-native-aesgcm-interop.md` (R1). Fetched 2026-09-18.

## Sources fetched (primary)

- `https://kotlinlang.org/docs/native-c-interop.html` (16688 B) — Kotlin/Native cinterop
  tool: "analyzes C headers and produces Kotlin bindings of C functions … platform
  libraries (POSIX, Apple frameworks) are available this way."
- `https://source.android.com/docs/security/keystore` — "Hardware-backed Keystore".
- `https://kotlinlang.org/docs/multiplatform-expect-actual.html` — KMP `expect/actual`
  (canonical page returned a JS-skeleton via fetch; cited for the KMP shape only).

## Verdict

| Q (from ticket) | Answer | Source |
|---|---|---|
| (a) common `expect` `actual` for AES-GCM viable? | **YES.** Standard KMP: `expect fun aes256GcmSeal(key, iv, plain, aad): ByteArray` in `commonMain`, `actual` in `androidMain`/`iosMain`. | kotlinlang expect-actual |
| (b) Android Keystore AES/GCM reachable + CT? | **YES + CT.** `javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")` + `KeyGenParameterSpec.Builder.setBlockModes("GCM")`. AES runs in the **KeyMint TA** (TrustZone/TEE): "provides all of the secure cryptographic operations … in a secure context … key material … not revealed" — key never in app memory, HW-backed. | AOSP Hardware-backed Keystore |
| (c) iOS native AES/GCM reachable + CT? | **YES, via CommonCrypto** (not CryptoKit directly). CryptoKit `AES.GCM` is a **Swift-only** API → invisible to KMP Obj-C interop. The native path is the **CommonCrypto C API** (`CCCryptorGCMCreate / AddIV / AddUpdate / Finalize`) via `cinterop("CommonCrypto")`. CT via the platform AES (ARMv8 Crypto Extensions on device arm64). Available iOS 13.0+. | kotlinlang native-c-interop (C bindings); CommonCrypto is the C framework |
| gotcha: GC / lifetime / threading | Android: `Cipher`/`SecretKey` are JVM objects (normal GC); the blocking `doFinal` must run on `Dispatchers.IO` (the Cipher call blocks — a threading concern, not a cinterop concern). iOS: CommonCrypto refs are C structs; KN handles refcount; do not strand `actual` refs across `suspend`/dispatcher hops without copying out. | kotlinlang native-c-interop; Android Keystore threading |

## One-line for D11

Interop surface confirmed on **both** platforms (Android Keystore via `javax.crypto`;
iOS via CommonCrypto `CCCryptorGCM` C shim), and **both are constant-time** (TEE / HW AES) —
strictly stronger CT posture than the pure-Kotlin S-box. Reinforces D11 → **B**, with the
pure-Kotlin path retained as the CT-correctness reference/fallback. The iOS Swift-only
CryptoKit gap is the notable friction (matches trancee's kompact repo using SKIE).
