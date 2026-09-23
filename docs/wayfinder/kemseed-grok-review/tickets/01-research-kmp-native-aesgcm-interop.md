# R1: KMP expect/actual interop surface for native AES-256-GCM

- **Type:** `research` (AFK — facts the D11 decision waits on)
- **Status:** RESOLVED — found 2026-09-18
- **Blocked by:** (none)
- **Informs:** D11 ("Native AES-GCM fast-path strategy"), D2 (iOS target dev-ex)

## Question

What is the actual `expect/actual` interop surface for a native AES-256-GCM
fast-path in this KMP library, and what are the constant-time guarantees?

Specifically, confirm against primary sources whether:

1. A common `expect` can declare
   `fun aes256GcmSeal(key: ByteArray, iv: ByteArray, plain: ByteArray, aad: ByteArray): ByteArray`
   with `actual` on `androidMain` calling **Android Keystore** (`javax.crypto.Cipher` +
   `KeyGenerator` w/ `KeyGenParameterSpec.Builder.setBlockModes("GCM")`) and `actual` on
   `iosMain` calling **CryptoKit** (`AES.GCM` / `SealedBox` / `SymmetricKey` via
   `kotlinx.cinterop` `platform.Cryptography`).
2. Each platform impl is constant-time over the key/schedule (Grok §2/#2 cache-timing concern)
   vs. the pure-Kotlin software reference.
3. KMP cinterop gotchas at Kotlin 2.4.20: GC lifetime of the `SymmetricKey`/`Cipher` handles,
   whether the `Cipher` blocking call needs `Dispatchers.Companion`, and kotlinx.cinterop
   stability across targets.

## Deliverable

Write findings to `docs/wayfinder/research/kmp-native-aesgcm-interop.md` with: per-platform
snippet shape, CT verdict (yes/no/with-footnotes), the gotchas list, and a one-line
recommendation for D11 (A vs B).

## Resolution (resolved in chart session — primary sources fetched 2026-09-18)

Findings: [`../research/kmp-native-aesgcm-interop.md`](../research/kmp-native-aesgcm-interop.md).

- **(a)** `expect/actual` AES-GCM: **viable** (standard KMP `expect`/`actual`).
- **(b)** Android Keystore AES/GCM (`javax.crypto.Cipher` + `KeyGenParameterSpec.Builder`):
  reachable + **constant-time** — AES runs in the KeyMint TEE; key never in app memory
  (AOSP "Hardware-backed Keystore").
- **(c)** iOS native AES/GCM: **not** via CryptoKit `AES.GCM` (Swift-only → invisible to KMP
  Obj-C interop) — reachable via **CommonCrypto `CCCryptorGCM` C API** through
  `cinterop("CommonCrypto")`; CT via HW AES on device arm64 (Kotlin native-c-interop confirms
  C-header/platform-library binding).
- **Gotcha:** iOS Swift-only CryptoKit gap; Android blocking `Cipher.doFinal` needs
  `Dispatchers.IO`; KN refcounts C handles (don't strand across `suspend`/dispatcher hops).
- **Verdict:** native path viable + CT-improving on **both** platforms → leans **D11 = B**
  (ship `expect/actual`, pure-Kotlin as CT-correctness reference/fallback). D11 (A vs B) stays
  the owner HITL decision.
- **Note:** vendor doc pages (developer.apple.com / developer.android.com detail pages) are
  JS-rendered and could not be re-fetched as full text; cited sources are the kotlinlang
  native-c-interop doc + AOSP Keystore overview.
