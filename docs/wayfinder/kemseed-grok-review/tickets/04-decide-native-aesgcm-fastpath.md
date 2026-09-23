# D11: Native AES-256-GCM fast-path strategy

- **Type:** `grilling` / HITL (owner decision)
- **Status:** DECIDED + RESOLVED (part 1 shipped `b351dc9`) — owner chose **B**. Part 2
  (HW backends) deferred to device-KAT-gated follow-ups (D11.1 iOS CC / D11.2 Android ACLE).
- **Blocked by:** R1 (interop surface facts — resolved)
- **Informs:** D7 (GHASH target — native first vs pure), D5 (cache-timing posture)

## Question

Grok §2/#2 + §3 propose a native `expect/actual` AES-256-GCM fast-path over the
pure-Kotlin software reference. ADR-0002 §5.2 already reserves this slot, but
the *when* is undecided. Pick one:

- **A — Defer.** Keep the pure-Kotlin AES-256 as the *only* path (already
  correct + KAT-gated). Accept the documented cache-timing surface on S-box
  lookups (acknowledged in `Aes256.kt`). Ship Phase-1b first; revisit native
  after the PDV envelope is signed off. Lowest risk; pays the perf cost now.
- **B — Ship `expect/actual` now.** Add an `expect` AES-256 single-block ECB encrypt
  in `commonMain` (the GCM building block — keystream/H/S blocks, not a native GCM)
  with `actual`s on device targets using **HW AES**: Android arm64 AES-ACLE
  (`<arm_acle.h>`, *not* Android Keystore — per-key keygen/init overhead loses on
  tiny BLE PDUs; needs `androidNativeArm64` + NDK cinterop) and iOS CommonCrypto
  `CCCrypt` AES-256-ECB (`<CommonCrypto/CommonCrypto.h>` cinterop; CryptoKit
  `AES.GCM` is Swift-only, invisible to KMP). The pure-Kotlin reference actual
  backs the host/JVM test matrix and stays the CT-correctness oracle. Matches
  Grok §3 + §2/#2 explicitly. Adds a native target + cinterop surface, gated on
  device KATs (R1).

## Recommendation

**B**, but gated on R1 confirming a clean interop surface + CT guarantees. If R1
reports hard cinterop blockers (GC handle lifetime, blocking-Cipher
dispatchers), fall back to A and park the research as the D7 input.

## Assets

- ADR-0002 §5.2 (crypto-gate `expect/actual` slot, reserved).
- R1 (interop facts — pending).
- #20 §kompact-adoption-path (parallel: hand-roll native, defer kompact).

## Grilling (2026-09-18 — wayfinder work session)

Resolving R1 sharpens D11 to a single owner decision. Design tree rooted at D11:

```
D11 (native fast-path: A vs B)
├── B chosen → D5 cache-timing SATISFIED (native TEE/HW CT > pure S-box)
│              ├── D7 → native PMULL/CLMUL shim (R2: feasible via cinterop, adds a native
│              │         C lib/target) OR native GHASH via CommonCrypto's CCryptorGCM GCM path
│              │         (iOS) — branch of D7.
│              └── iOS surface: CryptoKit AES.GCM is Swift-only (invisible to KMP) → must
│                  use CommonCrypto `CCCrypt` AES-256-ECB C shim via cinterop (extra surface; trancee
│                  already uses SKIE, so Swift→KMP interop friction is known).
│              └── Android surface: NOT Keystore (keygen/init overhead loses on tiny PDUs) →
│                  arm64 AES-ACLE (`<arm_acle.h>`, NDK) single-block C shim on `androidNativeArm64`.
└── A chosen → D5 stays non-CT (pure S-box, cache-timing acknowledged as "reference-only")
               └── D7 → pure-Kotlin GHASH table/Karatsuba multiply (no native lib).
D2 (iosSimulatorArm64) — INDEPENDENT of D11.
D14 (public API) — INDEPENDENT; blocked on #20.
D15 (kompact) — PARALLEL (1b PDV envelope); R3 gate cleared; blocked on #20 1b framing.
```

Concrete trade-off (grounded in R1 + the #1 baseline):

| Axis | A (defer, pure-only) | B (expect/actual now) |
|---|---|---|
| Perf vs pre-#1 | #1 gave ~6× (schedule) + table-GHASH ~4× ⇒ ~24× (still software) | HW AES (arm64 crypto ext / AES-NI) + HW PMUL ⇒ **~10–30× over pure** on device |
| CT | **No** — S-box cache-timing (acknowledged in `Aes256.kt`); reference-only | **Yes** — Android Keystore AES/GCM in KeyMint TEE (key never in app memory, AOSP); iOS CommonCrypto HW AES/PMULL |
| Surface / maintenance | none (current path) | + `androidNativeArm64` target + NDK C shim (`<arm_acle.h>` AES-256-ECB block encrypt; arm64 has no AES keygen assist, so the key schedule stays software/pure), iOS `cinterop("CommonCrypto")` `CCCrypt` shim; `-Xexpect-actual-classes` already on (kompact). |
| ADR-0001 | n/a | **No exception needed** — native path is `expect/actual` over *platform frameworks* (Keystore/Crypto/CommonCrypto), not a new dep (kompact's own build already uses expect/actual + `-Xexpect-actual-classes`) |
| Test gate | host KATs only | grows: Android `androidNativeArm64` NDK device test (arm64 AES-ACLE) + iOS device test (CommonCrypto `CCCrypt`); **cannot be host-tested**; native CT (D5) verified on device — pure-Kotlin reference stays the host oracle |
| Timing | available now | gated on Phase-1b framing (#20) per ADR-0002 §5.2 |

Recommendation (as before, now backed by R1): **B**, but with three riders:
1. Gate on #20 1b framing (don't ship native before the PDV envelope is frozen).
2. iOS uses **CommonCrypto `CCCrypt`** AES-256-ECB C shim (single-block building block, not
   GCM; CryptoKit `AES.GCM` is Swift-only and invisible to KMP).
3. Expand the test gate to **device tests** for the native path; keep pure-Kotlin as the
   CT-correctness reference (host KATs run on both).

The owner's call (A or B) then unblocks D5, D7, and the iOS-surface sub-branch above.

## Resolution (owner: B — 2026-09-18)

**Decision:** B. The native fast-path ships as an `expect/actual` dispatch seam; the
owner green-lit shipping the seam now and deferring verified HW backends to device-gated
work (per R1 — native CT cannot be host-KAT'd).

**Part 1 shipped `b351dc9` (green-gated):**
- `commonMain/Aes256Native.kt` — `expect class Aes256Native(key)` with
  `encryptBlock(block, out)`: single-block AES-256-ECB in-place dispatch point. The GCM
  building blocks (`Aes256Gcm` seal/open/ctrTransform, `Gmac.gcmAuthTag`/`gmacTag` →
  `Hmb1Handshake` signer verify) now call through it instead of `Aes256` directly.
- `androidMain` + `iosMain` actuals — pure-Kotlin reference (`Aes256Key`, T1 in-place):
  byte-exact vs the FIPS-197 / NIST-GCM KATs (host-gated), and the CT-correctness oracle.
  One `Aes256Native` per key, reused across H/S/CTR blocks (schedule cached — ADR-0002 §5.2).

**Part 2 (device-gated, deferred — NOT shipped):**
- D11.1 iOS: `cinterop("CommonCrypto")` `CCCrypt` AES-256-ECB C shim on `iosArm64` (HW
  AES on arm64); needs an iOS device test to green the native CT (D5).
- D11.2 Android: `androidNativeArm64` + NDK `<arm_acle.h>` AES-256-ECB block-encrypt shim
  (key schedule stays software — arm64 has no AES keygen assist); needs an Android device
  test to green the native CT (D5).
- GHASH (D7) HW PMUL/CLMUL shim — R2 confirms feasibility via cinterop; lands alongside
  the AES HW backends in the shared native C shim.

**Unblocks now:** D5 is in a resolved posture (pure reference = non-CT oracle; native CT
verified when part 2 lands). D7 (GHASH accel) stays gated on the D11.1/D11.2 HW backends.
