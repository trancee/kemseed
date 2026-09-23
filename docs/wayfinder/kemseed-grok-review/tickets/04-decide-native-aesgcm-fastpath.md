# D11: Native AES-256-GCM fast-path strategy

- **Type:** `grilling` / HITL (owner decision)
- **Status:** IN PROGRESS — claimed by: wayfinder-session (grilling)
- **Blocked by:** R1 (interop surface facts)
- **Informs:** D7 (GHASH target — native first vs pure), D5 (cache-timing posture)

## Question

Grok §2/#2 + §3 propose a native `expect/actual` AES-256-GCM fast-path over the
pure-Kotlin software reference. ADR-0002 §5.2 already reserves this slot, but
the *when* is undecided. Pick one:

- **A — Defer.** Keep the pure-Kotlin AES-256 as the *only* path (already
  correct + KAT-gated). Accept the documented cache-timing surface on S-box
  lookups (acknowledged in `Aes256.kt`). Ship Phase-1b first; revisit native
  after the PDV envelope is signed off. Lowest risk; pays the perf cost now.
- **B — Ship `expect/actual` now.** Add an `expect` AES-GCM in `commonMain` with
  `actual` using Android Keystore (`javax.crypto.Cipher`+`KeyGenParameterSpec`)
  on Android and CryptoKit (`AES.GCM`/`SymmetricKey` via kotlinx.cinterop) on
  iOS, with the pure-Kotlin path as the reference/fallback. Matches Grok §3
  + §2/#2 explicitly. Adds a platform module + cinterop surface to the library
  before 1b is frozen.

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
│                  use CommonCrypto CCryptorGCM C shim via cinterop (extra surface; trancee
│                  already uses SKIE, so Swift→KMP interop friction is known).
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
| Surface / maintenance | none (current path) | + platform module, `Cipher`+`KeyGenerator`+`Dispatchers.IO` (Android), CommonCrypto `CCCryptorGCM` C shim (iOS), `-Xexpect-actual-classes` until stable |
| ADR-0001 | n/a | **No exception needed** — native path is `expect/actual` over *platform frameworks* (Keystore/Crypto/CommonCrypto), not a new dep (kompact's own build already uses expect/actual + `-Xexpect-actual-classes`) |
| Test gate | host KATs only | grows: Android `androidTest` (Keystore) + iOS device test (CommonCrypto) — **cannot be host-tested**; native CT must be verified on device |
| Timing | available now | gated on Phase-1b framing (#20) per ADR-0002 §5.2 |

Recommendation (as before, now backed by R1): **B**, but with three riders:
1. Gate on #20 1b framing (don't ship native before the PDV envelope is frozen).
2. iOS uses **CommonCrypto `CCCryptorGCM`** C shim (not CryptoKit Swift API).
3. Expand the test gate to **device tests** for the native path; keep pure-Kotlin as the
   CT-correctness reference (host KATs run on both).

The owner's call (A or B) then unblocks D5, D7, and the iOS-surface sub-branch above.
