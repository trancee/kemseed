# R2: Native CLMUL/PMULL availability for GHASH on Kotlin/Native

- **Type:** `research` (AFK — facts the D7 decision waits on)
- **Status:** RESOLVED — found 2026-09-18
- **Blocked by:** (none)
- **Informs:** D7 (GHASH acceleration target), D11 (native fast-path scope)

## Question

Can GHASH's 128-iteration bit-by-bit field multiply be replaced by native
carry-less / polynomial multiply (ARMv8 `PMULL`/`PMULL2` on iOS arm64, x86
`CLMUL` via `<immintrin.h>` on Android x86_64) from Kotlin/Native?

Specifically confirm against primary sources whether:

1. Kotlin/Native exposes `PMULL`/`CLMUL` compiler intrinsics, or whether a C/C++
   interop shim (`cinterop` + `.def`) is required to reach them.
2. A `kotlinx.cinterop`-bound `actual` GHASH can run at native speed and stay
   constant-time, or whether the pure-Kotlin table/Karatsuba fallback is the
   only safe path on iOS arm64 (where CryptoKit has `CCCryptor` but no public
   GHASH primitive).
3. Target coverage: arm64 iPhone (iOS), arm64+x86_64 Android (AGP 9.4.0).

## Deliverable

Findings at `docs/wayfinder/research/clmul-pmull-kmp-native.md`: per-target
intrinsic availability, the cinterop shim shape (snippet), and a go/no-go for a
native GHASH `actual` vs. a pure-Kotlin table multiply.

## Resolution (resolved in chart session — primary source fetched 2026-09-18)

Findings: [`../research/clmul-pmull-kmp-native.md`](../research/clmul-pmull-kmp-native.md).

- Kotlin/Native exposes **no first-class PMULL/CLMUL intrinsics**.
- The Kotlin/Native **cinterop** tool "analyzes C headers … [of] C functions" + exposes
  platform libraries ⇒ native GHASH multiply **reachable via a C interop shim** wrapping the
  compiler intrinsics (`<immintrin.h>` `_mm_clmulepi64_si128` on x86_64; `<arm_neon.h>` /
  `<arm_acle.h>` `__builtin_arm_pmull` on arm64). KN does not auto-vectorize → hand-written
  per-target shim. (Source: `kotlinlang.org/docs/native-c-interop.html`.)
- Per-target: iOS arm64 ✓ (`arm_acle`), Android arm64 ✓ (NDK), Android x86_64 ✓
  (`immintrin`). A single `pmull`/`clmulepi64` instruction is branchless → constant-time.
- **Go/no-go:** **feasible on all targets** via a cinterop C shim, but adds a native C lib +
  `cinterop {}` per target — more surface than a pure-Kotlin table/Karatsuba multiply.
- Leaves D7 (native-shim vs pure-table) as the owner decision; R2 = feasibility confirmed,
  not chosen.
