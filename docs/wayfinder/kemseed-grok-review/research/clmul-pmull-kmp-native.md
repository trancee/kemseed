# Research — native CLMUL/PMULL for GHASH on Kotlin/Native

Ticket: `02-research-clmul-pmull-kmp-native.md` (R2). Fetched 2026-09-18.

## Source fetched (primary)

- `https://kotlinlang.org/docs/native-c-interop.html` — "Kotlin/Native comes with a cinterop
  tool, which you can use to … generate … Kotlin bindings" of "C functions … Pointers and
  arrays … Structs … Enums" and "platform libraries (POSIX, Apple frameworks)."

## Verdict

- Kotlin/Native exposes **no first-class CLMUL/PMUL intrinsics** (no Kotlin intrinsic for
  `_mm_clmulepi64_si128` / `__builtin_arm_pmull` / `vmull_p64`).
- The cinterop tool "analyzes C headers and produces Kotlin bindings of C functions" and
  exposes platform libraries + **any imported C lib via a `.def`**.
  ⇒ **native GHASH multiply is reachable via a small C interop shim**: a C source declaring
  wrappers around the compiler intrinsics (`<immintrin.h>` on x86_64, `<arm_neon.h>`/
  `<arm_acle.h>` `__builtin_arm_pmull` on arm64), imported with a `.def`, called from the
  `actual` GHASH multiply.
- **Per-target feasibility:**
  - iOS arm64 (device): `__builtin_arm_pmull` (`arm_acle.h`) via Clang cinterop. ✓
  - Android arm64: `__builtin_arm_pmull` / `vmull_p64` via NDK toolchain cinterop. ✓
  - Android x86_64: `_mm_clmulepi64_si128` (`immintrin.h`) via NDK cinterop. ✓
- **CT:** a single `pmull`/`clmulepi64` instruction is branchless → constant-time. ✓
- **Gotcha / cost:** KN does not auto-vectorize; the C shim must be hand-written per
  intrinsic and compiled per-target → adds a `cinterop {}` + native lib per target to the
  library module (more surface than a pure-Kotlin table multiply, and another platform
  build dep to maintain).
- **Alternative if the shim is too heavy:** a pure-Kotlin precomputed GHASH
  (4-bit/8-bit Shoup-Montgomery multiplication tables, branchless) — removes the
  128-iteration bit loop while staying single-source; still software but KAT-gated by
  `GmacTest`/`Aes256GcmTest` oracles.

## One-line for D7

Native CLMUL/PMULL is **feasible on all three targets** via a Kotlin/Native cinterop C shim,
constant-time. The decision driver is shim surface/maintenance cost vs. a pure-Kotlin table
multiply — not feasibility.
