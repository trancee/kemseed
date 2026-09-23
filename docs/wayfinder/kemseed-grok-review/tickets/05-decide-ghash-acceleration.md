# D7: GHASH acceleration target

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — claimed by: __
- **Blocked by:** D11 (native fast-path strategy must be chosen first)
- **Informs:** none (leaf decision)
- **Follow-up to:** 00 (expanded key schedule — H+S reuse one expansion now)

## Question

GHASH's multiply is a 128-iteration bit-by-bit loop (`Gmac.ghashMul`). After
D11 is decided, pick the GHASH acceleration target:

- **If D11 = A (pure-only):** optimize the pure path — table-based (4-bit/8-bit
  Shoup/Montgomery multiplication tables, ~1024-byte precompute) or
  Karatsuba/Galois-window. KAT-gated (GmacTest + 14 GCM oracles stay byte-exact).
  Still software; still non-CT at S-box level (but GHASH mul itself can be
  branchless).
- **If D11 = B (native ships):** back GHASH with native CLMUL/PMULL
  (arm64 `PMULL[2]` on iOS, x86 `PCLMULQDQ` on Android) via the `expect/actual`
  module + cinterop/Rust shim. Route via R2 (native intrinsics feasibility).
- **If neither** (defer): leave the 128-iter loop; acceptable only because BLE
  PDUs are ≤60 B (one GHASH block-pair per PDU, ~2×128 ops/tag) — quantify in T1
  perf if PDUs grow.

## Recommendation

Decide with D11. If B, take R2's answer; if A-and-still-deferring, park D7 in
the fog until 1b perf budget is measured.

## Assets

- R2 (native CLMUL/PMULL feasibility — pending D11).
- `Gmac.ghashMul` (current 128-iter bit loop).
