# D7: GHASH acceleration target

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — D11=B resolved (`b351dc9` seam shipped); posture set (native-PMUL
  deferred to D11.2, pure-CLMUL interim host-gated).
- **Blocked by:** native-PMUL variant gated on D11.2 (arm64 device backend); pure variant
  is unblocked (host-gated by the 128-vector oracle `73ba737`).
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
- **If D11 = B (native ships):** back GHASH with native PMULL (`arm64 PMULL/E` via
  `<arm_neon.h>` — iOS + Android arm64 are both ARM, so no x86 `PCLMULQDQ`) in the same
  C shim as D11.1/D11.2's AES; exposed as a native `Aes256Native` GHASH backend via
  cinterop (no Rust — R2 confirmed cinterop C-shim feasibility, no third-party deps).
  Device-gated (D5 CT verified on arm64 device; shares the D11.2 NDK target).
- **If neither** (defer): leave the 128-iter loop; acceptable only because BLE
  PDUs are ≤60 B (one GHASH block-pair per PDU, ~2×128 ops/tag) — quantify in T1
  perf if PDUs grow.

## Recommendation

Decide with D11. If B, take R2's answer; if A-and-still-deferring, park D7 in
the fog until 1b perf budget is measured.

## Assets

- R2 (native PMULL/CLMUL feasibility — confirmed; cinterop C shim, no third-party deps).
- `Gmac.ghashMul` (current 128-iter bit loop).
- `Aes256GcmTest.gcm_random_vectors_match_oracle` (128 OpenSSL-backed random vectors;
  green-gates any GHASH/CTR/tag change, `73ba737`).

## Resolution posture (D11=B decided)

- **Native PMULL** → lands with D11.2's arm64-ACLE/PMULL C shim (shared `<arm_acle.h>`/
  `<arm_neon.h>` surface); device-gated (arm64 device KAT + D5 CT).
- **Pure 64-bit-limb CLMUL interim** → host-gated by the 128-vector oracle; byte-exact
  reference + CT-correctness oracle. Only ships on explicit owner green-light (the
  native-PMUL direction is the D11=B default; pure interim is a deferred perf hedge
  iff native backends stay device-blocked). Leave the current 128-iter loop otherwise.
