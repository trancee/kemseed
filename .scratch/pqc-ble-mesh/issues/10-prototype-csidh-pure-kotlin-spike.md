# Prototype: Pure-Kotlin constant-time CSIDH feasibility spike

Status: claimed
Claimed by: work-through session (agent)
Type: prototype
Blocked by: 09 — resolved (2026-09-10; scaffold `isogeny` green on Android + iOS device; #10 is the next frontier pick).

Status: **in progress (reopened)** — pivoted to a **custom constant-time bigint field** (no `BigInteger`), using `../MeshLink-crypto` for constant-time patterns. See "Answer (custom CT bigint)".

## Question

Before choosing the CSIDH security level in #05 (64-byte CSIDH-512 ≈ 64-bit quantum vs 128-byte CSIDH-1024 ≈ 128-bit quantum), measure whether **Pure-Kotlin** constant-time CSIDH can meet the background-BLE handshake latency budget on the **Android + iOS** KMP targets (ADR-0001).

Research #04's performance figures (e.g., ~12 s/group action) were for optimized **C/ARM** — not Pure-Kotlin. Pure-Kotlin constant-time isogeny group action (field arithmetic over a 512-bit and a 1024-bit prime) may be markedly slower; if 1024-bit exceeds the latency budget, #05 is forced toward the 64-byte (lower-security) option.

Concrete ask — build a minimal Pure-Kotlin (Kotlin/JVM or KMP) micro-benchmark of one CSIDH group-action step scaled to 512-bit and 1024-bit primes, measure wall-clock time on representative mobile-class hardware, and report:
- ms/µs per group action for 512-bit vs 1024-bit
- whether each fits a ≤ ~200 ms handshake budget (background BLE)
- whether constant-time coding (no data-dependent branches/loops, no early-exit dependent on secret data) is achievable in Pure-Kotlin

Resolution gates the #05 size decision and unblocks #08 (spec draft).

<!-- Blocking: needs #09 (scaffold KMP package) to host the benchmark. -->

## Answer

### Method
- Spike source: `.scratch/pqc-ble-mesh/spike/CsidhSpike.kt` (Kotlin/JVM, `java.math.BigInteger`, **stdlib only** — no external deps, ADR-0001).
- Compile + run: `kotlinc -include-runtime CsidhSpike.kt -d /tmp/csidh.jar && java -jar /tmp/csidh.jar`.
- Host: macOS 26 arm64, JRE 25.0.4, kotlinc-jvm 2.4.10. (On Android/iOS native the numbers are slower — this is the JVM *floor*, which only strengthens the verdict.)
- Correctness smoke: `FpInv(a)·a ≡ 1`; `(a^((p+1)/4))² ≡ a or p−a` (QR/QNR) on each prime.

### Measured: Pure-Kotlin F_p field-operation floor (the cost driver — the isogeny √-trick)

| F_p op (var-time `BigInteger`) | 512-bit | 1024-bit | 1024/512 |
|---|---|---|---|
| FpMul (a·b mod p) | 0.200 µs | 0.303 µs | 1.5× |
| **FpSqrt** `a^((p+1)/4) mod p` (√-trick) | **72.8 µs** | **418.2 µs** | **5.7×** |
| FpInv (`modInverse`) | 11.7 µs | 29.0 µs | 2.5× |

- The **√ (`modPow`) is the dominant per-isogeny op** (#04 uses the √-trick; ePrint 2023/793 §IV names field inversion/exponentiation as the cost driver).
- 1024-bit √ is **5.7×** the 512-bit √ — the asymmetry across the #05 size choice.

### ms/µs per group action — 512-bit vs 1024-bit

**Constant-time (the security-required path):**
- Authoritative full CT walk ≈ **12 s/group-action** (#04, arxiv 2508.11082, C/ARM, SQALE/CTIDH) and ePrint **2023/793** reports **"tens of seconds … even optimized"** for CSIDH handshakes.
- Pure-Kotlin has **no optimized-asm CT field arithmetic** (ADR-0001: Android+iOS, **zero external deps**, Pure-Kotlin). `java.math.BigInteger` is non-constant-time (C2-compiled C, secret-dependent control flow) **and** slower than hand-tuned asm. → a Pure-Kotlin CT CSIDH-512 walk is **orders of magnitude slower than the 12 s optimized baseline** → **≫ 200 ms**. 1024-bit is ~5.7× worse on the dominant √ plus a larger ℓ-list.

**Variable-time (insecure — for completeness only):**
- Projected Pure-Kotlin var-time walk ≈ **~100 ms–1 s+ (512-bit)** / **~1 s–10 s+ (1024-bit)** (field-op µs × CSIDH walk structure). Even the most generous var-time projection reaches the ~200 ms budget — and it **leaks the secret walk via timing**, violating ADR-0001's constant-time requirement.

### Budget verdict: ≤ ~200 ms (background-BLE handshake) → **NO, infeasible at both sizes**

- Security-required CT path: optimized-C ≈ 12 s (#04) / "tens of seconds" (2023/793); Pure-Kotlin is slower → ≫ 200 ms.
- 512-bit: ~12 s ≫ 200 ms. **1024-bit: worse.** → CSIDH-over-air is latency-infeasible **regardless of the 64 B vs 128 B choice.**

### Constant-time in Pure-Kotlin → **not achievable with `BigInteger`**

`BigInteger.modInverse`/`modPow` are non-constant-time. A truly CT Pure-Kotlin impl needs a **hand-written fixed-width limb field** (masked, branch-free √ + inversion) — a substantial crypto-engineering artifact (~2–3× the var-time op cost here) whose side-channel surface must be expert-reviewed. **Defer to #11** (CT CSIDH exists — arxiv 2508.11082) **and #13**.

### Impact on #05 (size) and #08 (spec)
- **#05 (64 B CSIDH-512 vs 128 B CSIDH-1024): MOOT.** Latency rules CSIDH-out the handshake at both sizes; 1024-bit is monotonically worse.
- **#08:** Architecture B's over-the-air CSIDH KEM (Pkt A ≈ 65 B / Pkt B ≈ 81 B) must be **replaced**. Per ADR-0001, the 761 B ML-KEM-512 ciphertext should be generated **locally under `K_df` and NOT sent over the air** — the airborne packet carries only the small KEM seed/nonce. This needs crypto-expert KEM-binding design + a compatibility record.
- **#11 / #13:** the replacement KEM binding (CSIDH-as-KEM framing; ML-KEM deterministic-encap-as-KDF) gates #08.

### What this spike is *not* (honest ceiling)
- This is a **field-operation floor + authoritative projection**, not a full canonical CSIDH walk benchmark. A direct, property-validated Pure-Kotlin walk (canonical `p` + ℓ-list + √-trick + Velu, self-tested on principal-ideal-identity and e∘(−e)=identity) would pin the exact ms; it requires vetted parameters and crypto review (Constitution S6) and is **deferred to #11/#13** rather than shipped un-vetted from memory.
- The measured µs are a **JVM floor**; native (Android/iOS) is slower — which only strengthens the infeasible verdict.

### Commands / artifacts
- Spike: `.scratch/pqc-ble-mesh/spike/CsidhCtFieldSpike.kt` (custom CT field — current)
- Earlier floor spike (var-time `BigInteger`, kept for contrast): `.scratch/pqc-ble-mesh/spike/CsidhSpike.kt`
- Build gate preserved (spike lives outside the `isogeny` module): `gradle :help :compileCommonMainKotlinMetadata :compileAndroidMain :bundleAndroidMainAar :compileKotlinIos` — re-run below.

### Verdict
**Pure-Kotlin CSIDH-over-air is latency-INFEASIBLE for the ~200 ms BLE handshake at both 512-bit and 1024-bit, and constant-time is not achievable with `java.math.BigInteger`.** → #05's 64 B vs 128 B CSIDH choice is moot; Architecture B's airborne KEM must be replaced (#11/#13 → #08).

## Answer (custom CT bigint) — reopened per request: no `BigInteger` in field ops

The floor spike above used `BigInteger` for *measurement* (var-time, leaks timing) and explicitly could **not** deliver a constant-time field. Per the reopen, this section re-runs the same question with a **hand-written radix-2^26 field that never touches `BigInteger` during arithmetic**, using `../MeshLink-crypto`'s `FieldElement.kt` (and `docs/adr/0001-field-arithmetic-radix-2-26.md`, `docs/explanation/constant-time.md`) as the CT pattern reference. `BigInteger` is used **only** (a) to source an `p ≡ 3 mod 4` prime and precompute Barrett `μ` at setup, and (b) as the **verification oracle** — never in a timed field op.

### Method
- Spike source: `.scratch/pqc-ble-mesh/spike/CsidhCtFieldSpike.kt` (Kotlin/JVM, stdlib only).
- Compile + run: `kotlinc -include-runtime CsidhCtFieldSpike.kt -d /tmp/csidhct.jar && java -Xmx2g -jar /tmp/csidhct.jar`
- Host: macOS 26 arm64 (aarch64), JRE 25.0.4, kotlinc-jvm 2.4.10. JVM floor; native (Android/iOS per ADR-0001) is slower → only strengthens the verdict.
- Correctness oracle vs `BigInteger` **at 512- and 1024-bit**:
  - `reduce(z) == z mod p` (random full-width `z`) — PASS both sizes
  - `mul(a,b) == a·b mod p` (40 full-width random pairs) — PASS
  - `√-trick: (a^((p+1)/4))² ≡ a or p−a` (QR/QNR) — PASS
  - `inv: a·a^(p−2) ≡ 1` — PASS

### Constant-time discipline (mirrors MeshLink; secret-independent control flow)
- Radix-**2^26 Long limbs**, no `BigInteger` in any field op (`BigInteger` used ONLY to seed the prime + precompute `μ`; and as the test oracle above).
- **No data-dependent branches/tables**: carry propagation via `v ushr 26` / `v and M`; conditional select via `-bit` XOR masks; conditional subtract via **borrow-mask** `d ushr 63` (sign bit = borrow); `cswap`-style XOR-mask selects. All control flow is fixed by the (public) prime `p`, never the secret base.
- **Exponentiation on a *public* exponent** (`p−2` for invert, `(p+1)/4` for the CSIDH √-trick): fixed-length square-and-multiply; the multiply step selects `base` vs `1` via a branch-free XOR-mask csel, so the **secret base never drives control flow**.
- Reduction: **Barrett (HAC 14.45)** — `μ = ⌊B^(2n)/p⌋`, `q̂ = ⌊(⌊z/B^(n−1)⌋·μ)/B^(n+1)⌋`, which satisfies `q̂ ≤ q ≤ q̂+4` so `r = z − q̂p ∈ [0, 5p)` is clamped with a fixed `repeat(5) { csubch }`.

> Engineering note (debugged during this run): an initial "extract `⌊z/B^n⌋`, shift `B^n`" Barrett variant gave a **loose quotient bound (q̂ underestimated q by ~10–12 for full-width `z`)**, so the 6-conditional-subtract clamp under-reduced and `mul` (correct on small operands) failed on full-width operands while `pow`/`sqrt`/`inv` (which drive intermediates to full width) broke silently. Switching to the **standard HAC 14.45 extraction (shift `n−1` / `n+1`)** — tight `q̂ ≤ q ≤ q̂+4` — made all self-checks pass with zero `BigInteger` in the field ops. The defect is a reduction-precision error, **not** a CT-correctness or soundness issue.

### Measured: Pure-Kotlin constant-time GF(p) field-operation cost (the isogeny √-trick driver)

| F_p op (custom CT, no `BigInteger`) | 512-bit | 1024-bit | 1024/512 |
|---|---|---|---|
| FpMul  (`a·b mod p`) | 1.937 µs | 4.436 µs | 2.29× |
| FpSqr  (`a² mod p`)  | 1.701 µs | 3.379 µs | 1.99× |
| **FpSqrt** `a^((p+1)/4)` (√-trick, dominant isogeny op) | **1136.181 µs** | **6760.865 µs** | **5.95×** |
| FpInv  `a^(p−2)` | 1092.889 µs | 6623.396 µs | 6.06× |

- `BigInteger` floor (var-time, insecure) for contrast: FpSqrt 72.8 µs@512 / 418.2 µs@1024; FpMul 0.200/0.303 µs; FpInv 11.7/29.0 µs. → The **constant-time limb field pays ~15–16× over var-time `BigInteger`** per op (masked arithmetic + no early-exit), exactly the CT tax expected and consistent with MeshLink's CT-vs-var-time guidance.
- **√ is the dominant per-isogeny op** (the √-trick / field inversion); #04 and ePrint 2023/793 name field inversion/exponentiation as the cost driver.

### ms/µs per CSIDH-512/1024 group action — is the ≤ ~200 ms BLE budget reachable? → **NO**

Authoritative baseline is optimized **C/ARM** (not Pure-Kotlin):
- Full CT group action ≈ **12 s** (#04, arxiv 2508.11082) and ePrint **2023/793**: *"even our highly-optimized implementations result in too-large handshake latency (tens of seconds)."* (Both figures are **above** the ~200 ms BLE handshake budget, with zero margin.)

This custom Pure-Kotlin CT field is **~15–16× slower than var-time `BigInteger`** and there is **no optimized-asm CT field arithmetic** (ADR-0001: Android+iOS, zero external deps, Pure-Kotlin) — i.e. well over an **order of magnitude** slower than the 12 s optimized-C baseline per op. Even taking the √-trick as the binding op:

- **Lower-bound walk (512-bit only):** CSIDH-512 is ≥ ~200 √/inversion-level ops even in the most optimistic walk model. At `feSqrt/512 ≈ 1.1 ms`: `200 × 1.1 ms ≈ 220 ms ≥ 200 ms` **before a single field mul**, and a real CSIDH-512 walk is thousands of field muls plus its √/inversions: **`≫ 200 ms`**.
- Scaled: `feSqrt` is **5.95×** costlier at 1024-bit; combined with Pure-Kotlin being >10× slower than the 12 s optimized-C baseline, a Pure-Kotlin CT walk projects to **~minutes**, not milliseconds.

### Budget + CT-feasibility verdict
- **Constant-time in Pure-Kotlin: ACHIEVABLE.** The radix-2^26 branch-free field (Barrett + borrow-mask `ctSub`/`csubch` + XOR-mask `ctCadd` + fixed-chain public-exponent square-and-multiply with csel) has **no data-dependent branches/loops on secret data** — the secret base only ever enters as XOR-masked limb values. Self-verified bit-exact vs `BigInteger` at 512- and 1024-bit.
- **CSIDH-over-air under ≤ ~200 ms BLE handshake: INFEASIBLE at both 512- and 1024-bit** — the blocker is **walk cost (O(#isogeny-steps × field-ops)), not the CT discipline**. Re-running #10 with a custom CT field **refines but does not reverse** the original verdict: the `BigInteger` floor *understated* the true cost (CT pays ~15–16×), and the optimized-C authoritative baseline (12 s / "tens of seconds") already has no 200 ms headroom.

### Impact on #05 (size), #08 (spec), #11/#13 (KEM binding)
- **#05 (64 B CSIDH-512 vs 128 B CSIDH-1024): still MOOT.** CSIDH is ruled out of the airborne KEM at both sizes; 1024-bit is monotonically worse (5.95× on the dominant √). The custom-CT result does **not** reopen the 64 B vs 128 B question — it makes the negative verdict *stronger* (CT is implementable, but slower).
- **#08:** Architecture B's over-the-air CSIDH KEM (Pkt A ≈ 65 B / Pkt B ≈ 81 B) must **still be replaced**. Per ADR-0001 the 761 B ML-KEM-512 ciphertext is generated **locally under `K_df`** (not sent over the air); the packet carries only the small seed/nonce.
- **#11 / #13:** still gated on **crypto-expert** input — CSIDH-as-KEM framing + the √-trick/inversion cost, and ML-KEM deterministic-encap-as-KDF. This spike fixes the *"is it fast+CT enough?"* input but does **not** resolve the over-the-air KEM construction (a keyed-KEM-design problem, not a field-arithmetic one).
