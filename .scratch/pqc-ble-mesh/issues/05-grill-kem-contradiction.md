# Grill: Resolve KEM contradiction — confirm Architecture B is the spec target

Status: resolved
Claimed by: work-through session (agent)
Type: grilling
Blocked by: 01, 04 → resolved (01, 04 closed; decision rendered)

## Question

`PROMPT.md` is internally contradictory about the over-the-air KEM:

- **Sections 1–3** ("Designing the Smallest PQC Primitives" / "Zero-Fragmentation Exchange") propose a custom small-LWE/M-LWE scheme (Rudraksh/Smaug style, n=128/256) with ~320-byte ephemeral keys and Falcon-512 for enrollment, transitioning to symmetric MACs.
- **The titled "# Specification: Hyper-Efficient Isogeny-to-ML-KEM Hybrid"** and the "# Context Guide" (lines 80–258) use CSIDH-512 (64-byte PK/CT) → local ML-KEM-512 → AES-256-GCM.

This wayfinder map targets **Architecture B** (isogeny-to-ML-KEM).

Decision required: Is Architecture B confirmed as the spec target, making Architecture A (custom LWE + Falcon) superseded/rejected? Once #01 (CSIDH key sizes) and #04 (constant-time CSIDH) return, can we commit to CSIDH-512 as the over-the-air KEM — or does the research reveal CSIDH is infeasible (size or side-channels) and force a return to the LWE path?

<!-- Blocking: needs #01 (sizes) and #04 (side-channels) resolved before this decision is final. -->

## Answer

**Decision (session owner, 2026-09-10): Architecture B confirmed; CSIDH security level *deferred* — run a Pure-Kotlin feasibility spike first (Option C).**

- **KEM / architecture:** Architecture B (CSIDH-512 → local ML-KEM-512 → AES-256-GCM) is confirmed as the spec target. Architecture A (custom LWE + Falcon, Sections 1–3 of `PROMPT.md`) is superseded and moved to the map's `Out of scope`.
- **Security level (the crux):** *not chosen yet.* Rather than commit to 64-byte CSIDH-512 (~64-bit quantum, Option A) vs 128-byte CSIDH-1024 (~128-bit quantum, Option B), the owner chose to **spike Pure-Kotlin constant-time CSIDH feasibility first** — because research #04's C/ARM timing (~seconds) does **not** transfer to Pure-Kotlin (ADR-0001 forbids external libs), and 1024-bit field arithmetic in Pure-Kotlin may exceed the background-BLE latency budget, which would force Option A.
- **Cascade:** the 64 B vs 128 B choice will be made *after* #10's spike results feed a follow-up size-decision. The spec draft (#08) is **re-blocked on #10** (not this ticket), so #08 remains downstream.

Sources:
- Session owner choice: "Reconsider / spike Pure-Kotlin feasibility first" (Option C).
- #01 (64-byte CSIDH-512 sizes), #04 (constant-time CSIDH; C/ARM ~seconds; Pure-Kotlin slower), #03 (BLE MTU / zero-fragmentation), ADR-0001 (Pure-Kotlin KMP-only constraint).

## Post-#10 closure (re-evaluated 2026-09-10 after #10 reopen w/ custom CT field)

#10's Pure-Kotlin CSIDH feasibility spike re-resolved the 64 B vs 128 B size question by **voiding it**: CSIDH-over-air is latency-**infeasible** at both 512-bit (64 B) and 1024-bit (128 B) — the authoritative optimized-C constant-time walk is ~12 s (#04) / "tens of seconds even optimized" (ePrint 2023/793), and Pure-Kotlin is >10× slower per field op → a full walk projects to **~minutes ≫ 200 ms** (the √-trick alone, 1136 µs@512 / 6761 µs@1024 × the walk's √/inversion count, already blows the budget; 1024-bit is 5.95× worse on √).

**Refinement from the reopen (not a reversal):** the original closure hedged on "CT not achievable with `BigInteger`" as a blocker. That hedge is **removed** — the reopened spike built and self-verified (vs `BigInteger` oracle) a **custom radix-2^26 constant-time GF(p) field** (Barrett reduction + branch-free borrow-mask conditional subtract + XOR-mask conditional select; public-exponent square-and-multiply with branch-free csel). It is **genuinely constant-time in Pure-Kotlin** (no data-dependent branches on the secret base). The CT discipline is therefore **solved**; the infeasibility bottleneck is now cleanly the **irreducible O(#isogeny-steps × field-ops) walk cost** at these security sizes, not any missing CT machinery. So #11/#13 remain the gating crypto-expert tickets — but for **KEM-binding design of the replacement airborne KEM** (small + CT-reviewed), not for "hand-writing a CT bigint to make CSIDH fast."

Since size doesn't fix latency, #05's tradeoff collapses to **Architecture B drops the airborne CSIDH KEM** (keep the local ML-KEM-512 + AES-256-GCM tail; make the airborne KEM small + CT-reviewed — see #11/#13). The size decision is recorded as moot here; #08 re-blocked on #11/#13.

