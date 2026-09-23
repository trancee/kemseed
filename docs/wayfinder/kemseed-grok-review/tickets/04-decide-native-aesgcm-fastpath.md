# D11: Native AES-256-GCM fast-path strategy

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — claimed by: __
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
