# ADR-0001 — Stack & dependency constraints for the PQC-BLE mesh protocol

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** project
- **Context ref:** `PROMPT.md` (hybrid PQC seed-to-ML-KEM over BLE mesh)

## Context

`PROMPT.md` describes a post-quantum secure BLE-mesh protocol. The implementer
must target a narrow, constrained platform matrix:

- Mobile only — **Android and iOS**, operating in the BLE background.
- **Kotlin Multiplatform (KMP)** as the implementation technology.
- **Zero external dependencies** unless strictly approved (supply-chain + security surface).
- Native platform crypto (Android Keystore, iOS Security / CryptoKit) is preferred
  via `expect/actual`; **Pure-Kotlin** fallback is required where native primitives
  are unavailable — notably CSIDH and ML-KEM are **not** provided by the platform
  keystores, so those must be Pure-Kotlin.

This materially affects feasibility: the constant-time figures surveyed in
research ticket #04 were for optimized C/ARM code. **Pure-Kotlin** constant-time
CSIDH/ML-KEM is markedly slower, which sharpens the security-level tradeoff in
grilling ticket #05 (64-byte CSIDH-512 ≈ 64-bit quantum security vs 128-byte
CSIDH-1024 ≈ 128-bit). A 1024-bit field in Pure-Kotlin may be too slow for the
background-BLE latency premise.

## Decision

Adopt a **Kotlin Multiplatform** implementation targeting **Android + iOS only**,
with **zero external dependencies** unless a documented exception is approved.
Prefer native platform primitives via `expect/actual`; provide **Pure-Kotlin**
implementations (constant-time where the threat model requires it) for any
primitive the platforms do not supply.

## Alternatives considered

- **Wider KMP scope (Android + iOS + desktop/JS/Wasm).** Rejected — out of scope;
  the use case is mobile BLE mesh.
- **External crypto libraries (OpenSSL / BoringSSL / Bouncy Castle).** Rejected by
  the zero-dependency rule. Native keystores are the preferred path; Pure-Kotlin is
  the fallback, never third-party native libs.
- **Native-only via JNI/FFI to C libraries.** Rejected — violates the KMP
  source-sharing goal and the zero-dependency rule; also complicates iOS App Store
  review and removes compile-time constant-time guarantees.

## Risks

- **Performance:** Pure-Kotlin constant-time CSIDH/ML-KEM is slower than native;
  may make 128-bit CSIDH (#05 Option A) infeasible on mobile CPUs within the
  protocol's latency assumptions. Mitigated by DoS rate-limiting + the protocol's
  single-packet exchange design (#03).
- **Side-channel surface:** Pure-Kotlin must still meet the constant-time
  requirement (threat model §Elevation of Privilege). JVM/bytecode constant-time
  guarantees differ from C; a Pure-Kotlin constant-time verification spike is needed.
- **Supply-chain:** the zero-dependency rule avoids third-party crypto supply-chain
  risk; native keystores further shrink the audited surface.

## Migration

N/A — initial project decision. Any future deviation (a new platform target, or an
approved external dependency) requires a new ADR amending this one.

---
ADR-0001, v1.0, ratified 2026-09-10.
