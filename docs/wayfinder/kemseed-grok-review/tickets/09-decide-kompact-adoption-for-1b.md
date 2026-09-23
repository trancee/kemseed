# D15: Adopt kompact for Phase-1b PDV envelope?

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — claimed by: __
- **Blocked by:** R3 (resolved: gates cleared — see below); #20 (Phase-1b PDV framing sign-off, external)
- **Informs:** 1b bit-packing implementation choice

## Question

#20 §kompact-adoption-path deferred kompact adoption until upstream ships (a) an Android
KMP target and (b) a published `kompact-ksp`. **R3 confirms both are now live**
(`ch.trancee.kompact:kompact` + `:kompact-ksp:0.1.7` on Maven Central, 2026-09-17; runtime
Android target present; KSP 2.3.10–2.3.12 bincompat with kemseed `ksp=2.3.12`).

Now that the gate is cleared, decide for Phase-1b:

- **A — Keep hand-rolling.** Continue without kompact (current #20 directive). The
  pure-Kotlin AD-PDU bit-packing is already KAT-gated; avoids a new dependency and an
  ADR-0001 (zero-deps) exception.
- **B — Adopt kompact.** Pull `ch.trancee.kompact:kompact` for the PDV envelope bit-packing
  — it is purpose-built for "tiny dense BLE frames, zero-alloc," matching the protocol
  intent in #08. kemseed already imports `@KompactModel` patterns in `.scratch`.
  Trade: ADR-0001 exception (or a narrow reinterpretation — kompact as the zero-alloc
  bit-pack primitive, not a runtime crypto/transport dep).

## Recommendation

Table on #20. The 1b PDV framing (seqno-width / AAD / ACK, #20) must be locked first — it
fixes the envelope shape the bit-packing serves. Once #20 1b is signed off, **B** is
attractive (kompact is literally built for this); else A.

## Assets

- R3 ([`research/kompact-upstream-status.md`](../research/kompact-upstream-status.md)) —
  gates cleared.
- #20 §kompact-adoption-path + `.scratch/pqc-ble-mesh/issues/20-phase-1a-gcm-session.md`.
- ADR-0001 (zero external runtime deps).
