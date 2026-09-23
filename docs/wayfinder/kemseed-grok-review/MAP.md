# Wayfinder — Acting on Grok's critical review of `kemseed`

Label: `wayfinder:map` · Tracker: local markdown (`docs/wayfinder/kemseed-grok-review/tickets/`)

## Destination

A staged, owner-decidable plan for acting on Grok's critical review of `kemseed`: classify
each of the 12 review proposals as **decided/implemented**, **decided-to-defer**,
**out-of-scope**, or **blocked-on-a-future-decision**, and express the remaining sharp
design choices as takeable decision tickets — so the maintainer can execute the rest with
nothing left to decide.

## Notes

**Domain (crypto stack layers):**
- L1 `Aes256.kt` — AES-256 core (S-box, key expansion, rounds).
- L2 `Aes256Gcm.kt` / `Gmac.kt` — AEAD (GHASH, J0/inc32, CTR, tag).
- L3 `Hmb1Handshake.kt` — DoS prevalidation (GMAC signer-verify), replay cache.
- L4 PDV envelope `AdPduCrypto.kt` — **Phase-1b, BLOCKED** on framing sign-off (#20).
- L5 `KemSeed.kt` — near-empty public surface; exposure gated on Phase-1b.
- Platform: KMP `commonMain` → Android (java-interop) + iOS arm64 device (CryptoKit cinterop).

**Standing constraints (E1):** ADR-0001 zero new runtime deps; ADR-0002 §5.2 reserves the
`expect/actual` crypto-gate slot; ADR-0003 defers detekt (upstream marker 404/403); Const. E1
(reproducible, latest-stable only, ktfmt 0.64 pinned). Phase-1a GCM session is DONE + green
(#20 `1a DONE` at `2cbae34`); Phase-1b PDV framing is BLOCKED on owner sign-off (#20).

**Skills to consult:** `kotlin-multiplatform` (expect/actual + cinterop), `ble-protocol-stack`
(GCM/AEAD semantics), `android-ble-gatt-server` (CryptoKit/Keystore posture).

**Test gate for any crypto change:** `Aes256Test` (FIPS-197) + `Aes256GcmTest` (+`GmacTest`)
OpenSSL-backed oracles + `AdPduTest` + `Hmb1HandshakeTest`, then
`:compileKotlinIos spotlessCheck`. No crypto edit ships without a green gate.

## Decisions so far

- **"Expand AES-256 key schedule once per GCM op"** → committed `85775f6` (Grok §2/#1). Byte-exact:
  FIPS-197 + 14 OpenSSL-GCM/GMAC oracle tests green; ~6×→1× schedule expansions per seal/open.
  ([tickets/00-decided-expand-key-schedule.md](tickets/00-decided-expand-key-schedule.md))
- **"Recompute GHASH H on every `gcmAuthTag`"** → folded into `85775f6` (H = AES(0) now reuses
  the expanded key). (see above)
- **"AES-256-GCM tag comparison timing"** → already constant-time via `Gmac.ctEquals`/`ctEquals`
  (`Aes256Gcm.open`); no change. (Grok §3 CT-tag check — already satisfied.)
- **"kompact adoption"** → deferred; #20 §kompact-adoption-path decides: "hand-roll for 1b now,
  re-evaluate after upstream ships Android target + published `kompact-ksp`."
- **"detekt"** → deferred (upstream Gradle Plugin Portal/Maven Central marker 403/404 — publishing
  break, not repo-config); re-evaluate quarterly.
- **"ktlint 0.64 bump cadence"** → Dependabot policy (`.github/dependabot.yml`, direct-only,
  weekly); pinned per Const. E1. No decision needed here.
- **"native AES-256-GCM interop surface" (R1)** → RESOLVED 2026-09-18: `expect/actual` viable
  on both platforms; Android Keystore AES/GCM (`javax.crypto.Cipher`) is **constant-time**
  (KeyMint TEE, AOSP); iOS native AES/GCM reachable via **CommonCrypto `CCryptorGCM` C API**
  via cinterop — CryptoKit `AES.GCM` is Swift-only → invisible to KMP Obj-C interop.
  Leans D11 = B.
  ([tickets/01-research-kmp-native-aesgcm-interop.md](tickets/01-research-kmp-native-aesgcm-interop.md))
- **"native CLMUL/PMULL for GHASH" (R2)** → RESOLVED 2026-09-18: Kotlin/Native exposes no
  PMULL/CLMUL intrinsics, but the cinterop tool binds C functions → reachable via a per-target
  C shim wrapping `<immintrin.h>`/`<arm_acle.h>` intrinsics on all targets (branchless → CT).
  Feasibility confirmed; D7 (shim vs pure-table) is the owner call.
  ([tickets/02-research-clmul-pmull-kmp-native.md](tickets/02-research-clmul-pmull-kmp-native.md))
- **"kompact upstream gates" (R3)** → RESOLVED 2026-09-18: BOTH #20 gates CLEAR — `kompact`
  ships an Android target + `ch.trancee.kompact:kompact-ksp:0.1.7` is on Maven Central
  (ADR-0003 404/403 marker stale, resolved 2026-09-17). Spawned **D15**.
  ([tickets/03-research-kompact-upstream-status.md](tickets/03-research-kompact-upstream-status.md))

## Not yet specified (fog toward destination)

- Whether Phase-1b PDV framing (#20) mandates a specific AAD/seqno width that reshapes the
  public API contract — gates D14 and D15 (kompact serves the envelope, so it too waits on
  the framing shape).

## Out of scope

- §4 kompact-adoption analysis (resolved in #20: hand-roll for 1b, kompact is future) — the
  A/B/C gap analysis already lives there; do not redo. ([issues/20-phase-1a-gcm-session.md](../../.scratch/pqc-ble-mesh/issues/20-phase-1a-gcm-session.md))
- §1 zero-runtime-dep policy (ADR-0001) — native fast-paths are `expect/actual` over *platform
  frameworks* (CryptoKit / Android Keystore), not new deps; policy stands.
- §7 ktlint version bump — Dependabot-managed; not a design decision.

## Frontier (open, unblocked, unclaimed)

These are the open child tickets; claimed-by-assignee = in progress. Blocked tickets are
listed in their bodies.

- D11 [`grilling/HITL`] — Native AES-256-GCM fast-path strategy (A defer-pure vs B expect/actual ship-now); R1 resolved.
- D2 [`grilling/HITL`] — Add `iosSimulatorArm64` target (CI/dev-ex) vs Const. E1 device-only.
- T1 [`task`, RESOLVED `59c620e`] — AES/GCM alloc optimizations: in-place AES (ctrTransform reuses one 16B ks buffer; D11/B native path now has a pure reference) + pre-sized `ct‖tag` in `seal` GREEN; defer `open` `copyOfRange` slice (carries to D7/perf).
- D15 [`grilling/HITL`, blocked on #20 + R3] — Adopt kompact for Phase-1b PDV envelope? (R3 gates cleared; still awaits #20 1b framing).
- D7 [`grilling`, blocked on D11] — GHASH acceleration target (native pmull/CLMUL vs pure table/Karatsuba); R2 feasibility confirmed.
- D14 [`grilling`, blocked on #20] — Public API surface exposure (block on Phase-1b framing OR ship minimal seal/open).
