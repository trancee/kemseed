# #20 — Phase-1: AES-256-GCM session AEAD + AD-PDU envelope

## Context
Phase-0 (0a→0d) is complete and re-reviewed (8/8 RESOLVED) — working tree green at 76/76 host tests + `compileKotlinIos`. The only remaining `[EXPERT TBD]` in `#08` was the HKDF direction-label strings; the E1′ handshake already yields symmetric session keys `key_AB`/`key_BA`.

Phase-1 materialises #08 §3 Phase D ("AES-256-GCM bidirectional") using those keys: the AD PDU envelope that actually carries encrypted session material over the 60 B airborne frames.

## Status
- **1a AES-256-GCM seal/open primitive: DONE** (`2cbae34 feat(1a)`, red→green).
  - NIST SP 800-38D Alg 4/5; `seal`→`ct‖tag`, `open`→CT tag verify before decrypt (`null` on failure, no length oracle).
  - Reuses committed `Aes256` block cipher + the proven `Gmac` GHASH multiply (refactor `gmacTag`→shared `gcmAuthTag`; Gmac 5/5 stay green).
  - 14 `Aes256GcmTest` tests: 4 OpenSSL-backed oracle vectors + GMAC-consistency (`seal(∅-pt) == Gmac.gmacTag`) + 3 tamper + 3 reject.
  - Gate: `:testAndroidHostTest` **76/76 green** + `:compileKotlinIos` green; zero new deps.
- **1b AD-PDU envelope + session nonce: NEXT — BLOCKED on design TBD (see "Outstanding")**.

## Outstanding (owner decision required before 1b)
- **Session data-nonce layout.** ADR-0002 §3 §1.6 freezes the handshake/flight GCM IV as `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00` (the `direction`/`nonce` fields are the E1′ frame fields). The *session data* counter schema is NOT in the `#08` freeze — it is the lone residual `[EXPERT TBD]` folded into #07. Concrete choice to pin (one of):
  1. Re-use the frozen IV template verbatim as the data nonce = `0x11 ‖ dir ‖ seqno(8) ‖ 0x00 0x00` (monotonic `seqno` per direction), **or**
  2. Dedicated data nonce `0x12 ‖ dir ‖ seqno(4) ‖ random/uintro(4)` (lighter, distinguishes handshake-vs-data on-air, but the `0x12`/`0x11` split is NOT currently frozen — risks a spec divergence from `#08`).
  3. (Rejected) per-message random 96-bit nonce — GCM security bound degrades with reuse; must be monotonic.
- PDU framing width (seqno: 32-bit? 48-bit?), ACK/retransmit (#14), and p2p GATT relay (#08 §1) all fold into 1b once (1) is pinned.

## Scope / constraints (inherited from Phase-0)
- KMP `android` + `iosArm64`; `compileKotlinIos` MUST stay green; no `gradlew` (`gradle 9.7.1`).
- Pure `commonMain`; `kotlin-stdlib`/`kotlin-test` only; no `java.*`; no `clone()` (`copyOf*` only).
- Goldens from a validated oracle only (`cryptography.AESGCM`); no fabricated values.
- Zero new runtime deps.

## Result — Phase-1a
`git log` shows `2cbae34 feat(1a): AES-256-GCM seal/open primitive`. `:testAndroidHostTest` **76/76** (62 prior + 14 new), 0 failures; `:compileKotlinIos` green.

## Acceptance
- [x] 1a: AES-256-GCM `seal`/`open` byte-exact vs OpenSSL `AESGCM` oracle (4 vectors) + GMAC-consistency + tamper/reject (14 tests green).
- [x] `Gmac` refactor (green: GmacTest 5/5).
- [ ] 1b: AD-PDU envelope + session nonce (owner pins decision (1)/(2) above) → TDD red→green.
