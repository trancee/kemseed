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

## Outstanding (owner decision required before 1b PDU envelope)
- **Session data-nonce layout: RESOLVED by `#08` §1.6 — NOT a TBD.** §1.6 freezes "GCM IV (all flights + data): `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00` (12 B)" and §3 Phase D ("monotonic AEAD nonce"). So the data nonce is `0x11 ‖ dir(0xA0/0xA1) ‖ seqno(8) ‖ 0x00 0x00` (per-direction 8-byte monotonic `seqno`, big-endian, 0-based), re-using the handshake template under the session keys `key_AB`/`key_BA`. No new on-air field semantics — the `0x11` prefix is shared because handshake (signer=NetKey) and data (key=key_AB/keyBA) use *different keys*, so no cross-context nonce reuse. **(Corrects the earlier over-raise that this was "[EXPERT TBD #07]".)**
- **AD-PDU envelope framing: the real 1b residual (needs owner sign-off, per the Phase-0 code-review).** #08 §2 pins the *handshake* frame byte layout (version‖flags‖nonce‖sender_id‖epk‖GMAC, 60 B) but does **not** pin the *data* PDU bytes. Concrete choices to sign off (all fold into #14):
  1. **seqno width**: 32-bit (matches #14's app-layer seqno, 4.29 B rollover at 244 B/MTU) vs 64-bit (the IV already carries 8 bytes). Recommendation: **32-bit**, carried once in the IV (seqno occupies the frozen `nonce(8)` slot, high 4 bytes = seqno, low 4 = `0x00000000`); no separate seqno field (saves airspace, IV binds it).
  2. **AAD scope**: bind PDU type + length (`dir(1) ‖ seqno(4)`, 5 bytes) as AAD, or empty AAD (IV already binds dir+seqno). Recommendation: **`dir‖seqno(4)`** — prevents truncation/relay without growing the on-wire PDU.
  3. **ACK encoding**: in-band 32-bit bitmap per #14, *or* implicit (Phase-B "first data packet failing open ⇒ abort" = key confirmation, no explicit ACK). Recommendation: **implicit key confirmation** for the initial 1b slice (matches #08 §3 Phase B), defer in-band ACK to #14.

## Scope / constraints (inherited from Phase-0)
- KMP `android` + `iosArm64`; `compileKotlinIos` MUST stay green; no `gradlew` (`gradle 9.7.1`).
- Pure `commonMain`; `kotlin-stdlib`/`kotlin-test` only; no `java.*`; no `clone()` (`copyOf*` only).
- Goldens from a validated oracle only (`cryptography.AESGCM`); no fabricated values.
- Zero new runtime deps.

## kompact adoption path (investigated 2026-09-11 — only if owner wants the zero-alloc view layer)
`../kompact` is purpose-built (zero-alloc `@JvmInline` result reads, lazy `@KompactModel` value-class views, LSB-first bit packing, KMP). For a byte-aligned AD-PDU (seqno/length/ct-tag) bit-order is irrelevant (byte-aligned ⇒ endian-identical), so the conceptual fit is excellent. **But pqcble cannot consume it as-is — three verified gaps:**

1. **No Android target in `:kompact`** (`kompact/build.gradle.kts` lines 31–40: only `jvm{JVM_21}` + `iosArm64()` + `iosSimulatorArm64()`). pqcble ships `android`+`iosArm64`; a KMP consumer resolves per-target klibs, so there is **no `kompact-android` artifact**. kompact cannot satisfy pqcble's Android target.
2. **`:kompact-ksp` is unpublished.** It has only a plain `publishing{}` (POM "Kompact KSP") with **no** Central Portal pipeline (`centralPortalDeploy`/`generateChecksums`/`assembleCentralBundle` exist only in `:kompact`, not `:kompact-ksp`), and `kompact/references/central-release-report.md` lists **no `kompact-ksp-*` coordinates**. So `@KompactModel` codegen is unavailable to consumers.
3. **Kotlin version skew**: kompact `libs.versions.toml` pins Kotlin **2.3.21** (KSP 2.3.12); pqcble runs **Kotlin 2.4.10 / AGP 9.4.0**. Mixed klib/stdlib versions risk ABI drift.

### Required kompact-side changes (to fit pqcble Phase-1b)
- **A. Add an Android target to `:kompact`**: apply `alias(libs.plugins.android.library)`, add `androidLibrary { namespace="ch.trancee.kompact"; compileSdk=36; minSdk=21 }`, declare the `android()` KMP target, and extend `apiValidation { klib/android }` + `publish` to emit `kompact-android` (klib + JVM fallback). (Mirror pqcble's android setup; ADR-0001 minSdk=21.)
- **B. Ship `:kompact-ksp` to Central**: port the Portal pipeline (`generateChecksums`/`assembleCentralBundle`/`centralPortalDeploy`/`centralPortalStatus`/`centralPortalPublish`) from `:kompact` into `:kompact-ksp`, add `signing` (currently absent), and publish `kompact-ksp-0.1.0` with the `@KompactModel` processor descriptor. (The `com.google.devtools.ksp:symbol-processing-api` + `kotlinpoet` deps are already declared.)
- **C. Align Kotlin toolchain**: bump kompact `kotlin` → 2.4.10 (and `ksp`/`skie`/`kover`/`dokka`/`bcv` to the 2.4-compatible set pqcble uses) so klibs/stdlib match; re-run 100%-coverage `kover` + strict `bcv` `apiValidation` on all targets.

### Required pqcble-side changes (if kompact adopted)
- **(P1)** New `ADR-0003` relaxing `ADR-0001` **only for the session/transport layer**: allow `ch.trancee.kompact:kompact` (runtime) + `kompact-ksp` as the single Phase-1 dependency, keeping `kemseed` crypto core strictly zero-dep. OR restructure pqcble into `:kemseed` (crypto) + `:kemseed-session` (depends on kompact).
- **(P2)** In `kemseed` (or the new session module): add `alias(libs.plugins.ksp)`, depend on `kompact` + `kompact-ksp@0.2.0` (post A/B/C release), and annotate the AD-PDU `@KompactModel value class` with `@KompactField` seqno/dir/length fields over the frozen nonce layout.

### Recommendation
The kompact adoption path (A+B+C + P1+P2) is real cross-repo release work (Android target, KSP publishing pipeline, Kotlin-2.4 bump, ADR-0001 exception + possible pqcble subproject split). For a minimal, ADR-0001-preserving Phase-1b **now**, hand-roll the PDU envelope in `commonMain` over the committed `Aes256Gcm` (seqno as a 4-byte big-endian counter in the frozen IV `nonce(8)` slot; AAD=`dir‖seqno`; `ct‖tag` blob via `writeBlob`/`readNested`-style length prefix) — zero new deps, no KSP, no Android gap, no version skew. Keep kompact as the **future** zero-alloc view layer once A+B+C land and ADR-0003 is accepted.

## Result — Phase-1a
`git log` shows `2cbae34 feat(1a): AES-256-GCM seal/open primitive`. `:testAndroidHostTest` **76/76** (62 prior + 14 new), 0 failures; `:compileKotlinIos` green.

## Acceptance
- [x] 1a: AES-256-GCM `seal`/`open` byte-exact vs OpenSSL `AESGCM` oracle (4 vectors) + GMAC-consistency + tamper/reject (14 tests green).
- [x] `Gmac` refactor (green: GmacTest 5/5).
- [ ] 1b: AD-PDU envelope + Phase-B first data packet (data-nonce frozen by #08 §1.6; PDU framing/ACK per #14 — owner sign-off on seqno-width/AAD/ACK defaults above).
