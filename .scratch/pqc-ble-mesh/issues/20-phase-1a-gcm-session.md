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

## Proposal review (2026-09-11)

Review of the "pqcble consumer enablement" proposal for `../kompact` (Changes A–E).
Ground-truth sources: `kompact/kompact/build.gradle.kts`, `kompact/kompact-ksp/build.gradle.kts`,
`kompact/settings.gradle.kts`, `kompact/gradle/libs.versions.toml`, `kompact/.github/workflows/ci.yml`,
`kompact/gradle/wrapper/gradle-wrapper.properties` (Gradle 9.7.1), and official docs
(kotlinlang.org `gradle-binary-compatibility-validation.html`, AGP 9.0/Kotlin compat matrix,
gradle.org compatibility matrix, Gradle Plugin Portal).

### ✅ Verified correct
- **Change A key decision**: `com.android.kotlin.multiplatform.library` (AGP 9.x) is the correct
  plugin for a KMP library — `com.android.library` + KMP is no longer allowed (Android/AGP 9.0 blog).
- **Change E**: built-in `abiValidation { keepLocallyUnsupportedTargets = false }` ≈ BCV
  `strictValidation = true`; tasks `checkKotlinAbi`/`updateKotlinAbi`; opt-in
  `@OptIn(ExperimentalAbiValidation::class)`; DSL is on `KotlinMultiplatformExtension` so it
  covers the new Android KMP-library target too. Golden-file regeneration path is correct.
- **Compat**: Kotlin 2.4 → AGP ≥8.5.2 (AGP 9.4.0 ✅); KSP no longer version-locked to Kotlin since 2.3.0 (so `ksp="2.4.10"` is fine); Kover 0.9.9 (created 2026-07-17) is contemporary with Kotlin 2.4.10 (2026-07-14) ✅; kotlinpoet 2.4.0 is KMP-capable ✅; Spotless 8.10.2 / SKIE 0.10.14 are Kotlin-version-independent ✅.

### ✏️ Corrections required
- **Change A, §2.1 / §2.2 "No new `androidMain` source set is required" — FALSE.**
  The 7 result value classes are `public expect value class` in `commonMain` with `actual` in
  **per-target** source sets: `@JvmInline actual` in `jvmMain`, plain `actual value class` in
  `iosMain`. With `applyDefaultHierarchyTemplate=false`, adding `android()` creates a separate
  `androidMain` source set — it will **not** see `jvmMain`'s `actual` declarations and the build
  fails with "expected X has no actual in androidMain". Required fix:
  `sourceSets { getByName("androidMain") { dependsOn(getByName("jvmMain")) } }` (share the JVM
  `@JvmInline` actuals) — this is the idiomatic KMP "JVM+Android share actuals" pattern. Also,
  `JvmCoveragePinning.java` (in `jvmMain`, Kover scaffolding) would leak into the Android artifact
  via the `dependsOn` — exclude it from the Android jar/AAR (`android.packaging.excludes` or a
  shared intermediate source set). This must be verified by `:kompact:assembleReleaseAar` +
  `check`.
- **Change A, §2.3 risk row "Gradle 9.7.1 outside Kotlin 2.4.0's tested range (7.6.3–9.5.0)"
  is STALE and should be DELETED.** kompact's own `gradle-wrapper.properties` pins Gradle 9.7.1,
  and gradle.org's official matrix maps Gradle 9.7.0 ↔ Kotlin 2.4.0 (and "Gradle tested with
  Kotlin 2.0.0–2.4.20-Beta1"). AGP 9.4.0 needs Gradle ≥9.1 (satisfied). No risk.
- **Change C compat table "Dokka 2.2.0 supports Kotlin 2.4.10 = ✅ — UNVERIFIED, likely wrong.**
  The Gradle Plugin Portal lists Dokka's **latest as 2.2.0 (created 2026-03-26)**; kompact's
  `libs.versions.toml` pins `dokka = "2.2.0"`. Kotlin 2.4.0 shipped 2026-06-03, ~2.5 months
  *after* Dokka 2.2.0. kompact currently runs dokka 2.2.0 on Kotlin 2.3.21 (works), but bumping
  to 2.4.10 risks incompatible K2 metadata parsing. kompact CI gates on
  `:kompact:dokkaGeneratePublicationHtml` + `git diff --exit-code kompact/docs/api/` (macOS only).
  **Required**: empirically run `:kompact:dokkaGeneratePublicationHtml` against a Kotlin-2.4.10
  metadata build *before* cutting 0.2.0. Fallback if it breaks: no newer Dokka exists on the
  portal, so either (a) keep the docs-sync CI gate on hold until a Dokka 2.4.x release appears,
  or (b) pin the KDoc sources only and regenerate docs out-of-band. This is the highest-risk
  item in the proposal and must not be `✅` untested.
- **Change B §3.1 items 4–5 confirmed needed**: kompact-ksp has only `tasks.jar` (no `sourcesJar`/
  `javadocJar`). But kompact-ksp is `kotlin("jvm")` (not KMP), so it has no KSP-generated
  `jvmSourcesJar`/`dokkaJavadocJar` — these must be hand-written (`Jar` tasks + dokka README-stub
  jar). Correct as specified; verify with `generateChecksums` dry-run.
- **`kotlin-mpp` / `kotlin-android` migration flag**: Kotlin 2.4.0 removed legacy Android source-set
  layout (`kotlin.mpp.androidSourceSetLayoutVersion=1` is gone) — kompact must not rely on it
  (it doesn't — `applyDefaultHierarchyTemplate=false` is used). No change, but flag for CI.

### 🚧 New gap surfaced — CI Section (7) breaks under strict mode
The proposal's Section 7 renames `:kompact:jvmApiCheck` → `:kompact:checkKotlinAbi` on the **Linux**
`jvm-test` job. With `keepLocallyUnsupportedTargets=false` (the strict mode Change E wants),
`checkKotlinAbi` validates **all** targets — including `android` — and the Android klib **cannot
compile on Linux/Ubuntu**. So the Linux CI job fails. The *current* kompact sidesteps this by
running the per-target `jvmApiCheck` (BCV exposes `jvmApiCheck`/`klibApiCheck`). The built-in
`abiValidation` does not expose a JVM-only variant the same way. **Required resolution** (pick one):
- (a) Run `checkKotlinAbi` (strict) on the **macOS** `api-check` job only (which already has the
  full gate); keep the Linux job abi-free, or
- (b) Set `abiValidation { keepLocallyUnsupportedTargets = true }` on Linux (lenient inference)
  and `= false` only on macOS — configurable via `gradle.properties` + per-job init, or
- (c) Split: `:kompact:checkKotlinAbi` guarded so it only validates targets the host can build.
  The proposal must choose; option (a) is simplest and matches the existing macOS-full-gate model.
  `kompact-ksp`'s `:kompact-ksp:checkKotlinAbi` (JVM-only, no klib) is fine on Linux.

### Bottom line
The proposal is structurally sound and the kompact→pqcble fit is genuine. The blockers that
block are: (i) Change A needs the `androidMain dependsOn(jvmMain)` source-set fix (with
`JvmCoveragePinning` exclusion) — non-optional, (ii) the CI strict-mode gap (Section 7 must
restrict `checkKotlinAbi` to macOS or go lenient on Linux), and (iii) Dokka 2.2.0's Kotlin-2.4
compatibility must be empirically proven before 0.2.0 (no newer Dokka is published). Kover, AGP,
KSP, kotlinpoet, Spotless, SKIE compat are all confirmed good. Suggest: ship A+B+C with these
three issues resolved, then re-run `:pqcble` 1b PDU TDD against `kompact:0.2.0`.

## Proposal v2 review (2026-09-11)

v2 fixes every error from the earlier kompact-fit assessment (read-only). Confirmed-correct claims (ground-truth sources: kompact build files + kotlinlang.org ksp-quickstart/abi-validation docs + gradle.org matrix + gradle/plugin-portal):

- **KSP versioning CORRECT**: kotlinlang `ksp-quickstart` pairs Kotlin **2.4.10 with KSP 2.3.10** — KSP is *not* version-aligned to Kotlin. So `ksp = "2.3.12"` (unchanged) is right; `ksp = "2.4.10"` would fail. (Corrects my own earlier v1 feedback that 2.4.10 was wanted.) ✓
- **`jvmCommon` shared-actuals restructure CORRECT**: `jvmCommon = creating { dependsOn(commonMain) }`; `jvmMain`/`androidMain` both `dependsOn(jvmCommon)`; `@JvmInline actual` Result/ScalarType/NestedRegionResult/VehicleTelemetry moved there. Intermediate source sets *may* host `actual` declarations that are shared by multiple targets consuming the same `expect` — this is the documented KMP "shared actual" pattern. So "no androidMain of its own" is now TRUE (androidMain exists implicitly and only pulls jvmCommon). ✓
- **`kotlin { android { namespace; compileSdk; minSdk; compilerOptions } }` DSL** is the AGP-9.4 correct form (not `androidLibrary{}`/`top-level android{}`). ✓
- **`abiValidation { keepLocallyUnsupportedTargets = false }` ≈ BCV `strictValidation=true`; tasks `checkKotlinAbi`/`updateKotlinAbi`** — confirmed via kotlinlang.org BCV page. ✓
- **Gradle 9.7.1 + Kotlin 2.4.10** is fine (Kotlin 2.4 compat: "Gradle 7.6.3 through 9.5.0; up to the latest Gradle release with possible warnings") — so v2 §7.6 downgrade-to-9.5.0 fallback is UNNECESSARY. ✓ keep 9.7.1.

### ⚠️ Corrections still needed in v2
1. **§4.1 item 4 (`kompact-ksp`): "jvmSourcesJar already auto-created by KGP for JVM" — FALSE.** KGP auto-creates `jvmSourcesJar` only for KMP modules (`:kompact`). `kompact-ksp` is `kotlin("jvm")` → NO auto sources jar. It also lacks a javadoc-stub jar. **Fix:** add explicit `sourcesJar` (`Jar` from `kotlin.srcDirs`) + `javadocJar` (README stub, mirroring `:kompact`) tasks and attach to the JVM publication.
2. **§3.1 misplaced `includeBuild("build-logic")`** — belongs in §4.2 (the convention-plugin extraction of the Portal pipeline), not Change A (Android target). Move it.
3. **§3.3 vs §7.3 `keepLocallyUnsupportedTargets` muddle** — §3.3 table says "set `true` (default) in build config; macOS strict" but if the *build config* default is `true`, macOS also runs lenient. Resolution: keep `keepLocallyUnsupportedTargets = false` (strict, matching Change E's `strictValidation=true` intent) in the build, and run `checkKotlinAbi` **on macOS only** (full, all targets incl. iOS klibs); on Linux run `checkKotlinAbi` with the default (lenient, infers iOS, still really validates JVM+Android) OR skip abi-check on Linux. Pick one and make §3.3 consistent with §7/§8.
4. **Task-name verification**: confirm the Android release-artifact task (`assembleReleaseAar` vs `assembleReleaseKotlinAndroid` vs `assembleRelease`) in Step 0.

### 🔴 Residual high-risk (NOT yet resolved — must gate on pre-flight)
- **Dokka 2.2.0 ↔ Kotlin 2.4.10 metadata compatibility.** The Gradle Plugin Portal latest Dokka is **2.2.0** (26 Mar 2026); Kotlin 2.4.0 shipped 3 Jun 2026. kompact currently runs dokka 2.2.0 on Kotlin 2.3.21 (works). Whether dokka 2.2.0 parses Kotlin-2.4 metadata is unproven, and **no newer Dokka is published to upgrade to**. The macOS CI gate runs `:kompact:dokkaGeneratePublicationHtml` + `git diff --exit-code docs/api/`. **Must verify in Step 0 spike**: run dokka on a Kotlin-2.4.10 build. If it fails, the dokka-sync gate must be deferred (no Dokka upgrade path exists) — unacceptable for a release but tolerable for a 0.2.0-SNAPSHOT dev cycle. Keep this RED until empirical green.

### Bottom line
v2 covers all KOMPAT-SIDE gaps (Android target, KSP publication, Kotlin-2.4 alignment, BCV→built-in abiValidation, version bump) and fixes the v1 errors. It does **not** cover the pqcble-side blocker (**ADR-0001: zero runtime deps** — that remains pqcble's decision and is necessary-but-not-sufficient; see §kompact-adoption-path above). Three mechanical corrections (kompact-ksp sources/javadoc jar, misplaced includeBuild, the keepLocallyUnsupportedTargets consistency) plus the Dokka-compat pre-flight gate are the only items standing between this proposal and `kompact:0.2.0-SNAPSHOT`.

## Proposal v2 (GFM/Dokka variant) review (2026-09-11)

v2 fixes the KSP-version, `keepLocallyUnsupportedTargets`, and AGP-9-DSL items from the
earlier review. But two claims are **not reproducible / use non-existent API**:

- **§2 "Step 0 COMPLETED ✅ Verified" / §4.5 Markdown convention plugin:** the cited
  prototypes `/tmp/dokka-prototype/` and `/tmp/dokka-kmp-prototype/` **do not exist** in
  this environment (verified `ls` → No such file). The only `/tmp` artifacts from this
  session are AES-crypto files (`tiny_aes.c`, `gen_sbox.py`, `aesref.py`,
  `gmac_test.py`, `sbox_tables.txt`). So the Dokka+GFM verification is **not backed by
  evidence I can reproduce** — the "Worker log: Loaded plugins: …, GfmPlugin" output is
  not from a run I executed.
- **§4.5 code uses non-Dokka-2.2.0 API:**
  - `formatName = "markdown"` — the Dokka GFM/markdown format id is `gfm`, not `markdown`.
  - `tasks.named("dokkaGeneratePublicationMarkdown")` — DGP v2 task names are
    `dokkaGeneratePublicationHtml` / `dokkaGeneratePublicationJavadoc` (+ `dokkaGenerate`);
    there is no `…Markdown` task. GFM follows `dokkaGeneratePublicationGfm` (Alpha).
  - `DokkaFormatPlugin(formatName=…)` + `DokkaFormatPlugin.DokkaFormatPluginContext` +
    `formatDependencies.dokkaPublicationPluginClasspathApiOnly.dependencies.addLater(…)`
    + the `dokka(…)` helper are **not** the documented surface (kotlinlang.org DGP docs).
  - **Correct GFM approach** (DGP v2, no custom subclass needed):
    ```kotlin
    plugins { id("org.jetbrains.dokka") version "2.2.0" }
    dependencies { dokkaPlugin("org.jetbrains.dokka:gfm-plugin:2.2.0") }
    tasks.named("dokkaGeneratePublicationGfm") {   // verify exact name in Step 0
      outputDirectory.set(layout.projectDirectory.dir("docs/api"))
    }
    ```
    Caveat: GFM/Markdown is **Alpha** in Dokka 2.2.0 (per README) — higher risk for a
    committed `git diff --exit-code docs/api/` CI gate.

### Remaining (still-open) issues not fixed by v2
1. **§4.1 item 4:** "jvmSourcesJar already auto-created by KGP for JVM" — still FALSE.
   `kotlin("jvm")` does not auto-create a sources jar; kompact-ksp needs an explicit
   `sourcesJar` + `javadocJar`(README stub). (v2 keeps the erroneous claim.)
2. **§3.3/§5.3/§11 #9:** "Gradle 9.7.1 outside KGP 2.4.10 fully-supported range; fallback 9.5.0."
   STALE — kompact wrapper is 9.7.1; gradle.org matrix = Gradle 9.7.0 ↔ Kotlin 2.4.0
   ("tested with Kotlin 2.0.0–2.4.20-Beta1"; Gradle up to latest). Remove the fallback.

### Recommendation
**Decouple the GFM/Dokka-format switch from the 0.2.0 consumer-enablement PR.** Keep
Dokka HTML output + the existing `docs/api/` HTML sync gate as today (HTML is stable/
beta-confirmed); ship A+B+C+D+E (Android target, KSP publish, Kotlin 2.4.10, abiValidation
migration, version bump) on their own. Put the GFM-Markdown switch in a **separate,
opt-in** task verified against the real `dokkaGeneratePublicationGfm` task name
(empirically, in a real Step-0 — not prototypes that don't exist). Rationale: the GFM
switch is the only item whose verification is fabricated, and GFM is Alpha — not worth a
real-release CI gate. The consumer-enablement (the whole point) has zero dependency on
output format.

Bottom line: v2's **build/toolchain changes (A/B/C/D/E) are correct** (once the two
stale items above are dropped). The **Dokka/GFM material is unverified + uses wrong API**
and must be de-scoped or properly re-done before approval.
