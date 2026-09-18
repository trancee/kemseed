# ADR-0003 — Adopt kompact 0.1.6 for AD-PDU bit-packing (ADR-0001 relaxation)

- **Status:** Accepted — *kompact `0.1.6` runtime + kompact-ksp `0.1.6` adopted (v1.5). Defects
  A & B (service-file, round-handling, expect/actual routing — fixed in 0.1.4) and defect #3
  (non-`val` ctor `raw` param, fixed upstream in 0.1.5 via PR #48) and defect #4 (missing `actual`
  modifier on the generated companion — fixed upstream in 0.1.6 via PR #51) are **all resolved**.
  The `mavenLocal()` bridge from v1.4 is **dropped**; the committed tree resolves `kompact` 0.1.6
  directly from Maven Central. `@KommutModel` codegen is **ON**: the processor LOADS, PARSES, and
  GENERATES `AdPduHeaderGenJvm.kt`/`AdPduHeaderGenIos.kt` into the correct platform trees with
  `public actual companion object` + `require(raw.size >= 1)` guards. Hand-written platform
  `actual`s are **deleted**; only the KSP-generated actuals remain. Green gate: `BUILD SUCCESSFUL
  in 21s`, `TOTAL tests=94 skipped=0 failures=0 errors=0` (commit `e3e55e5`).*
- **Date:** 2026-09-13 (adopted v1.0) · 2026-09-14 (kompact-ksp deferred, v1.1) · 2026-09-13 (kompact-ksp 0.1.2 wired, codegen defects A+B found, v1.2) · 2026-09-15 (kompact bumped to 0.1.4, codegen re-attempted live, generator defect #3 found, v1.3) · 2026-09-16 (kompact bumped to 0.1.5, defect #3 fixed upstream PR #48, defect #4 patched via mavenLocal bridge, v1.4) · 2026-09-17 (kompact bumped to 0.1.6, defect #4 fixed upstream PR #51, bridge dropped, codegen GREEN, v1.5)
- **Deciders:** project (trancee = kompact author; pqcble = consumer on Kotlin 2.4.20 / AGP 9.4.0 / Gradle 9.7.1)
- **Context ref:** `PROMPT.md` §1.b (Phase-1b AD-PDU envelope) + `.scratch/pqc-ble-mesh/issues/08-prototype-spec-outline.md` §1.6/§3 (Phase D)

## Context

Phase-1b (AD-PDU envelope) needs a deterministic, zero-allocation, **cross-platform**
bit-packer for the secured-PDU plaintext header (`version` | `pduType` | `reserved`,
sub-byte fields) that wraps the existing AES-256-GCM seal/open
(`ch.trancee.kemseed.Aes256Gcm`). Hand-rolled bit-twiddling would drift between the
Android (JVM) and iOS (Kotlin/Native) backends.

`ch.trancee.kompact:kompact:0.1.6` is a KMP library (The Unlicense) that ships exactly
the Android + iOS target set the protocol commits to, and provides two distinct surfaces:

- A **runtime** of zero-alloc, LSB-first bit-stream primitives (`KompactWriter`,
  `KompactRuntime.readBits/writeBits`, `ScalarType`, `KompactFraming`) — used here.
- A **KSP processor** (`kompact-ksp` 0.1.6) that validates `@KompactModel` field layout at
  compile time and emits the platform `actual` value-class accessors
  (`get() = KompactRuntime.readBits(raw, off, w)`). 0.1.6 resolves all prior generator defects
  (A/B service-file + round-handling + expect/actual routing fixed in 0.1.4; defect #3 non-`val`
  ctor `raw` fixed upstream in 0.1.5 via PR #48; defect #4 missing `actual` on the generated
  companion fixed upstream in 0.1.6 via PR #51) — see the amendment history for the defect log.

`kompact` (runtime) has **zero transitive runtime dependencies** (kotlin-stdlib only).
The processor (`kompact-ksp`) is compile-time-only (kotlinpoet-jvm 2.4.0).

## kompact-ksp 0.1.2 — service-file fix landed, codegen still blocked

`kompact-ksp` 0.1.2 **fixes the KSP 2.x service-file registration** that blocked 0.1.1:

- 0.1.1 registered the provider under the legacy KSP-1.x file
  `META-INF/services/com.google.devtools.ksp.SymbolProcessorProvider` (never scanned by KSP 2.x)
  while the class itself implements the KSP-2.x interface
  `com.google.devtools.ksp.processing.SymbolProcessorProvider` ⇒ `No providers found in processor
  classpath` (recorded verbatim in v1.1).
- 0.1.2's published jar registers `…META-INF/services/com.google.devtools.ksp.processing.SymbolProcessorProvider`
  → `ch.trancee.kompact.ksp.KompactSymbolProcessorProvider` (ground-truthed from the unpacked 0.1.2
  service file + `javap` confirming the class implements the `com.google.devtools.ksp.processing.*` interface).

**Verified live on pqcble (KSP 2.3.12, Kotlin 2.4.20):** `:kspAndroidMain` now loads the
processor — `/tmp/ksp_info.txt` shows:

```
i: [ksp] loaded provider(s): [ch.trancee.kompact.ksp.KompactSymbolProcessorProvider]
i: [ksp] KompactKSP: processing AdPduHeader (3 fields, 8 bits, 1 bytes)
```

The first line proves the 0.1.2 service-file fix; the second proves the processor **parses the
`@KompactModel` expect value class correctly** (3 fields, 8 bits, 1 byte — exactly the pinned
`version(4)|pduType(3)|reserved(1)` layout in `AdPduHeader`). So 0.1.2's packaging fix is real
and the validator (`LayoutValidator.validateWidths` / `validateNoOverlaps`) passes.

**However, codegen then fails — `:kspAndroidMain` → `KSP failed with exit code: PROCESSING_ERROR`.**
Two defects in `kompact-ksp` 0.1.2's `ValueClassGenerator` / `KompactSymbolProcessor` block the
`@KompactModel` codegen path for pqcble's KMP `expect value class`:

### Defect A — round-handling: `FileAlreadyExistsException` on re-process

`KompactSymbolProcessor.process()` (read from the 0.1.2 `sources.jar`) filters symbols with
`getSymbolsWithAnnotation(KOMPAT_MODEL_FQN).filterIsInstance<KSClassDeclaration>().filter {
it.validate(enableNewFeatures = true) }` and only *returns* (marks consumed) the declarations
that pass the filter. For an `expect value class`, `validate(enableNewFeatures = true)` returns
**false** in early KSP rounds (an `expect` isn't "fully resolved" until its platform `actual`s
exist — which don't yet, since ksp hasn't emitted them). Because the filtered-out symbol is
returned un-consumed, **KSP re-queues it** in the next round and `process()` runs again on the
same `@KompactModel` symbol.

Evidence (same log): `KompactKSP: processing AdPduHeader …` appears **twice** — one per round.
Round 2 calls `createNewFile(packageName="ch.trancee.kemseed.pdu", fileName="AdPduHeaderGen")`
again; KSP 2.x's `createNewFile` is single-shot per `(packageName, fileName)` in an invocation, so
it throws `FileAlreadyExistsException` whose message is the target path. `KompactSymbolProcessor`'s
`writeFile` swallows it in `catch { logger.error("KompactKSP: failed to process …: ${e.message}") }`
— so the on-disk symptom is the error logging the Gen.kt path:

```
e: [ksp] …/AdPduHeader.kt:90: KompactKSP: failed to process ksp.com.google.devtools.ksp.common.impl.KSNameImpl@466fee3:
   /Users/phil/Projects/pqcble/build/generated/ksp/android/androidMain/kotlin/ch/trancee/kemseed/pdu/AdPduHeaderGen.kt
```

### Defect B — generated `expect` is routed to the platform (not `commonMain`)

`kompact-ksp` binds `@KompactModel` processing to the **per-platform** KSP configs
(`kspAndroid`/`kspIos` ⇒ `kspAndroidMain`/`kspKotlinIos`) rather than
`kspCommonMainMetadata`. `ValueClassGenerator::processModel` therefore writes the common
`expect value class` (file `AdPduHeaderGen.kt`, package `ch.trancee.kemseed.pdu`) — which is
supposed to live in **commonMain** — into the **platform** generated tree. Captured on the 0.1.2
run: the expect landed at `build/generated/ksp/android/androidMain/kotlin/ch/trancee/kemseed/pdu/AdPduHeaderGen.kt`
(the android source set), and the ios actual likewise into `…/ios/…`. For Kotlin Multiplatform an
`expect` must be declared in a **common** source set; an expect in a platform source set is
unmatchable, which is why `:compileKotlinIos` fails with `The 'expect' declaration 'AdPduHeader' has
no 'actual' declaration in module '<commonMain> for Native'` once ksp aborts (Defect A) and emits
no platform actual. The catalog confirms `kspCommonMainMetadata` exists (the correct common config),
so binding the processor there (plus separating common-expect emission from per-platform actual
emission) is the intended shape.

> Note on Defect A vs. the generated-file package: `ValueClassGenerator::generateJvmActual` builds
> the `FileSpec` with `spec.packageName` (`ch.trancee.kemseed.pdu`) but the processor calls
> `writeFile(packageName = "$packageName.jvm", …)` ⇒ the actual is *written* under a `…/jvm/`
> path yet declares `package ch.trancee.kemseed.pdu`. Kotlin does not enforce directory==package, so
> this is cosmetic for compilation (the actual still resolves for `androidMain`); it is *not* the
> blocking failure — Defects A and B are.

### KSP version

`ssp = "2.3.12"` (bumped from the originally-assumed `2.3.10` on the v1.1 hypothesis that KSP 2.3.10
was the 2.4.20 pairing). 2.3.12 is the **latest** KSP line — **no `2.4.x` KSP exists** (KSP ships on
the 2.3.x line for Kotlin 2.4.x). The provider load is attributable to kompact-ksp 0.1.2's
service-file fix (any KSP 2.x scans the relocated path), not to the 2.3.10→2.3.12 minor bump; the
bump is for currency with the latest 2.4.x-compatible KSP + to pick up KSP fixes since 2.3.10.

## Decision

Adopt the `ch.trancee.kompact:kompact:0.1.4` **runtime** as the **single, bounded exception** to
ADR-0001 §"zero external dependencies" (stdlib-only, no device-runtime impact). `kompact-ksp`
0.1.4 is **wired** (the `ksp` plugin + `kspAndroid(libs.kompactKsp)` + `add("kspIos", …)`) and
**verified loadable + generating** under KSP 2.3.12, but its codegen is **disabled** pending the
generator defect #3 below is fixed upstream — so `AdPduHeader` is shipped **hand-written** (plain
`expect value class` + `@JvmInline`/plain platform `actual`s using `KompactRuntime.readBits`),
which is **byte-for-byte the accessor shape `ValueClassGenerator` intends** (`get() =
KompactRuntime.readBits(raw, off, w)`).

- **Runtime surface pulled by pqcble:** `kompact` 0.1.4 only — kotlin-stdlib transitive (no other
  runtime deps). The 0.1.4 runtime API is byte-identical to 0.1.2 (`readBits/writeBits`,
  `KompactWriter`, `ScalarType.of`).
- **Kotlin / AGP / Gradle / JDK:** Kotlin 2.4.20, AGP 9.4.0 (android-library KMP), Gradle 9.7.1,
  JDK 25 — matches `kompact` 0.1.4's compiled targets (avoids KMP klib-metadata skew on `iosArm64`).
- **JVM target:** Android pins `jvmTarget = JVM_21` to match `kompact`'s published bytecode target.
- **KSP:** applied (`alias(libs.plugins.ksp)`, `ksp = "2.3.12"`); `kspAndroid(libs.kompactKsp)` +
  `afterEvaluate { dependencies { add("kspIos", libs.kompactKsp) } }` (KGP 2.4 emits no `kspIos(…)`
  accessor and the `kspIos` config is created lazily — the `afterEvaluate` bind is required).
  With `@KompactModel` off, the processor finds no `@KompactModel` symbols → no-op → GREEN.
- **Usage:** `AdPduHeader` is a hand-written `expect value class` (commonMain) + platform `actual`s
  (`@JvmInline` on android JVM, plain on iosArm64 Native) reading via `KompactRuntime.readBits`.
  The write path uses `KompactWriter` (`encodeAdPduHeader`); the read accessors are zero-alloc.
  Layout is pinned by the bit-exact TDD goldens in `AdPduTest` (`0x01`/`0x21`/`0xB1` encode +
  round-trip reads), giving equivalent protection to kompact's compile-time `LayoutValidator`
  for this 3-field, 8-bit header.

### Re-enabling `@KompactModel` codegen (upstream fix required)

Re-enabling pqcble is gated on **Defects A and B** (both **fixed** in kompact-ksp 0.1.4 — the
processor now loads/parses/generates without `FileAlreadyExistsException` and routes the
expect/actuals to the correct platform trees) **AND on a residual generator defect #3** below,
plus the ios-binding anomaly:

- Defect A: ✅ fixed in 0.1.4 (round-safe — `[mode=JVM]` process log appears once, no `FAE`).
- Defect B: ✅ fixed in 0.1.4 (expect/actuals emit into the correct platform trees).
- **Defect #3 (residual, blocks re-enablement):** `ValueClassGenerator.buildActual` emits the
  `raw` payload-field as a *non-`val`* constructor parameter **plus** a body
  `public actual val raw: ByteArray` with no initializer. Kotlin rejects this inside a
  `@JvmInline value class`:
  - `Value class primary constructor must only have final read-only ('val') property parameters`
    (the constructor arg `raw: ByteArray` lacks `val`).
  - `Property must be initialized or be abstract` + `Value class cannot have properties with
    backing fields` (the body `actual val raw` re-declares `raw` as a 2nd property with a backing
    field but no initializer).
  This was confirmed empirically: `:compileAndroidMain` on the 0.1.4-generated
  `AdPduHeaderGenJvm.kt` fails with the three errors above (full log `/tmp/stage2_compile_jvm.txt`).
  kommut's *hand-written* `ScalarType` actual uses `public actual val raw: ByteArray` **on the
  constructor** (one property, init'd) — the generator's `buildActual` deviates from this. Fix
  needed in `ValueClassGenerator.buildActual`: declare `public actual val raw` on the primary
  constructor (`raw: ByteArray` → `actual val raw: ByteArray`) and drop the body property, so
  the generated actual mirrors kommut's own `ScalarType` (and compiles as a 1-property value class).
- **ios-binding anomaly (separate, secondary):** `add("kspIos", libs.kompactKsp)` in `afterEvaluate`
  does **not** load the processor on `kspKotlinIos` (`:kspKotlinIos --info` ⇒ `BUILD SUCCESSFUL in
  838ms`, no `loaded provider(s)` line, no `KompactKSP` log, no `build/generated/ksp/ios/...` output).
  The android binding (`kspAndroid` aggregate) works; the ios binding does not. With `@KompactModel`
  off this is harmless (hand-written ios actual ships), but once defect #3 is fixed it must be
  resolved too or `AdPduHeaderGenIos.kt` is never generated. (TODO: isolate in a follow-up — the
  global `ksp{arg}` mode-routing also failed earlier; per-task modes require the binding to load
  first.)
- Plus: drop the `@KompactField`/`@KompactPreview`/`@KompactModel` from pqcble's hand-written
  expect (or delete the hand-written expect/actuals) so kompact's generated `expect` (class
  `AdPduHeader`) isn't a duplicate.

Once the upstream fix lands, in `AdPduHeader.kt` either (i) keep the hand-written expect and let
kompact emit only the actuals (if the processor supports expect-coexistence), or (ii) replace the
hand-written class with the `@KompactModel` schema and let kompact generate expect + actuals — TBD
against the fixed processor. The public API (`.raw`, `.version`, `.pduType`, `.reserved`,
`encodeAdPduHeader`, `PduType`) is intentionally identical to the codegen output, so consumer code
(`AdPduCrypto`, `AdPduTest`) is unchanged.

## Solved / Working — Green baseline (current)

With `@KompactModel` off and the hand-written expect/actuals in place, the repo builds GREEN on both
targets (`/opt/homebrew/bin/gradle :testAndroidHostTest :compileKotlinIos --rerun-tasks
--console=plain --no-build-cache`):

- ksp tasks run kompact-ksp 0.1.4 → processor loads (`loaded provider(s): …`) → no `@KompactModel`
  symbols → no-op → no generated output → no codegen defect triggered.
- `:compileKotlinIos` (iosArm64 native) ✅ · `:compileAndroidMain` ✅ · `:testAndroidHostTest` ✅.
- **94 tests, 0 skipped, 0 failures, 0 errors** (Aes256Gcm 14, Aes256 3, Gmac 5, Hkdf 8,
  Hmb1Handshake 19, Keccak 13, MlKem512Property 4, MlKem512 6, X25519 4, AdPdu 18).

## Alternatives considered

- **`@KompactModel expect value class` + hand-written actuals (the 0.1.1 plan).** Blocked under 0.1.1
  (service file) and 0.1.2 (Defects A + B above). Kept the `kompact`/`ksp`/`kompactKsp` catalog
  coordinates and `AdPduHeader`'s value-class API intact so this stays a drop-in swap once fixed.
- **Inline bit-twiddling (no kompact).** Rejected — drifts between JVM and Native, no zero-alloc
  primitives, no shared schema. kompact's runtime avoids exactly this.
- **Adopt kompact + a plain (non-`expect`) `@KompactModel` value class.** Rejected — kompact-ksp
  emits the `expect`+`actual`s itself; a plain `@KompactModel` class would be a duplicate symbol
  of the generated expect, and the generator (Defect B → now fixed in 0.1.4, but defect #3 remains)
  would still collide with a hand-written class.
- **Local KSP-1.x service shim / downgrade Kotlin to 2.3.x.** Rejected — kompact 0.1.4's runtime
  targets Kotlin 2.4.x (klib-metadata); downgrading Kotlin to chase a pre-0.1.4 ksp breaks the
  iosArm64 klib contract and is a worse tradeoff than hand-writing the 3 accessors.

## Risks

- **Supply-chain:** one external dependency (kompact runtime, stdlib-only, The Unlicense). Acceptable:
  it replaces a hand-rolled, error-prone bit-pack layer and removes a class of layout bugs.
- **kompact-ksp deferral:** the `@KompactModel` compile-time layout validation (Ticket 06
  non-overlap) is not enforced. Mitigated by the bit-exact TDD goldens (`AdPduTest`) pinning both
  the encode byte and the read-back field values for all 3 fields.
- **Kotlin / toolchain:** 2.4.20 / AGP 9.4.0 / Gradle 9.7.1 / JDK 25 (required by kompact runtime).
- **KMP expect/actual flag:** `-Xexpect-actual-classes` retained (kompact's published runtime
  declares `expect`/`actual` value classes e.g. `ScalarType` consumed on iosArm64).
- **Upstream-fix dependency (RESOLVED in v1.5):** defect #3 fixed upstream in 0.1.5 (PR #48) and
  defect #4 fixed upstream in 0.1.6 (PR #51) — both now in the committed tree. The ios-binding
  anomaly is resolved by the Stage-2 `kspKotlinIosProcessorClasspath` binding + per-task
  `kompact.generate=ios` mode routing (`AdPduHeaderGenIos.kt` now generates correctly).
  `@KommutModel` codegen is ON; hand-written actuals are deleted.

## Migration — current state (kompact 0.1.6)

> **Provenance (attribution):** the KSP build wiring listed below — the `ksp` plugin; root
> `dependencies { kspAndroid(libs.kompactKsp) }`; the `afterEvaluate` bindings `add("kspIos", …)`
> + `add("kspKotlinIosProcessorClasspath", …)` (binds the processor to the ios KSP task
> classpath); the per-task `kompact.generate=jvm|ios` routing via
> `KspAATask.commandLineArgumentProviders`; `commonMain` `implementation(libs.kompact)`;
> `-Xexpect-actual-classes` on common/android/ios; and the absence of any `mavenLocal()` mirror —
> is the **committed state at base `5cbaf7c`** ("Stage 2: enable KSP codegen of AdPduHeader
> expect; drop hand-written platform actuals") and is **unchanged by v1.5**. v1.5 = commit
> `e3e55e5` ("Bump kompact 0.1.5 -> 0.1.6"), a **version-only** bump (`kompact`/`kompactKsp`
> 0.1.5 → 0.1.6) that pulls the upstream defect-#4 fix (PR #51); it introduces **no build-logic
> change** vs `5cbaf7c`, which already had codegen ON and dropped the `mavenLocal()` bridge.

- `gradle/libs.versions.toml`: `kotlin=2.4.20`, `agp=9.4.0`, `kompact=0.1.6`, `kompactKsp=0.1.6`,
  `ksp=2.3.12`; ksp wired-**on** (codegen active, see §Decision).
- `build.gradle.kts`: `ksp` plugin applied; root `dependencies {}` binds
  `kspAndroid(libs.kompactKsp)`; `afterEvaluate` adds `kspIos` + `kspKotlinIosProcessorClasspath`
  (the latter binds the processor to the ios KSP task classpath — resolves the v1.3 ios anomaly);
  per-task `kompact.generate=jvm|ios` mode routing via `KspAATask.commandLineArgumentProviders`
  (`kspAndroidMain`→jvm, `kspKotlinIos`→ios); `commonMain` `implementation(libs.kompact)`;
  `-Xexpect-actual-classes` on common/android/ios; no `mavenLocal()` mirror.
- `AdPduHeader.kt` (commonMain): `@KommutModel expect value class AdPduHeader(raw: ByteArray)` —
  `@KompactField`-annotated `version`/`pduType`/`reserved` + `encodeAdPduHeader` + `PduType` enum
  + `AD_PDU_VERSION`/`AD_PDU_HEADER_BITS` constants. `@KommutModel` ON → KSP generates the platform
  actuals (`AdPduHeaderGenJvm.kt`/`AdPduHeaderGenIos.kt`).
- `AdPduHeader.kt` (androidMain / iosMain): **deleted** — replaced by the KSP-generated actuals.
- `AdPduCrypto.kt`: `UnsealedAdPdu(header, payload)`; `seal(dir, seqno, key, header, payload,
  aad = EMPTY_AAD): ByteArray` over `header.raw ‖ payload`; `unseal(...): UnsealedAdPdu?`.
- `AdPduTest.kt`: TDD — bit-exact encode goldens + independent OpenSSL `cryptography.AESGCM`
  seal/unseal oracles + tamper/seqno/direction/key/aad rejection + monotonic-distinctness (18 tests).
  94 total tests, 0 failures.

---

### ADR-0003 v1.2 amendment (2026-09-13) — kompact-ksp 0.1.2 wired, codegen defects found

Per owner directive "kompact 0.1.2 is now available with the fix," the 0.1.2 service-file fix
was verified live: the processor loads under KSP 2.3.12 and parses the `@KompactModel` expect
correctly (`3 fields, 8 bits, 1 bytes`). Two codegen defects remain in 0.1.2 (Defects A:
round-handling `FileAlreadyExistsException` on the generated `Gen.kt`; B: the common `expect` is
emitted into the platform (`kspAndroidMain`/`kspKotlinIos`) generated tree instead of
`commonMain`, so ios finds no actual). The repo is left **GREEN**
(`:testAndroidHostTest :compileKotlinIos --rerun-tasks` → BUILD SUCCESSFUL, 94/94 tests) using
hand-written expect/actuals (byte-identical to `ValueClassGenerator` output) with `ksp` +
`kompact-ksp` 0.1.2 wired-but-idle. `@KompactModel` codegen is **deferred** pending the upstream
fix to Defects A + B; re-enabling instructions are in §"Re-enabling `@KompactModel` codegen".

---

### ADR-0003 v1.3 amendment (2026-09-15) — kompact bumped to 0.1.4, codegen re-attempted, generator defect #3 found

Per owner directive "kompact has been fixed and released as 0.1.4, check it out and try again,"
the catalog was bumped to `kompact = 0.1.4` / `kompactKsp = 0.1.4` (`KommutRuntime`-API is
unchanged vs 0.1.2) and the full 0.1.4 codegen path was re-attempted live. Outcome:

- **Defect A ✅ + Defect B ✅ are FIXED in 0.1.4.** `gradle :kspAndroidMain --info` shows
  `loaded provider(s): [ch.trancee.kompact.ksp.KompactSymbolProcessorProvider]` +
  `KompactKSP: processing AdPduHeader (3 fields, 8 bits, 1 bytes) [mode=JVM]`
  (log `/tmp/stage1_ksp.txt`), and `AdPduHeaderGenJvm.kt` is emitted to
  `build/generated/ksp/android/androidMain/kotlin/ch/trancee/kemseed/pdu/` — correct package,
  correct platform tree, no `FileAlreadyExistsException`, single `[mode=JVM]` process line.
  Defects A (round-handling) and B (expect/actual mis-routing) from v1.2 are resolved.
- **Residual generator defect #3 (distinct from A+B) — BLOCKS codegen.** `ValueClassGenerator.buildActual`
  (kommut 0.1.4 sources, `/tmp/k14`) emits the `raw` payload-field as a non-`val` constructor
  parameter **plus** a body `public actual val raw: ByteArray` with no initializer. Kotlin rejects
  this inside the `@JvmInline value class AdPduHeader`:
  ```
  e: .../AdPduHeaderGenJvm.kt:13:3  Value class primary constructor must only have final read-only ('val') property parameters.
  e: .../AdPduHeaderGenJvm.kt:15:17 Property must be initialized or be abstract.
  e: .../AdPduHeaderGenJvm.kt:15:17 Value class cannot have properties with backing fields.
  e: .../AdPduHeaderGenJvm.kt:51:20 Declaration must be marked with 'actual'.
  ```
  (empirical: `gradle :compileAndroidMain` on the generated file, log `/tmp/stage2_compile_jvm.txt`).
  kommut's *hand-written* `ScalarType` actual declares `public actual val raw: ByteArray` **on the
  constructor** (one property, initialized) — the generator's `buildActual` deviates from this.
  Fix required upstream: `buildActual` must emit `public actual val raw: ByteArray` on the primary
  constructor and omit the redundant body property, so the generated `AdPduHeader` actual mirrors
  `ScalarType` and compiles as a 1-property value class.
- **ios-binding anomaly (secondary, reproducible).** The per-task-mode wiring
  (`KspAATask.commandLineArgumentProviders` → `kompact.generate=jvm|ios`) compiles and applies
  `jvm` mode on `kspAndroidMain` (confirmed `[mode=JVM]`), but the generated actuals cannot compile
  (defect #3) AND kommut is **not** loaded on `kspKotlinIos`: `gradle :kspKotlinIos --info` ⇒
  `BUILD SUCCESSFUL in 838ms`, no `loaded provider(s)` line, no `KompactKSP` log, no
  `build/generated/ksp/ios/...` — so `AdPduHeaderGenIos.kt` is never produced.
  `add("kspIos", libs.kompactKsp)` in `afterEvaluate` therefore does not bind the processor on the
  ios KSP task (in the GREEN baseline this was masked: hand-written ios `actual` shipped, so kommut
  on ios was irrelevant). With defect #3 blocking the jvm actual anyway, the ios anomaly is tracked
  but deferred.
- **Full build fails** (expected — defect #3 + missing ios actual): `:compileKotlinIos` ⇒
  `expect declaration 'AdPduHeader' has no 'actual' declaration in module '<commonMain> for Native'`,
  `BUILD FAILED` (log `/tmp/stage2_full.txt`).

**Rollback to GREEN:** `@KompactModel` left **OFF** in `commonMain`; hand-written `@JvmInline`
(android) + plain (ios) `actual` `AdPduHeader(raw)` restored; the per-task
`kompact.generate` arg wiring removed; `ksp` + `kompactKsp` 0.1.4 kept wired-but-idle
(`kspAndroid(libs.kompactKsp)` + `afterEvaluate { add("kspIos", …) }`). Verified:
`/opt/homebrew/bin/gradle :testAndroidHostTest :compileKotlinIos --rerun-tasks --console=plain
--no-build-cache` ⇒ **`BUILD SUCCESSFUL in 10s`**, `TOTAL tests=94 skipped=0 failures=0 errors=0`
(log `/tmp/rollback_green.txt`). The repo ships GREEN on kommut 0.1.4 with codegen disabled; the
kommut-generator bug #3 + ios-binding anomaly are filed upstream (sources + generated file + the
hand-written `ScalarType` reference attached) for the next `kommut-ksp` release.



`kompact-ksp` 0.1.1's provider class implements the KSP-2.x
`com.google.devtools.ksp.processing.SymbolProcessorProvider` but is registered under the legacy
`META-INF/services/com.google.devtools.ksp.SymbolProcessorProvider` file; KSP 2.x scans only the
relocated path, so `:kspAndroidMain` reported `e: [ksp] No providers found in processor classpath`.

### ADR-0003 v1.0 (2026-09-13) — initial adoption (kompact runtime + kompact-ksp)

Superseded by v1.1 (kompact-ksp deferral), v1.2 (0.1.2 service-file verified, codegen defects
A+B found, ksp re-wired as idle-but-loaded), and v1.3 (kompact bumped to 0.1.4; A+B fixed but
generator defect #3 + ios-binding anomaly found; ksp idle-but-loaded at 0.1.4, hand-written
actuals ship, 94/94 tests green).

### ADR-0003 v1.4 amendment (2026-09-16) — defect #3 fixed upstream (PR #48, CI green)

Per decision **B** (wait for the upstream release rather than build against a
local snapshot), this section records the defect-#3 fix outcome so Stage 2 can
land cleanly once `kompact` ships `0.1.5`.

The residual **generator defect #3** — the processor emitted the model `raw`
`ByteArray` as a non-`val` primary-constructor parameter plus a separate body
property, which Kotlin rejects for a value class
(`VALUE_CLASS_CONSTRUCTOR_NOT_FINAL_READ_ONLY_PARAMETER`: "Value class primary
constructor must only have final read-only ('val') property parameters";
"Value class cannot have properties with backing fields") with a cascading
"Declaration must be marked with 'actual'" at the companion `create()` — is
**fixed upstream**. **No kotlinpoet patch is required**: kotlinpoet 2.4.0
already supports constructor-`val` emission via the
`PropertySpec(initializer=name)` + same-named `primaryConstructor` parameter
merge idiom (runtime-verified: emits `public actual val raw: ByteArray,` on the
constructor — trailing comma = constructor parameter, zero body property —
matching the hand-written `VehicleTelemetry` reference). The processor had
simply not invoked `.initializer("raw")` in `buildActual`; that invocation is
now added.

Residual kotlinpoet gap — **expect form only, not required by pqcble**:
kotlinpoet forbids `PropertySpec` initializers in `expect` classes ("properties
in expect classes can't have initializers") and exposes no val modifier for
`ParameterSpec`, so a `val` cannot be placed on an `expect value-class`
constructor parameter via the high-level API. The processor drops the invalid
`actual` from the expect's `raw` (expect members must not be `actual`) and
emits it as an abstract body property; consumers hand-write their `expect`
declaration (pqcble does — it runs the processor in `jvm`/`ios` modes only,
never `common`). Documented as a known kotlinpoet limitation; does not affect
pqcble.

**Upstream defect log.**
- defect #3 (raw constructor `val`) — fixed in `kompact` 0.1.5 via PR #48; all CI
  `SUCCESS` (`kompact-ksp:test` 27/27, `koverVerify`, `checkKotlinAbi`, `spotlessCheck`,
  dokka, CodeQL). See L349-374 above.
- defect #4 (companion `actual`) — **NOT fixed in 0.1.5**. Bytecode of the published
  0.1.5 `ValueClassGenerator.buildActual` calls `TypeSpec.companionObjectBuilder()` with
  no `.addModifiers(KModifier.ACTUAL)`; only the inner `create` receives `actual`.
  Kotlin rejects an `actual companion object` declared without the `actual` modifier
  ("Declaration must be marked with 'actual'") for nested declarations in an
  `actual value class`. Generated actuals emit `public companion object {` (no
  `actual`) -> `:compileKotlinIos` / `:testAndroidHostTest` fail.

**Upstream fix (PR #51 to `kompact`, base `main`).** `ValueClassGenerator.buildActual`:
append `.addModifiers(KModifier.ACTUAL)` to the `companionObjectBuilder()` chain
(1-line; `buildExpect` untouched). Adds two regression tests in
`ValueClassGeneratorTest` (`jvm` / `ios` actual companion marked `actual`),
asserting `contains("actual companion object")`. `kompact-ksp:test` -> `BUILD SUCCESSFUL`
(27 + 2 new).

**pqcble Stage 2 — GREEN (proof via local `mavenLocal()` bridge).** With `kompact` 0.1.5
+ defect-#3 fix and the defect-#4 patch bridged through local `mavenLocal()` (a
`settings.gradle.kts` mirror, reverted/uncommitted — not part of this tree), Stage 2
lands:
- `@KommutModel` ON in `commonMain` `AdPduHeader` (expect); hand-written
  `androidMain` / `iosMain` `AdPduHeader.kt` actuals DELETED.
- per-source-set `kompact.generate=jvm|ios` routed via `KspAATask.commandLineArgumentProviders`
  (`kspAndroidMain`->jvm`, `kspKotlinIos`->ios`; `kspKotlinIosProcessorClasspath` ios bind).
- generated `AdPduHeaderGenJvm.kt` / `AdPduHeaderGenIos.kt` now emit
  `public actual companion object` (defect-#3 `require(raw.size >= 1)` guard present).
- exact gate (JDK 21): `/opt/homebrew/bin/gradle :testAndroidHostTest :compileKotlinIos
  --rerun-tasks --console=plain --no-build-cache` -> `BUILD SUCCESSFUL`,
  `tests=94 skipped=0 failures=0 errors=0`.

**pqcble commit status.** `build.gradle.kts` (kommut wiring),
`gradle/libs.versions.toml` (`kompact=0.1.5`), `commonMain` expect,
`commonTest` goldens (94, incl. `raw==[0x21]`, untouched), ADR-0003 v1.5. The
`androidMain` / `iosMain` `AdPduHeader.kt` hand-written actuals are deleted; only
the ksp-generated `...GenJvm` / `...GenIos` actuals remain. Settings intentionally
carries NO `mavenLocal()` mirror (clean tree resolves `kompact` 0.1.5 from Maven Central).

**Migration / status.** Committed tree is GREEN only with the local `mavenLocal()`
bridge (defect-#4 patch on `kompact` 0.1.5); on a clean env it resolves `kompact-ksp`
0.1.5 (buggy) from Maven Central -> red. Status: `kompact` PR #51 awaiting review +
`0.1.6` release. On release: no pdcble toml bump (published 0.1.6 fixes defect #4)
— drop the bridge. Until then: (a) wait for 0.1.6, or (b) apply the 1-line
`buildActual` patch locally + a local `mavenLocal()` mirror.

### ADR-0003 v1.5 amendment (2026-09-17) — kompact 0.1.5 → 0.1.6, defect #4 fixed upstream (version-bump-only; no build-logic change vs 5cbaf7c)

Per owner directive "kompact 0.1.6 is now available and fixes defect #4 for both JVM and iOS
targets," the catalog was bumped `kompact = 0.1.6` / `kompactKsp = 0.1.6` (`e3e55e5` Bump kompact
0.1.5 -> 0.1.6). 0.1.6 carries PR #51's 1-line `buildActual` fix: `.addModifiers(KModifier.ACTUAL)`
appended to the `companionObjectBuilder()` chain, so the generated companions emit
`public actual companion object` rather than the bare `public companion object` that 0.1.5
rejected with "Declaration must be marked with 'actual'".

**Status change:** the local `mavenLocal()` bridge from v1.4 is **no longer needed** — the
committed tree resolves `kompact` 0.1.6 (defect-#4 fix included) directly from Maven Central.
`settings.gradle.kts` carries only `google()` + `mavenCentral()` (no `mavenLocal()` mirror).

**Green gate (clean tree, JDK 21, no bridge):**
`/opt/homebrew/bin/gradle :testAndroidHostTest :compileKotlinIos --rerun-tasks --console=plain
--no-build-cache` → **BUILD SUCCESSFUL in 21s**, `TOTAL tests=94 skipped=0 failures=0 errors=0`.
Generated artifacts:
- `build/generated/ksp/android/androidMain/kotlin/ch/trancee/kemseed/pdu/AdPduHeaderGenJvm.kt` —
  `public actual companion object` + `require(raw.size >= 1)` guard (defect #3 satisfied).
- `build/generated/ksp/ios/iosMain/kotlin/ch/trancee/kemseed/pdu/AdPduHeaderGenIos.kt` —
  `public actual companion object` (defect #4 satisfied for iOS target too).
Both actuals are now emitted (the v1.4 ios-binding anomaly is resolved by the Stage-2
`kspKotlinIosProcessorClasspath` binding + per-task `kompact.generate=ios` mode routing), so
`./gradlew :compileKotlinIos` succeeds without the hand-written ios `actual`.

**Codegen is ON** — `@KommutModel` is enabled on the `commonMain` `expect value class
AdPduHeader`; the hand-written `androidMain`/`iosMain` `AdPduHeader.kt` actuals are deleted;
only the KSP-generated `...GenJvm`/`...GenIos` actuals remain. The per-source-set
`kompact.generate=jvm|ios` mode routing (via `KspAATask.commandLineArgumentProviders`)
emits exactly one platform actual per KSP task, preventing expect/actual duplicates.

**Downstream impact:** zero — `AdPduHeader`'s public API (`.raw`, `.version`, `.pduType`,
`.reserved`, `encodeAdPduHeader`, `PduType`) is identical to the codegen output, so
`AdPduCrypto.kt` and `AdPduTest.kt` (94 tests, incl. `raw==[0x21]` golden) are unchanged.

**v1.4 supersession:** the v1.4 "Migration / status" paragraph (which described the 0.1.5
state as GREEN-only-with-bridge) is superseded by this amendment — 0.1.6 resolves defect #4
upstream and the bridge is dropped; the committed tree is GREEN on a clean environment
resolving from Maven Central.
