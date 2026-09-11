# Task: Scaffold repo — package structure, CONTEXT.md glossary, docs/adr/

Status: resolved
Claimed by: work-through session (agent)
Resolved by: work-through session (agent); 2026-09-10
Type: task
Blocked by: (none)

## Question

Create the implementation scaffolding so a code-gen agent can begin:

1. A `hybrid_pqc_ble_mesh/` package/module. Language TBD — Kotlin Multiplatform is the likely target given the mobile BLE focus and the Kotlin/AGP toolchain conventions in `AGENTS.md`; confirm via repo language signals, or treat as a decision for #05-adjacent scoping.
2. A root `CONTEXT.md` with the domain glossary (terms: PQC, BLE, MTU, ATT_MTU, KEM, CSIDH, ML-KEM, GMAC, PFS, etc.) — the `/domain-modeling` skill populates this lazily; seed it now.
3. A `docs/adr/` directory ready for ADRs (e.g., ADR-0001: adopt CSIDH-512 as the over-the-air KEM, once #05 resolves).

This unblocks domain-modeling and any code-gen effort. Resolve by completing the scaffolding and linking from the map.

## Answer

**Decision (work-through session, 2026-09-10): scaffold complete, verified, and named.**

- **Name (decided with the user, 2026-09-10): the library is `isogeny`.** Gradle module/root = `isogeny`; Kotlin package `ch.trancee.isogeny`; AGP `namespace = "ch.trancee.isogeny"`; facade `object Isogeny` (+ `ProtocolPhase` enum). Chosen from {isokem, pqcble, blekem, meshkem, isogeny} — `isogeny` names the project's distinctive core (the CSIDH isogeny-group action), is pronounceable, and sits cleanly at `ch.trancee.isogeny` (org given as `ch.trancee`). The wire protocol id `PROTOCOL_NAME = "hybrid-pqc-ble-mesh"` and the destination spec doc `hybrid_pqc_ble_mesh_spec.md` (named in `PROMPT.md`) are intentionally left unchanged — those are the protocol/spec identity, distinct from the library name.
- **Amendment (H3 naming decision, 2026-09-11):** CSIDH-512 was ruled infeasible over the air in Pure-Kotlin (#10 spike), so the CSIDH-motivated name — `isogeny`/`ch.trancee.isogeny`/`object Isogeny`/`K_isogeny` — is **superseded**. Renamed to the architecture-neutral **`kemseed` / `ch.trancee.kemseed` / `object KemSeed` / `K_seed`** (valid under every #11 candidate). Wire id `hybrid-pqc-ble-mesh` + spec doc name unchanged. `PROMPT.md` left as the verbatim original input prompt (still CSIDH-framed). Build re-verified after rename: `:compileCommonMainKotlinMetadata :compileAndroidMain :bundleAndroidMainAar :compileKotlinIos` → BUILD SUCCESSFUL.
- **Structure:** single-project Gradle build — root IS the library (no subproject), so there is exactly one project `isogeny` over the `pqcble` repo dir.
- **Build:** Gradle 9.7.1 + Kotlin 2.4.10 + AGP 9.4.0 (latest stable, verified compatible). Used `com.android.kotlin.multiplatform.library` + `kotlin { android { namespace; compileSdk=36; minSdk=21 }; iosArm64("ios") }` — the AGP-9.0-required path (legacy `com.android.library` is incompatible with KMP since AGP 9.0; verified against developer.android.com/kotlin/multiplatform/plugin). `gradle/libs.versions.toml` version catalog; **zero runtime dependencies** (#libraries empty; stdlib implicit; CSIDH/ML-KEM Pure-Kotlin per ADR-0001).
- **Targets — Android + iOS devices only:** the `android` target (via `kotlin { android { namespace; compileSdk; minSdk } }`) + `iosArm64("ios")`. **iOS simulator targets intentionally omitted** — BLE does not work in the iOS simulator. Sources: `commonMain` (`Isogeny` + `ProtocolPhase`), `androidMain` / `iosMain` (`.gitkeep` expect/actual placeholders for Android Keystore / CryptoKit AES-GCM), `src/main/AndroidManifest.xml`.
- **Verification gates (all green, rebuilt after the rename):** `gradle :help` ✓ · `:compileCommonMainKotlinMetadata` ✓ · `:compileAndroidMain` ✓ · `:bundleAndroidMainAar` (manifest + AAR) ✓ · `:compileKotlinIos` (native klib, Xcode 26.6) ✓ — `BUILD SUCCESSFUL` (22 tasks, 3s). No `dev.pqcble` / `:hybrid_pqc_ble_mes` stragglers in build or source.
- **Docs:** root `CONTEXT.md` seeded with the domain glossary (PQC, BLE, ATT_MTU / 244 B budget, KEM, NIKE, CSIDH-512/1024 key sizes, ML-KEM-512, GMAC, AES-256-GCM, PFS, K_seed / K_df / transcript, phases A–D). `docs/adr/` ready (ADR-0001 present).

Effect: a code-gen agent can begin implementing the `isogeny` library against the verified KMP scaffold. **#10 (Pure-Kotlin CSIDH spike) is now unblocked** — it was gated on this scaffold and is the user's Option-C path to the #05 64-vs-128-byte KEM decision; #08 remains blocked on #10.

Sources:
- ADR-0001 (KMP / Android+iOS device / zero runtime deps / Pure-Kotlin fallback).
- Android Developers, "Set up the Android Gradle library plugin for KMP" (plugin id + `kotlin { android {} }` DSL; `com.android.library` deprecated for KMP since AGP 9.0).
- Installed toolchain: Gradle 9.7.1, Kotlin 2.4.10, Kotlin/Native, Android SDK (android-36, build-tools 36.0.0), Xcode 26.6.
