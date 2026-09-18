# kemseed

Deterministic, **zero external runtime-dependency** Kotlin Multiplatform serialisation for the
hybrid PQC-BLE mesh protocol. Platform `actual`s for protocol value classes are **KSP-generated**
by `ch.trancee.kompact:kompact-ksp` (0.1.6) from a single `@KommutModel` `expect` declared in
`commonMain` — no hand-written platform actuals, no runtime reflection.

The reference schema is the **AD-PDU plaintext header**
(`ch.trancee.kemseed.pdu.AdPduHeader`): an LSB-first, bit-packed 8-bit header
(`version` / `pduType` / `reserved`) with zero-allocation `readBits`/`writeBits` accessors.

> The crypto core stays strictly zero-dependency by policy — see
> [`docs/adr/0001-stack-and-dependency-constraints.md`](docs/adr/0001-stack-and-dependency-constraints.md).
> `kompact` 0.1.6 is the *only* relaxation: its runtime is `kotlin-stdlib` only (Unlicense), and
> `kompact-ksp` is compile-time-only (KotlinPoet; not shipped to devices). See
> [`docs/adr/0003-…kompact-adoption.md`](docs/adr/0003-stack-and-dependency-constraints-kompact-adoption.md).

## Targets

| Target | Notes |
|---|---|
| Android (`jvm`) | AGP 9.4, `compileSdk` 36, `minSdk` 21, `namespace = ch.trancee.kemseed`, JVM target 21 |
| iOS (`iosArm64("ios")`) | **device-only** arm64 — no simulator build (ADR-0001) |

## Build & test

Requires **JDK 25** (pinned via `org.gradle.jvm.toolchain=25` in `gradle.properties`). Uses the
included Gradle wrapper (9.7.1):

```bash
./gradlew :testAndroidHostTest :compileKotlinIos spotlessCheck
```

- `:testAndroidHostTest` — 94 tests (10 suites), 0 failures/errors/skips.
- `:compileKotlinIos` — KMP iOS binary target (needs macOS + Xcode).
- `:spotlessCheck` — ktfmt (`kotlinlangStyle`) format gate, `ratchetFrom = main`.

## Q1 repository gates (Constitution Q1)

- **Formatter:** Spotless + ktfmt 0.64 (`kotlinlangStyle`) on both `.kt` and `.kts`; pinned
  (`spotless` 8.10.2, `ktfmt` 0.64 — latest stable, verified against the Plugin Portal + Maven
  Central).
- **Static analysis:** `detekt` 1.23.8 is **not wired** — its Gradle-plugin Portal marker is
  unresolvable (HTTP 404 across all versions; Gradle fails at *resolution*, not configuration).
  The `:detekt` task (and CI step) are deferred until upstream republishes the marker; a
  custom `detekt-cli` task is also non-viable (1.23.8 not on Maven Central). See
  `docs/adr/0003`.
- **CI:** [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the gate above on
  `macos-14` (JDK 25) for every push/PR.

## Dependencies

- [`ch.trancee.kompact:kompact`](https://github.com/trancee/kompact):0.1.6 — Unlicense,
  kotlin-stdlib-only runtime (the only ADR-0001 relaxation).
- [`ch.trancee.kompact:kompact-ksp`](https://github.com/trancee/kompact):0.1.6 — Unlicense,
  compile-time-only (KSP 2.3.12, paired with Kotlin 2.4.20; KotlinPoet-generated).

Toolchain: Kotlin 2.4.20 · AGP 9.4.0 · Gradle 9.7.1 (pinned wrapper).

## Docs

- `docs/adr/0001-stack-and-dependency-constraints.md` — zero-runtime-dep policy, device-only iOS.
- `docs/adr/0002-crypto-gate-resolution.md`
- `docs/adr/0003-stack-and-dependency-constraints-kompact-adoption.md` — kompact 0.1.6 adoption,
  KSP codegen, §Migration attribution, defects #3/#4 fixes.

## License

`kemseed` is part of trancee's PQC-BLE-mesh implementation. `kompact` is released into the
public domain (Unlicense). See `docs/adr/0003` for the dependency-constraint rationale.
