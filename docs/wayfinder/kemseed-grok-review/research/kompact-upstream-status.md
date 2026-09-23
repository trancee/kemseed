# Research — kompact upstream: Android target + `kompact-ksp` publish status

Ticket: `03-research-kompact-upstream-status.md` (R3). Fetched 2026-09-18.

## Sources fetched (primary)

- `https://github.com/trancee/kompact` (repo + file tree).
- `https://raw.githubusercontent.com/trancee/kompact/main/settings.gradle.kts`.
- `https://raw.githubusercontent.com/trancee/kompact/main/build.gradle.kts` (`allprojects { group = "ch.trancee.kompact"; version = "0.2.0-SNAPSHOT" }`).
- `https://raw.githubusercontent.com/trancee/kompact/main/kompact/build.gradle.kts` (runtime targets + publication).
- `https://raw.githubusercontent.com/trancee/kompact/main/kompact-ksp/build.gradle.kts` (KSP module publication).
- `https://raw.githubusercontent.com/trancee/kompact/main/CHANGELOG.md`.
- `https://repo1.maven.org/maven2/ch/trancee/kompact/kompact-ksp/maven-metadata.xml` (Central CDN).
- `https://repo1.maven.org/maven2/ch/trancee/kompact/kompact/maven-metadata.xml` (Central CDN).

## Verdict — BOTH #20 §kompact-adoption-path gates are CLEARED

| #20 gate | Status | Evidence |
|---|---|---|
| (a) Android KMP target present? | ✅ YES | `kompact/build.gradle.kts`: `kmp` plugin + `android { namespace="ch.trancee.kompact"; compileSdk=36; minSdk=21; withJava() }` alongside `iosArm64()` + `iosSimulatorArm64()` + `jvm()`. |
| (b) `kompact-ksp` published? | ✅ YES | `kompact-ksp/build.gradle.kts` applies `portal-publish` + `maven-publish` (publication "Kompact KSP", JVM_17); Central CDN returns `ch.trancee.kompact:kompact-ksp` 0.1.0→0.1.7 (latest `0.1.7`, 2026-09-17 18:44 UTC). Runtime `ch.trancee.kompact:kompact` likewise `0.1.7`. |

- Repo: `github.com/trancee/kompact` (90 commits, owner `trancee` — matches kemseed).
- Latest release: **0.1.7** (2026-09-17). ADR-0003's "403/404 marker" is **STALE** — Central
  publishes are live as of 2026-09-17 (the prior 403/404 was a transient upstream
  publishing break, now resolved in `0.1.7`).
- KSP compatibility: `kompact-ksp` 0.1.7 is "compiled against KSP 2.3.10 for binary
  compatibility … for all consumers on KSP 2.3.10–2.3.12+"; kemseed uses `ksp=2.3.12` →
  **compatible**.
- Activity: two releases in two days (0.1.6, 0.1.7 — 2026-09-17); recent work:
  "round-safety + KMP expect/actual split via `kompact.generate` mode", `chore(deps): bump
  ksp 2.3.10→2.3.12`, `fix(ci): use packages input for setup-android@v4`.

## Note for ADR-0003 / #20

ADR-0003 records the kompact marker as "403/404 (upstream publishing break, not a
repo-config issue)." Fact-check: **not broken** — `ch.trancee.kompact:kompact-ksp:0.1.7`
resolves on Maven Central as of 2026-09-17. Recommend amending ADR-0003 / #20 to flip
the kompact-gate from "wait for upstream" to "gate cleared — re-evaluate adopt-vs-hand-roll."

## One-line for the map

Kompact re-evaluation gate MET → spawns **D15** (adopt kompact for 1b PDV envelope? owner
decision; still blocked on #20 1b framing).
