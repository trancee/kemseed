# R3: kompact upstream — Android target + kompact-ksp publish status

- **Type:** `research` (AFK — facts the kompact-defer re-check waits on)
- **Status:** RESOLVED — found 2026-09-18
- **Blocked by:** (none)
- **Informs:** kompact re-evaluation (ADR-0003 / #20 §kompact-adoption-path)

## Question

What is the current state of the kompact project (repo + Maven Central /
Gradle Plugin Portal publishes), and has the blocker from ADR-0003 / #20 been
cleared?

#20 §kompact-adoption-path defers: "hand-roll for 1b now; re-evaluate after
upstream ships (a) an Android KMP target and (b) a published `kompact-ksp`."
ADR-0003 notes the marker is currently 403/404 (upstream publishing break).

Confirm against primary sources:

1. Canonical kompact repo URL + latest release.
2. Does it ship an **Android** KMP target? (was none at decision time)
3. Is `kompact-ksp` **published** to Maven Central / Gradle Plugin Portal?
   (resolve the 403/404.)
4. Recent activity: PRs/commits last 90 days referencing Android target or KSP
   publishing.

## Deliverable

Findings at `docs/wayfinder/research/kompact-upstream-status.md`: the two
gate items (Android target, KSP publish) as pass/fail, last-release date,
and a one-line "re-evaluate kompact?" recommendation.

## Resolution (resolved in chart session — primary sources fetched 2026-09-18)

Findings: [`../research/kompact-upstream-status.md`](../research/kompact-upstream-status.md).

- Repo: `github.com/trancee/kompact` (owner `trancee`, 90 commits, matches kemseed).
- Latest release: **0.1.7** (2026-09-17 18:44 UTC).
- #20 gate (a) Android KMP target: **PASS** — `kompact/build.gradle.kts` declares `android {}`
  (`compileSdk=36`, `minSdk=21`, `withJava()`) alongside `iosArm64()` + `iosSimulatorArm64()` +
  `jvm()`.
- #20 gate (b) published `kompact-ksp`: **PASS** — Maven Central CDN returns
  `ch.trancee.kompact:kompact-ksp` 0.1.0→0.1.7 (latest `0.1.7`) and
  `ch.trancee.kompact:kompact` likewise `0.1.7`. **ADR-0003's "403/404 marker" is stale** —
  the transient upstream publishing break is resolved.
- KSP compat: `kompact-ksp` 0.1.7 targets "KSP 2.3.10–2.3.12+"; kemseed uses `ksp=2.3.12` →
  compatible.
- Gate **cleared** → spawned **D15** (adopt kompact for Phase-1b? owner decision; blocked on
  #20 1b PDV framing).
- Recommendation: amend `docs/adr/0003-stack-and-dependency-constraints-kompact-adoption.md` /
  #20 to flip the kompact gate from "wait for upstream" to "cleared — re-evaluate
  adopt-vs-hand-roll" pending #20 1b.
