# AGENTS

AI execution policy. Before repository mutation: load [`CONSTITUTION.md`](CONSTITUTION.md) fully; summary != source.

```text
R/X/D/O := Constitution notation
priority := CONSTITUTION > AGENTS > scoped docs/ADRs > config/templates/comments
conflict => higher priority + report; lower priority may refine, X weaken
```

## START

1. Load Constitution + task-scope docs/specs/ADRs.
2. Derive commands from repo scripts/metadata/build/CI; X assume stack/layout/framework.
3. Inspect worktree; preserve user/concurrent changes.
4. Map affected contracts/callers/tests/artifacts/platforms/docs/gates.
5. Non-trivial task => short ordered plan, checkable completion, exactly one active implementation step.

START complete iff behavior source-of-truth + proof commands known.

## PATH

- `feature|fix` => TDD: one behavioral test => run expected red => smallest complete implementation => run green => refactor green => repeat. Pre-change pass or setup-failure != red.
- `refactor` => establish green behavior check; preserve observable behavior; migrate all callers; delete obsolete path. Alias/dead path only if Q7 requires deprecation.
- `docs-only` => verify claims against source/config/executable commands; run repo link/markup/spelling/example checks; X unrelated app suite unless docs affect executable/generated content.
- `security|protocol|schema|persistence` => load applicable ADR; update/create O3 ADR; test applicable valid/invalid/incompatible/replayed/truncated/boundary cases.

## ASK

- Unclear requirement/constraint/outcome/material tradeoff OR human-only input => R use `ask` tool.
- Before ask: exhaust repo/docs/config/tools; X ask tool-answerable facts.
- Ask payload R self-contained `{objective,current behavior/state,exact unknown,why it matters,distinct options,each option's cost/risk/compatibility/irreversibility}`.
- O recommendation; if given R identify+justify against known constraints.
- R ask minimum blocking input; finish independent work first.
- X confirmation request when Constitution/docs/local convention determines answer.

## IMPLEMENT

- R existing compliant structure/naming; X parallel convention.
- R root-cause fix; X error suppression/fixture special-case/validation weakening.
- R requested scope; X unrelated cleanup/speculative retry/fallback/config/abstraction.
- Contract change => clean cutover: update all affected callers/platforms/tests/docs/examples/specs/compat records/generated artifacts/release metadata; delete obsolete paths.
- R repository formatter; X manual formatter workaround.
- Generated files => owning command only.
- Materially different compliant product/compat/security/maintenance choices => ASK.

IMPLEMENT complete iff zero repository-controlled consumer needs old behavior.

## VERIFY

1. Run narrow changed behavior/test/program path.
2. Run every applicable broader gate: format/static-analysis/build/test/coverage/security/compat/docs/benchmark/platform.
3. Use clean/forced execution when supported; cache-only != proof.
4. Performance-sensitive => compare committed baseline.
5. Review result against applicable Constitution IDs.

Failure => incomplete; fix cause+rerun. External prerequisite failure => finish reachable work; report exact command/failure/missing prerequisite.

## GIT/EXTERNAL

- R feature branch; X protected-default direct commit.
- Without explicit user approval X commit/push/open-or-merge PR/publish/change external service.
- X discard unrelated work/rewrite history/force-push/destructive cleanup without explicit approval.
- R repository-preferred issue/PR/CI integration tool.

## KOTLIN TOOLCHAIN

When working on Kotlin projects, use these tools. Each entry lists the Gradle plugin ID (or built-in), key tasks, and the Constitution ID it supports.

**Always use the latest stable version** of every dependency and tool. Before adoption or upgrade, verify the current release against the tool's official sources (Gradle plugins via the Gradle Plugin Portal Maven metadata, Maven Central, or the tool's own release page). Do not pin to an older version unless a documented stability blocker exists — and if you do hold a version back, record the blocker's rationale and removal condition. Re-evaluate held versions every sprint.

Keep plugin versions aligned with the Kotlin/Gradle/AGP-compatible release; run each gate in CI.

### dokka — API documentation (Q1, E7, O1)

- Plugin: `org.jetbrains.dokka` (latest stable; prefers DGP v2 since 2.1.0).
- Key tasks: `dokkaGenerate` (all formats), `dokkaGeneratePublicationHtml` (HTML output dir for other tasks), `dokkaHtml` / `dokkaHtmlMultiModule` (legacy v1 tasks).
- Multi-project: apply to every documentable subproject; declare `dokka(project(":library"))` in the aggregator.
- Output policy: `reportUndocumented=true` gates CI only when undocumented public API blocks release; never hand-edit generated files.
- Publish: attach the documentation archive through the existing Maven/Gradle publication; verify the local publication contains the entry point and source links.

### kover — code coverage (Q1, T3, E7)

- Plugin: `org.jetbrains.kotlinx.kover` (latest stable; JVM bytecode only — excludes KMP JS/Native and Android instrumented tests).
- Key tasks: `koverHtmlReport`, `koverXmlReport`, `koverBinaryReport`, `koverLog`, `koverVerify`.
- Engines: IntelliJ (default), JaCoC; one engine across all `kover` dependencies — mixed engines are invalid.
- Multi-project: select a merging module; declare `kover(project(":moduleA"))` for every module whose classes/tests contribute.
- Verification: seed one uncovered branch → `koverVerify` must fail; add a test → must pass. Filters win over verification; seed both include and exclude declarations to prove the exact boundary.

### spotless — formatting and lint (Q1, E1, E7)

- Plugin: `com.diffplug.spotless` (latest stable; JRE 17+, Gradle 8.1+).
- Key tasks: `spotlessCheck` (CI, read-only), `spotlessApply` (developer-controlled, mutates sources).
- Kotlin steps: `ktfmt` (latest) or `ktlint` (latest); pin external formatter versions for reproducible output.
- Rollout: clean repository-wide formatting commit OR `ratchetFrom origin/main` for incremental; never use `HEAD`.
- Idempotency: after `spotlessApply`, a second `spotlessApply` must produce zero diff; `spotlessCheck` must then pass.
- Exclude: generated output, build dirs, vendored code, contractual fixtures.

### kotlin-binary-compatibility (ABI validation) (Q5, E1, E7, G2)

- Built-in KGP ABI validation (experimental; use latest KGP): tasks `checkKotlinAbi` / `updateKotlinAbi`.
- Legacy: `org.jetbrains.kotlinx.binary-compatibility-validator` (use latest stable): tasks `apiCheck` / `apiDump`.
- Policy: built-in for new adoption when dump stability is acceptable; preserve legacy for existing builds unless migration is requested.
- Baseline: `apiDump` once → inspect entire ABI as public API review → commit with the generating config → `apiCheck` passes on unchanged code.
- Review: every dump diff maps to a source declaration + published binary; removals/descriptor changes require MAJOR + migration; additions require review before accepting.
- Filters: prefer source visibility; `binary-compatibility-validator` exclusions only for effectively-internal JVM-public declarations; use BINARY/RUNTIME-retained marker annotations for allowlists.
- KMP: validate each target from an authoritative host; mark inferred unsupported targets explicitly.

### skie — KMP to Swift interop (C2, C9, O3)

- Plugin: `co.touchlab.skie` (latest stable; applies only to framework-producing KMP modules).
- Requires: macOS + Xcode for framework/Swift verification; verify current Kotlin/Swift/Xcode compatibility from the live intro/changelog before version/config edits.
- Config: global Gradle rules for default behavior; `co.touchlab.skie:configuration-annotations:<VERSION>` for annotation-based overrides per package.
- Migration: disable broad features, enable narrow packages/declarations incrementally; never all-at-once for large consumers.
- Interop: enums generate Swift enums (original via `__Type`); suspend → `async` (two-way cancellation); Flow → `AsyncSequence`; defaults disabled by default.
- Verify: compile actual Swift consumer on macOS/Xcode; test enum/sealed switches, suspend cancellation, Flow cancellation, exported dependencies.

### kotlin-power-assert — test diagnostics (T1, T4, T8)

- Plugin: `kotlin("plugin.power-assert")` or `org.jetbrains.kotlin.plugin.power-assert` (latest Kotlin; **Experimental** — obtain explicit acceptance for library API reliance).
- Align plugin version exactly with the Kotlin compiler; one version owner across all modules.
- Scope: default transforms all test source sets; main/custom source sets only when their assertion diagnostics are required and runtime impact is accepted.
- Configuration: `functions` set takes exact fully-qualified callable names; OMIT `@PowerAssert`-annotated functions (annotation makes calls discoverable already).
- Diagnostics: keep the causal expression inside the assert call; never precompute to a Boolean variable (hides subexpressions). Append domain messages; power-assert adds expression context.
- Library API: opt in narrowly to `ExperimentalPowerAssert`; `@PowerAssert`-annotate assertion functions; `@PowerAssert.Ignore` noisy params; test both plugin-enabled consumer and non-transformed fallback.
- Verification: seed one deliberate failure → capture exception type, source expression, intermediate values → reverse to passing → run full test suite.

### Tool selection map

- **Documentation needed**: dokka
- **Coverage threshold in CI**: kover
- **Code formatting/lint**: spotless (always apply; `spotlessCheck` gates CI)
- **Library/API binary surface**: kotlin-binary-compatibility (abi validation)
- **KMP with iOS/macOS targets**: skie (Swift interop)
- **Test assertion diagnostics**: kotlin-power-assert (Experimental)

## DONE

Yield only if all true:

- request+acceptance criteria complete;
- applicable TDD observed expected red then green;
- affected callers/platforms/docs/examples/specs/compat/generated/release state agree;
- applicable local+CI-equivalent gates pass, or exact external blocker recorded;
- zero temporary/placeholder/disabled/stale/unjustified suppression/`TODO` state;
- Constitution compliant.

Final report R `{changed files+behavior, exact commands+observed results, docs/API/compat/security/performance impact, blocker/unverified state, specialized instructions/skills used}`. X claim unobserved command/test/review/runtime behavior.

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage role labels, each string equal to its name: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
