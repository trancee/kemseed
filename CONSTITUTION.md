# Constitution

AI-targeted normative policy.

```text
R = required (MUST)       X = forbidden (MUST NOT/NEVER)
D = default (SHOULD); deviation => written task-specific reason
O = optional (MAY)        A => B = if A, then B
scope = code|tests|docs|config|automation|release|review
priority = CONSTITUTION > AGENTS > scoped docs/ADRs > config/templates/comments
```

Lower priority may refine, X weaken. Conflict => follow higher priority + report; X invent exception. Project commands,
platforms, budgets, artifacts live in version control and refine this policy.

## S: security/trust

- S1 X secrets/credentials/keys/tokens/session or derived key material/PII in logs, errors, crashes, tests, fixtures,
  artifacts. R diagnostics = redacted IDs + non-sensitive context.
- S2 `{network,file,env,CLI,persistence,third-party response}` = untrusted unless explicitly proven. R validate at
  boundary; invalid => typed+redacted error/result. X uncontrolled throw/panic/crash/partial mutation.
- S3 Uncertain identity/authentication/authorization/integrity/replay/protocol/config/security-state => fail closed at
  smallest safe work unit.
- S4 Failure path: X implicit trust/security downgrade/stale credential/partial state/corrupt-identity replacement.
  Fallback R `{specified,security-preserving,observable,tested}`.
- S5 Each fail-closed branch R typed+redacted reason + automated test.
- S6 Crypto R approved provider/established library. New primitive R spec+expert review+conformance vectors.
- S7 Crypto/security protocol R recognized conformance/adversarial vectors when available.
- S8 Pre-merge secret scan R pass. Found secret => R revoke + remove from reachable history; current-line deletion != fix.
- S9 Disclosed vulnerability R merge <=5 business days; CVSS>=9 equivalent R <=48h.

## Q: code quality

- Q1 Repository formatter+static analysis R pass pre-merge.
- Q2 X production suppressions for formatter/compiler/static analysis. Test-only suppression R local applicability reason.
- Q3 Names R full+descriptive; domain terms/acronyms O; X invented abbreviations/ambiguous contractions/unexplained
  single letters except trivial local indices.
- Q4 Public declarations R explicit visibility+types where supported.
- Q5 Public interfaces R repository compatibility tracking; each diff R release-impact explanation.
- Q6 Released public/serialized contract semver: breaking=MAJOR, additive=MINOR, compatible fix=PATCH.
- Q7 Public API removal R documented deprecation >=1 MINOR; O immediate removal only for security incident.
- Q8 Merged code X placeholders/disabled implementations/`TODO`; future work => issue tracker.
- Q9 Comments R intent/constraint/tradeoff only; structure+names R explain behavior.
- Q10 Closed-set handling R exhaustive; X default hiding new state/variant/enum.
- Q11 Long async work R structured concurrency+cancellation; X unbounded polling.
- Q12 Preconditions D idiomatic validator; custom error/result only for caller-visible semantic distinction.

## T: tests

- T1 Feature/fix R TDD cycle: behavior test red for intended reason => smallest complete implementation => green =>
  refactor while green.
- T2 Default CI suite R deterministic+isolated+repeatable+self-validating; X developer workstation/retained process/
  physical hardware/manual inspection dependency.
- T3 Maintained production code R 100% line+branch CI coverage. Generated/vendor/example/benchmark/internal-tool scope O
  excluded only if CI names it; all tests still R pass.
- T4 Coverage != behavior proof. R tests cover observable behavior/boundaries/invariants/transitions/precedence/real errors.
- T5 Each test R one primary Act; Arrange/Act/Assert visually distinct; unrelated Acts => split.
- T6 Assertions D retain failure context; structural equality only when structure is tested behavior.
- T7 Tests R public/stable-internal contracts; X source text/incidental order/private detail/time/shared-state dependence unless
  itself tested behavior.
- T8 Multi-process/node/network/distributed tests D deterministic virtual environment in default suite.
- T9 Mock/simulator X hardware proof. Hardware behavior R supported-hardware execution pre-release.
- T10 Security/protocol/parser/serializer tests R applicable malformed/truncated/boundary/replayed/incompatible/adversarial cases.
- T11 Performance-critical operations R retained representative benchmarks + comparison environment metadata.

## C: public/platform contracts

- C1 Public contract R same behavior on all supported platforms unless public spec documents difference.
- C2 Platform code R behind adapters/platform modules; shared business rules R platform-independent when possible.
- C3 Config concepts/defaults/validation/diagnostics/state transitions R cross-platform consistency; platform inputs D
  factory/adapter, X public-config branching.
- C4 Platform errors/types X leak through shared API; R translate to documented error model.
- C5 Diagnostic names/severity/payload shape R stable+documented; payload R S1.
- C6 Persisted/network formats R explicit stable IDs; released field/message/enum IDs X reinterpret/reuse.
- C7 Breaking persisted/network format => R MAJOR+migration+compatibility tests.
- C8 Public API change => R same-change reference docs+examples; cross-platform docs cover every affected platform.
- C9 API newer than minimum platform => R runtime guard or supported fallback.

## P: performance

- P1 Performance-sensitive project R numeric budgets for relevant resources; each budget R workload+environment+method+
  threshold.
- P2 Each budget R automated benchmark or reproducible measurement.
- P3 Budgeted-path change R current benchmark evidence.
- P4 Regression >10% vs committed baseline => block merge unless approved budget+rationale update.
- P5 Hot path R avoid unnecessary allocation/copy/parse/serialization/I/O/recompute. Optimization R preserve correctness+
  measurement.
- P6 Performance claim without recorded measurement = no evidence.

## D: design

- D1 R simplest approved-requirement design; X speculative extension/framework/config/retry/fallback.
- D2 Module/class/file D one reason to change.
- D3 Abstraction allowed only for demonstrated duplication|known hotspot|stable protected contract; one use/future guess != reason.
- D4 R low coupling+high cohesion+small stable contracts; X deep traversal/foreign internals.
- D5 D composition/factory/strategy over inheritance; inheritance only if subtype substitutable.
- D6 R volatile details behind internal boundaries.
- D7 Command/query R distinct naming+contract; mutating return allowed if mutation explicit.
- D8 Touched code/tests/docs R no less clear; added complexity R reason.
- D9 Maintained source/test file D <=300 lines, R <=500; split by responsibility/layer/platform. Generated/vendor exempt.
- Review vocabulary: God object=>split responsibility; shotgun surgery=>centralize boundary; feature envy=>move beside data;
  premature abstraction=>remove; copy/paste=>extract variance; magic value=>name+document; long method=>extract stages;
  excessive/restating/dead comments=>improve names+delete.

## O: documentation/completeness

- O1 One change set R code+tests+public docs+specs+ADRs+examples+generated artifacts+release metadata agree.
- O2 Incomplete if any affected caller/platform/test/compat record/API dump/example/doc retains old contract.
- O3 Security/auth/crypto/protocol/routing/persistence/schema/wire change R versioned ADR update containing
  `{context,decision,alternatives,risks,migration}`.
- O4 Docs D separate tutorial/how-to/reference/explanation; each doc R one dominant purpose.
- O5 Checkable examples R compile/execute.
- O6 Docs-only change R repository link/spelling/format/markup checks.
- O7 Day-to-day conventions R narrow scoped docs, X constitution duplication.

## E: dependencies/tooling

- E1 Build/release R reproducible; dependency/tool versions R ecosystem-standard pin/lock.
- E2 Dependencies/tools R mutually compatible stable releases. Hold R documented blocker+removal condition.
- E3 New runtime dependency R rationale covering `{need,maintenance,license,security,size,transitives,why stdlib/existing fails}`.
- E4 Production artifact X undeclared/unreviewed runtime dependency.
- E5 Platform/test/benchmark/docs/build dependencies X production artifact unless runtime contract requires.
- E6 Generated file R owning-tool regeneration; X hand edit.
- E7 CI config = authoritative automated gates; local hooks != CI proof.

## G: merge/release

Before merge, all applicable:

- G1 R feature branch; X protected-default direct commit.
- G2 R clean-checkout authoritative CI pass, including applicable S/Q/T/C/P/D/O/E and repo validators.
- G3 Config/workflow files R format+schema validation.
- G4 Public change R docs+examples+compat artifacts+semver impact.
- G5 PR R Constitution Check over S-Q-T-C-P-D-O-E-G. Violation => approved amendment; X silent exception.
- G6 Commits R Conventional Commits or stricter repository format.

## V: governance

- V1 Constitution outranks repository policy.
- V2 Change R written `{rationale,impact,migration,approval}`.
- V3 Document semver: removed/incompatible principle=MAJOR; new/material expansion=MINOR; obligation-neutral clarification=PATCH.
- V4 Policy change R same-change automation/templates/hooks/checklists.
- V5 Ownership rules D designated review for constitution/security/release/CI/protocol/schema/persistence paths.
- V6 Lower convention R narrowest relevant document; X duplicate here.

`version=2.0.1; ratified=2026-04-30; amended=2026-08-29`
