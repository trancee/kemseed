# Handoff: Crypto-expert review packet for #11 (airborne-KEM binding) + #13 (deterministic self-encap-as-K_df)

Status: open
Type: handoff (coordination)
Wayfinder: expert gate on the destination. Produced by the wayfinder charting session (AFK de-fog of #14–#17 complete). This packet is the **only** input an expert needs to close #11 + #13 and **unblock the #08 spec freeze**. Do **not** self-resolve #11/#13 in code-gen sessions.

> Purpose: surface the *exact* gaps an expert must fill. The agent has resolved everything that is researchable (transport, DoS, iOS background, OOB feasibility, native at-rest). The expert decides **only** the airborne-KEM binding + the deterministic-self-encap soundness.

---

## 1. Executive summary

- **#10 ruled CSIDH-over-air INFEASIBLE** in Pure-Kotlin (>200 ms at 512- and 1024-bit; custom CT field built but the irreducible isogeny-walk cost dominates). So the 64-byte CSIDH public-key/ciphertext can no longer be the airborne KEM.
- **Architecture B is confirmed** (PROMPT "Specification"; #05): a **small airborne element** drives a **local** FIPS 203 ML-KEM-512 state engine → AES-256-GCM session. The isogeny step is now only a **seed** for `SHAKE-256`.
- **Open (expert):** (a) *what* the small airborne element is and *how* it binds to the local ML-KEM-512 engine ( **#11**); (b) whether using ML-KEM's Encap **deterministically** (reused seed) as the KDF is sound, with both peers reproducing `K_df` ( **#13** ).

Everything below is decided or constrained AFK — treat as immutable for #11/#13.

---

## 2. Decided (do NOT re-decide)

| Ticket | Decision | Source |
|---|---|---|
| **#05** Arch B confirmed; Arch A (custom LWE+Rudraksh/Smaug + Falcon) Out of scope. CSIDH-over-air **dropped**; local ML-KEM-512 + AES-256-GCM tail retained. | `issues/05-grill-kem-contradiction.md` |
| **#10** CSIDH-512/1024 infeasible (>200 ms, minutes projected in Pure-Kotlin). CT achievable (custom radix-2^26 field self-verified vs `BigInteger`); bottleneck = irreducible walk cost, not CT discipline. Do **not** try to make CSIDH fast. | `issues/10-prototype-csidh-pure-kotlin-spike.md` (+ spike `CsidhCtFieldSpike.kt`) |
| **#02** `SHAKE-256(K_seed,64)` → deterministic `(d,z)` → `ML-KEM.KeyGen(d,z)` is **valid** deterministic KeyGen (Federal Register confirms seed-regeneration). Engine `(pk,sk)` ephemeral per session, shared by both peers; non-persisted → PFS (#07). | `issues/02-research-fips203-mlkem-keygen.md` |
| **#06** Auth model: **symmetric-only.** AES-256-GMAC signer over a **long-term pre-shared identity key**; non-repudiation explicitly out of scope (PROMPT §Repudiation; ADR-0001). The signer key is **AES-256-GMAC**; it is the *same* key as the #15 DoS gate key (single AES-256 key, two AAD domains — see §5.4). | `issues/06-grill-auth-model.md` |
| **#07** Engine = per-session ephemeral `(pk,sk)`; K_df via deterministic self-encap; AES-256-GCM session key via proposed **HKDF-SHA3-256** (RFC 5869); exact labels deferred to #08 (informed by #11/#13). | `issues/07-grill-mlkem-state-engine.md` |
| **#14** Transport = **p2p GATT connection-graph** (NOT SIG mesh). Degree ≤5 per phone; ATT_MTU 247; foreground bootstrap; per-hop latency floor = 1 connection interval (≥100 ms bg); app-layer seqno+ACK+retransmit (Write-With-Response only). | `issues/14-research-ble-mesh-routing.md` |
| **#15** DoS: format-check → nonce-freshness cache (2^10, 30 s TTL+LRU) → **AES-256-GMAC-before-Decaps** over `(version‖nonce‖sender_id‖flags)` using the #06 signer key; fail-closed; ML-KEM-512 Decaps ≈ **30–70 µs** on phone ARM. | `issues/15-research-dos-prevalidation.md` |
| **#16** iOS bg = relay-over-live-links only (no new-peer discovery backgrounded; `AfterFirstUnlockThisDeviceOnly` key + CoreBluetooth state-restoration). Topology asymmetric (Android seeds/maintains from bg via FGS; iOS cannot). | `issues/16-research-ios-background-peripheral.md` |
| **#17** At-rest: signer AES-256-GMAC key is **symmetric → NOT Secure-Enclave-backed** (SE is asymmetric-only); stored in **iOS Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** (required so the #15 bg GMAC gate works) / **Android Keystore AES** (+ optional StrongBox); rotation = delete-then-add, atomic (brief no-key window must drop traffic). | `issues/17-research-oob-provisioning.md` |
| **ADR-0001** KMP (Android+iOS only); **zero external deps**; native-keystore via `expect/actual`; **Pure-Kotlin** constant-time fallback mandatory where native lacks the primitive (ML-KEM/KeyGen are not in platform keystores → Pure-Kotlin). Threat model §Elevation of Privilege → **CT required** on the airborne-KEM verification path. | `docs/adr/0001-stack-and-dependency-constraints.md` |

## 3. Hard constraints the #11/#13 answer must satisfy

1. **Size:** airborne `Packet_A` ≤ **60 B** (≤240 B ceiling, but the *payload* is tiny — a seed/nonce, not the 768 B ML-KEM ciphertext, which stays local). `ATT_MTU = 247`; single frame, zero fragmentation.
2. **No CSIDH:** the isogeny group action is **not** on the hot path. `K_seed` (the shared secret that seeds ML-KEM) **must come from the replacement airborne KEM**, not from a CSIDH walk.
3. **Local ML-KEM-512 only:** both peers run `ML-KEM.KeyGen(SHAKE-256(K_seed,64))` locally (#02 valid). Nothing larger than a seed crosses the air.
4. **DoS posture (#15):** the airborne element is verified by the **AES-256-GMAC-before-Decaps gate** *prior* to `ML-KEM.Decaps`. The replacement must (a) be cheap to reject (sub-µs to µs), (b) be replay-bounded by the #15 nonce cache, (c) **not** let a malformed/attacker-chosen `Packet_A` force a wasteful Decaps or a wrong `K_df`.
5. **Background-safe (#16):** must work under throttled bg connection intervals (≥100 ms) and the 30 s BGTask; no blocking/long ops in the bg path.
6. **Storage/rotation (#17):** the airborne-KEM binding, if it introduces a *new* long-term key, must follow §4 (#17) (iOS Keychain `AfterFirstUnlockThisDeviceOnly` / Android Keystore StrongBox; atomic rotation). If it reuses the existing signer key, note that explicitly (the signer key already carries the #15 DoS-gate and #06 auth duties — see §5.4).
7. **Constant-time (#04 #17 ADR-0001):** the verification path of the airborne KEM (decoding/reducing the 60 B element, deriving the seed) **must be constant-time** in Pure-Kotlin or native-keystore. (The #10 spike file shows the radix-2^26 CT patterns that may be reused for any arithmetic, but is **not** reused as-is — p=2^255−19 is Curve25519-hardcoded.)

## 4. Open expert questions

### #11 — replacement airborne KEM binding (the core ask)

CSIDH is gone. **Decide the replacement airborne element** that yields `K_seed` for `SHAKE-256(K_seed,64)→ML-KEM.KeyGen`. Provide:

- **(a) Payload layout + size** (≤60 B) and the exact field map of `Packet_A` (`version ‖ seed/nonce ‖ sender_id ‖ flags`, matching the #15 GMAC AAD framing). Specify which bytes are secret, which public.
- **(b) Binding correctness vs. the #06 Q3 tampering threat.** The old flaw (#11 original Q2): a modified-in-transit public key let the receiver recompute a *valid* GMAC because it holds the signer key. The replacement must **bind peer identity** to the derived `K_seed` so an attacker-substituted `Packet_A` is rejected **before** ML-KEM Decaps. State the binding (e.g. include a key-confirmation MAC, a transcript binding, or a self-encap cross-check) and prove it defeats substitution — or add the minimal extra field that does.
- **(c) Domain-separation + freshness + replay.** How `seed` is derived (context string, version, role), and how freshness is guaranteed given the #15 30 s nonce cache (the expert must confirm the cache bound is sufficient, or extend it).
- **(d) CT posture.** A constant-time argument or review statement for the decode/reduce/derive path in §3.7; reference the #10 radix-2^26 primitives **only if** they apply to your construction.
- **(e) Candidate families** the expert may pick from (agent does **not** pick — present tradeoffs for approval):
  - **(E1) Ephemeral X25519-as-seed hybrid.** Sender generates ephemeral X25519 keypair; sends 32-byte X25519 public key in `Packet_A`; shared secret = X25519(ephemeral, receiver's *static* X25519) → feeds `SHAKE-256(·,64)→ML-KEM.KeyGen` as `K_seed`. PQ-ness is preserved by the **local ML-KEM-512** tail (X25519 is the seed-authenticator only, like a HKDF-style extractor over an ephemeral DH — analogous to X-Wing / RFC 9496). *Pros:* 32 B fits trivially; X25519 is fast on mobile; native X25519 available on Android Keystore (API 28+) — **but not iOS native** (CryptoKit exposes it privately; public only via PrivateCoreCrypto/Security `SecKeyAlgorithm` with caveats) ⇒ Pure-Kotlin CT X25519 likely required on iOS. *Cons:* adds an X25519 primitive + its CT review (new attack surface vs "ML-KEM only").
  - **(E2) Pre-shared `K_seed` (NetKey-derived).** `K_seed` is the fleet/provisioned NetKey (#17), no per-message DH; both peers already share it; `Packet_A` carries only `(version ‖ session_nonce ‖ sender_id ‖ flags ‖ GMAC)`. *Pros:* zero new PQ-adjacent primitive; minimal on-air bytes; reuses the signer key for the gate. *Cons:* PFS at the isogeny layer is lost (mitigated by **per-session ephemeral ML-KEM engine** — confirm PFS still holds end-to-end with a static `K_seed`); security rests entirely on #17 OOB provisioning/rotation.
  - **(E3) Other** — specify and justify against §3.

### #13 — deterministic self-encap-as-K_df soundness

The mechanism (#07) has both peers compute the **same** `(pk,sk)` from the (new) `K_seed`, then run **deterministic ML-KEM self-encap** to agree on `K_df`. Standard CCA-secure ML-KEM assumes **fresh randomness** per Encap. Validate:

1. **Is deterministic (reused seed) self-encap sound** when `(pk,sk)` is ephemeral per session and secret to both peers? Compare to the CCA transform / implicit-rejection (#13 original Q1). Give a yes/no + argument; flag any multi-key/reuse subtlety vs. FIPS 203 §7.
2. **PFS inheritance.** Does `K_df` inherit PFS from the *airborne* KEM's per-session secrecy (i.e., from #11's choice), assuming `(pk,sk)` is never persisted (#07)? State the precise condition and whether a compromised signer/NetKey retroactively breaks past sessions.
3. **Test vector (conformance).** A minimal deterministic vector: fixed `rnd` → fixed `(ct, K_df)` reproducible by both peers from the *same* `K_seed`. (For reference: ML-KEM decapsulation failure rate for -512 is 2^−138.8 — irrelevant to soundness but record it.) Include whether the `rnd` is re-used (same every session) or bound (e.g. `rnd = HKDF(role‖sender_id‖session_nonce, …)`) — bound is strongly preferred.

## 5. Tension points the expert must resolve (not the agent)

- **§5.1 Signer key reuse.** #15 + #06 + #11 share: if the airborne KEM (E2) reuses the long-term signer key, then **one key = signer + DoS-gate + (airborne) KEM seed** — three roles. Confirm this is acceptable, or mandate a separate key per role (and update #17 at-rest accordingly).
- **§5.2 CT review scope.** The replacement's CT argument must cover decode/reduce/derive AND not regress under Pure-Kotlin (ADR-0001). If (E1) is chosen, the X25519 scalar mult CT path is *new* and needs its own review (not the #10 CSIDH field).
- **§5.3 iOS native-gap.** Any candidate requiring X25519 or ML-KEM must run as **Pure-Kotlin** on iOS (not in a platform keystore — iOS CryptoKit has no public ML-KEM; X25519 is private). Confirm the implementation plan + CT guarantee.

## 6. Acceptance criteria — what "closed" looks like (so #08 can freeze)

| Ticket | Resolved ↔ closed means | Then the agent does |
|---|---|---|
| **#11** | A written **replacement airborne-KEM binding** that: picks a family from §4(e), specifies payload layout ≤60 B matching the #15 GMAC AAD, binds peer identity (defeats in-transit substitution per §4(b)), defines domain-separation+freshness+replay handling consistent with the #15 30 s nonce cache, and carries a **constant-time statement/review** for the verification path. | Fills `#08` §2 (airborne Packet_A) + the binding lines in §3 Phases A/B/C, plus HKDF labels; writes acceptance tests. |
| **#13** | A **soundness yes/no + argument** for deterministic self-encap-as-KDF, the **PFS condition** (#07 engine ephemeral), and a **minimal deterministic test vector** (fixed `rnd` → `(ct, K_df)`, reproducible by both peers; specify whether `rnd` is bound or reused). | Adds the vector to the test corpus; locks §3 Phase B/C K_df derivation. |

Once both are **signed-off**, the agent freezes `hybrid_pqc_ble_mesh_spec.md` (no `[EXPERT TBD]` remaining) → ready for AI code-gen.

## 7. Reference packet (read in this order)

- **Decided foundation:** `issues/05-grill-kem-contradiction.md` (Post-#10 closure — Architecture B drops CSIDH), `issues/02`, `issues/06`, `issues/07`, `docs/adr/0001-stack-and-dependency-constraints.md`, `PROMPT.md` §1–§3 (Context Guide).
- **Why CSIDH is out:** `issues/10-prototype-csidh-pure-kotlin-spike.md` + spike `CsidhCtFieldSpike.kt` (CT patterns only — p=2^255−19 hardcoded, **not** reused).
- **AFK-resolved constraints the binding must honor:** `issues/14`, `issues/15`, `issues/16`, `issues/17`.
- **The draft to freeze:** `issues/08-prototype-spec-outline.md` (the `[EXPERT TBD]` lines are exactly the §6 acceptance items above).
- **Standards:** FIPS 203 (ML-KEM); ePrint **2023/793** (CSIDH cost); RFC 9496 (X-Wing hybrid reference, for the E1 PQ-preservation analogy); NIST CSWP 04282021 (PQC transition).

## 8. Coordination

- **Claim:** crypto-expert (S6/S7). Not a wayfinder-charting ticket.
- **Do not** let code-gen sessions close #11/#13. If an implementer tries to "pick X25519" without this review, halt — that is crypto design.
- **Hand back:** sign-off on §4 (binding + CT) and §6 (test vector + PFS) → agent freezes #08.
