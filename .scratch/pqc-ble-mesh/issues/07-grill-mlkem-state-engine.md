# Grill: Clarify local ML-KEM-512 state engine and session key derivation

Status: resolved
Claimed by: work-through session (agent)
Type: grilling
Blocked by: (none)

## Question

Phase C derives an ML-KEM-512 "state engine" locally from the CSIDH shared secret, and Phase D says: "Mix the final derived `ml_kem_engine` keys with the session transcript using HKDF-SHA3-256."

Decision required:
1. What concretely is `ml_kem_engine`? After deterministic `KeyGen(d, z)` the engine holds `(pk, sk)`. To get a session key, an encapsulation must run — but locally, between whom? If both peers independently derive the **same** `(pk, sk)` from the same `K_seed`, can they each perform a deterministic self-encapsulation to agree on `K_df`?
2. How exactly is the final AES-256-GCM session key derived from `(K_seed, K_df, transcript)` via HKDF-SHA3-256? Specify HKDF salt / info / purpose labels and inputs to avoid cross-protocol key reuse.
3. Is the local ML-KEM engine re-keyed per session or persisted, and how does that interact with PFS (K_seed is ephemeral per connection)?

## Answer

**Decision (work-through session, 2026-09-10): ML-KEM state-engine mechanics confirmed; crypto soundness + KDF-label conformance under expert review.**

- **Q1 (what is `ml_kem_engine`; can both peers agree on K_df):** **Mechanically confirmed.** Under E1′ the X25519 DH is symmetric, so both peers share `K_seed = HKDF-Extract(ss ‖ NetKey)` (#11/ADR-0002; CSIDH-over-air was ruled infeasible #10, making `ss` the airborne shared secret, not a CSIDH NIKE). Both derive the same `(d, z) = SHAKE-256(K_seed, 64)` and thus the same `(pk, sk)` via FIPS 203 deterministic KeyGen (#02). Both then run **deterministic self-encapsulation** (Encap with a deterministic seed derived from the shared state) → identical `(ct, K_df)`. Peers agree on K_df. **Caveat — soundness:** deterministic Encap departs from standard CCA-secure ML-KEM (fresh randomness per encaps assumed); whether reusing the seed is a safe KDF keyed by an ephemeral K_seed is **not self-resolved** → **#13 (crypto-expert review).**
- **Q2 (HKDF-SHA3-256 session-key derivation):** **Proposed.** `HKDF-Extract(salt = HASH(transcript), IKM = K_seed ‖ K_df) → PRK`; `HKDF-Expand(PRK, info = "pqc-ble-mesh v1 session aes-256-gcm key"‖0x00‖len, L=32) → AES-256` session key. Structure mirrors TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1); exact bytes finalized in #08; transcript-binding in the salt prevents replay/cross-binding.
- **Q3 (re-keyed per session / PFS):** **Confirmed — ephemeral, not persisted.** Phase C derives the engine *from K_seed* ("from the ephemeral X25519 ss, E1′: `K_seed = HKDF-Extract(ss ‖ NetKey)`"). Since `K_seed` is fresh per session (driven by the ephemeral-erased `ss`), `(pk,sk)` and `K_df` are re-derived per session. The ML-KEM engine is **not** persisted; K_df reuse occurs only if `ss` is reused, which the ephemeral-erased X25519 DH forbids (`ss` is a fresh DH secret erased post-session, irreducible by the long-term NetKey; a duplicate `(dir, nonce)` is rejected at the #15 cache). → **PFS achieved** (true forward secrecy; see #11/ADR-0002 §4.6). Under E2 (no `ss`) this was the unresolved integrity flag — now closed.

Net: #07 closed. The ML-KEM engine is a per-session ephemeral keypair shared deterministically by both peers; K_df via deterministic self-encaps (mechanism correct); AES-256-GCM session key via proposed HKDF-SHA3-256 (labels finalized in #08); the one crypto-soundness open item (deterministic Encap security) is tracked in #13.

Sources:
- FIPS 203 (deterministic KeyGen; verified in #02).
- RFC 5869 (HKDF) + RFC 8446 §7.1 (HKDF-Expand-Label usage).
- #04 (CSIDH-NIKE ruled out #10; E1′: X25519 DH is symmetric → `K_seed = HKDF-Extract(ss ‖ NetKey)`, shared & PFS-driving, driving Q1/Q3).

