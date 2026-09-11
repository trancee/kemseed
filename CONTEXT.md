# CONTEXT — KEM-Seed Hybrid PQC over BLE Mesh

Single-context domain doc (see `docs/agents/domain.md`). Source of truth for the terminology
used across `PROMPT.md`, `docs/adr/`, and `.scratch/pqc-ble-mesh/`. Seeded during #09; re-framed
for the CSIDH-over-air drop (#10) per the H3 naming decision (module `kemseed`, package
`ch.trancee.kemseed`, shared seed `K_seed`).

## Glossary

- **PQC** — Post-Quantum Cryptography: primitives believed secure against classical and
  quantum adversaries.
- **BLE** — Bluetooth Low Energy. Here: GATT-based, connection-oriented links (not SIG
  Bluetooth Mesh) carrying the PQC handshake; peer phones act as both Central and Peripheral
  across an optional relay mesh.
- **MTU / ATT_MTU** — Maximum Transmission Unit / Attribute Protocol MTU. Default 23
  (20-byte payload), negotiable up to 247 on Android (`BluetoothGatt.requestMtu(247)`) and
  capped at 185 on iOS (182-byte payload). Zero-fragmentation budget = `ATT_MTU − 3`
  (3-byte ATT opcode+handle) = 244 B at ATT_MTU=247 (#03).
- **244 B non-fragmentation budget** — the *airborne* `Packet_A` is now a small seed/nonce
  (≤60 B, single frame per #14); the 768-byte ML-KEM ciphertext stays **local** (never
  over the air). (This supersedes the superseded #01 CSIDH-512 size accounting.)
- **KEM** — Key-Encapsulation Mechanism (FIPS 203 KeyGen/Encap/Decaps → pk, sk, ciphertext,
  shared secret). Used here only as the **local** ML-KEM-512 state engine (#07). CSIDH was
  considered as the airborne KEM but is **not used** — ruled infeasible in Pure-Kotlin (#10).
- **NIKE** — Non-Interactive Key Exchange (e.g. ephemeral X25519): both peers contribute an
  ephemeral key; the shared secret is their commutative group action. Relevant only as the
  #11 candidate E1 airborne-seed option (ephemeral X25519 DH feeds `K_seed`); not yet chosen.
- **CSIDH** — (Historical) Commutative Supersingular Isogeny DH, formerly the candidate
  airborne KEM. Ruled infeasible over the air in Pure-Kotlin (#10: >200 ms at both 512/1024-bit,
  minutes projected). The airborne element is now a small seed resolved by #11; CSIDH is not on
  the hot path. Retained in prose only as the superseded rationale.
- **ML-KEM-512** — FIPS 203 (Kyber) KEM, used **locally** (never over the air) as the
  "state engine" (#07). Deterministic KeyGen(d, z) from `SHAKE-256(K_seed, 64)` (#02);
  K_df via deterministic self-encapsulation (soundness reviewed in #13).
- **GMAC** — Galois/Message Authentication Code (AES-GCM integrity tag without encryption).
  Used as "GMAC-as-signer" for symmetric session-layer auth (Phase D); no non-repudiation
  (#06). Also the #15 DoS gate and the #11 airborne-Packet_A authenticator (signer key per #17).
- **AES-256-GCM** — Authenticated encryption for the session layer (Phase D). Native via
  Android Keystore / iOS CryptoKit (`expect/actual`); no Pure-Kotlin fallback required.
- **PFS** — Perfect Forward Secrecy. Achieved because `K_seed` is ephemeral per connection
  (freshly derived from the #11 airborne exchange) and the ML-KEM engine is re-derived per
  session, never persisted (#07).
- **K_seed / K_df / Session key** — `K_seed`: the small airborne shared secret (resolved by #11)
  that seeds the local ML-KEM engine via `SHAKE-256(K_seed, 64)`; `K_df`: ML-KEM-derived secret
  (deterministic self-encap, #13); session AES-256-GCM key:
  `HKDF-SHA3-256(K_seed ‖ K_df, transcript)` (#07).
- **Transcript** — running hash of handshake messages bound into the final HKDF, tying the
  session key to the exchange (#07 Q2).

## Actors & phases (PROMPT.md §Context Guide; resolved spec in #08)

- **Central / Peripheral** — the two peers in a GATT exchange; roles may swap across the mesh.
- **Phase A — Provisioning:** OOB establishment of the long-term identity key (AES-256-GMAC)
  + session identity (#17 at-rest/rotation; #12 mechanism pick is HITL human).
- **Phase B — Airborne seed → local ML-KEM:** `Packet_A` carries the small seed/nonce
  (≤60 B, #14) + an AES-256-GMAC tag (the #15 DoS gate, signed with the #06 signer key /
  #17 at-rest key). Both peers derive the local ML-KEM-512 engine from `SHAKE-256(K_seed, 64)`
  (#02 valid deterministic KeyGen). The exact airborne-KEM binding that produces `K_seed`
  is crypto-expert-gated (#11; handoff packet #18).
- **Phase C — Local key-derivation:** derive the ML-KEM-512 engine from `K_seed` → `K_df` via
  deterministic self-encaps (#13 soundness) → `HKDF-SHA3-256(K_seed ‖ K_df, transcript)` to the
  session key (#07).
- **Phase D — Session:** AES-256-GCM authenticated channels.

## Constraints (ADR-0001)

Kotlin Multiplatform, Android + iOS only; zero external runtime dependencies (native
Keystore/CryptoKit preferred; Pure-Kotlin fallback for ML-KEM, and — if #11 chooses candidate
E1 — a Pure-Kotlin constant-time X25519 on iOS since CryptoKit exposes no public ML-KEM/X25519).
Constant-time required for the airborne-KEM verification path (#04, #13, #11).
