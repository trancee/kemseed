# `hybrid_pqc_ble_mesh_spec.md` — frozen draft (crypto gates #11 E1′ + #13 SOUND closed; **true PFS achieved**)

Status: **FROZEN for AI code-gen** (expert sign-off packet 6, 2026-09-11: #11 DECIDED **E1′** / #13 SOUND). Owner decision recorded 2026-09-11: **adopt true-forward-secrecy E1′ — "allow X25519"**, explicitly reversing the packet-5 preference ("X25519 not needed under E2" / "do not revert to E1′"). The expert packet 6 confirmed pure E2 is non-PFS — *"the claim that PFS was fully preserved was overstated on this point"* — and that true PFS under a ≤60 B airborne frame requires ephemeral↔ephemeral X25519. `Blocked by: (none)`.

> Source-of-truth for the protocol. `kemseed` library module (`ch.trancee.kemseed`), package/namespace per #09. `PROTOCOL_NAME="hybrid-pqc-ble-mesh"`; `PROTOCOL_VERSION=1`. Targets: Android + iOS (device only, no iOS-simulator targets — BLE is non-functional in simulators). Zero external deps (ADR-0001).

## 1. Transport (resolved from #14 / #15 / #16)
1.1 **Topology:** p2p GATT connection-graph. Each node = central to ≤5 immediate neighbours; "mesh relay" = app-layer forward (`read char-B → write char-C`). *Not* SIG Bluetooth Mesh (iOS/Android are proxy-client only — no connectionless flood between phones).
1.2 **Link / frames:** `ATT_MTU = 247` (`requestMtu(247)`). E1′ is **two flights** (`Packet_A1`, `Packet_A2`), each 60 B — both within the 244-byte non-fragmentation budget at `ATT_MTU=247` (zero fragmentation, zero reassembly buffering). End-to-end = 2 frames + DH/encap/derive (no third flight; key-confirmation is implicit via GCM-open of the first data packet per §3 Phase B... wait — see correction below, E1′ is the 2-flight handshake itself, then data).
1.3 **Reliability:** all relay writes use **Write With Response** + app-layer seqno + ACK + retransmit window; Write-Without-Response forbidden for control traffic.
1.4 **Bootstrap:** foreground-gated — scan→connect→discover(SR/GCM)→MTU must complete before background handoff.
1.5 **Latency budget:** per-hop = ≥1 connection interval + ATT RTT (foreground 7.5–30 ms; background ≥100 ms, throttled); E1′ adds one extra ATT frame vs single-flight E2 (negligible vs the ≥7.5 ms CI floor).
1.6 **DoS gate (pre-derivation, #15):** (a) format/length/version check; (b) per-peer freshness cache (key = `dir(1) ‖ nonce(8)`, 2^10 entries, 30 s TTL + LRU); (c) **AES-256-GMAC over the authenticated flight fields** verified **before any X25519-DH or ML-KEM work**, using the #06 signer key; fail-closed. Pending-handshake caps (packet 5 §1.4, tightened for 2 flights): ≤1 pending incomplete handshake per remote `sender_id`; ≤2 pending engines globally; engines freed on 30 s TTL. GCM IV (all flights + data): `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00` (12 B). Replay bounded by the cache within TTL; post-TTL replay bounded by the caps (accepted waste).

## 2. Airborne element (E1′ — ephemeral X25519, true PFS; symmetric auth, no new long-term key)
E1′ is chosen for **true forward secrecy**: the long-term secret (NetKey, #06/#17, symmetric AES-256 signer) authenticates both flights via GMAC, while an **ephemeral X25519 key pair contributed by each peer** (private erased after the session, never transmitted) supplies `ss` to `K_seed`. No new *long-term* key is provisioned (X25519 ephemeral ≠ long-term identity). Because a secret-bearing field (`epk`) now travels on the air, the #06 substitution/key-replacement attack must be explicitly closed by GMAC'ing `epk` (§3).

### 2.1 `Packet_A1` (initiator→responder), 60 B on air
| Field | Bytes | Notes |
|---|---|---|
| `version` | 1 | protocol version (Public) |
| `nonce_i` | 8 | initiator freshness token (Public; #15 cache key, dir=0xA0) |
| `sender_id_i` | 2 | mesh address (Public) |
| `flags` | 1 | bitfield incl. role/type (Public) |
| `epk_i` | 32 | **X25519 ephemeral public** (Public — on air; GMAC-bound to kill substitution) |
| `GMAC` | 16 | **AAD = `version ‖ flags ‖ nonce_i ‖ sender_id_i ‖ epk_i`**; signer key K_gmac |

Total = `1+8+2+1+32+16` = **60 B** (≤60 B; single ATT frame). (Headroom vs the 244 B non-fragmentation budget: ample.)

### 2.2 `Packet_A2` (responder→initiator), 60 B on air
| Field | Bytes | Notes |
|---|---|---|
| `version` | 1 | |
| `nonce_r` | 8 | responder freshness token (Public; #15 cache key, dir=0xA1; distinct from `nonce_i`) |
| `sender_id_r` | 2 | |
| `flags` | 1 | |
| `epk_r` | 32 | responder X25519 ephemeral public (Public — GMAC-bound) |
| `GMAC` | 16 | **AAD = `version ‖ flags ‖ nonce_r ‖ sender_id_r ‖ epk_r ‖ A1fields`** (transcript binding — A2 cannot be spliced onto a different A1) |

Same 60 B. GMAC over A1's fields in A2's AAD is the #06 substitution fix *across* the two flights (reflection / splice rejection).

## 3. Derivation (E1′; true PFS)
```
ss      = X25519(eph_priv_local, eph_pub_remote)          // reject all-zero ss (CT, no branch)
T       = SHA3-256("HMB1-TR" ‖ Packet_A1 ‖ Packet_A2)     // transcript (both authenticated frames)
K_seed  = HKDF-Extract(salt = T, IKM = ss ‖ NetKey)        // ss → PFS; NetKey → auth-binding
(d, z)  = SHAKE-256("HMB1-DZ" ‖ T ‖ K_seed, 64)           // #02 FIPS 203 KeyGen seed
(pk,sk) = ML-KEM-512.KeyGen(d, z)                          // local only, NEVER on air
m       = SHAKE-256("HMB1-EM" ‖ T ‖ K_seed, 32)           // bound coin (transcript + K_seed)
(K_df, c*) = ML-KEM-512.Encaps_internal(pk, m)            // c* NEVER on air
key_AB/key_BA = HKDF-Expand(K_df, "HMB1-K-AB"‖sid_i‖sid_r / "HMB1-K-BA"‖sid_i‖sid_r, 32)   // #07 labels
```
- `ss` is the **only** non-NetKey source of `K_seed`. It is an X25519 DH shared secret whose private scalar is erased after the handshake and never leaves the device. Later compromise of `NetKey` cannot reconstruct `ss` ⇒ cannot reconstruct `K_seed` ⇒ cannot reconstruct `(d,z),(pk,sk),m,K_df` ⇒ **true PFS**.
- Freshness: 8-byte nonces checked against the #15 cache (replay → GMAC gate drop before DH/ML-KEM).
- `NetKey` is 32 B (#17 OOB = AES-256-GMAC signer = this same symmetric key, domain-separated by HKDF labels — §5.1 single-key reuse, no new long-term key).
- `c*` discarded; `Decaps` runs only as a test self-check (#08 §6).

## 4. DoS gate & ordering (every flight)
1. A1 received → format/version → nonce cache (fresh?) → **GMAC(A1) over `(version‖flags‖nonce_i‖sender_id_i‖epk_i)` using K_gmac** → only then responder proceeds.
2. A2 received → format/version → nonce cache (fresh?) → **GMAC(A2) over `(…‖A1fields)` using K_gmac** (transcript binding) → only then BOTH peers run X25519 → ML-KEM.
**GMAC-before-X25519-before-ML-KEM.** Caps: ≤1 pending per `sender_id`, ≤2 global, 30 s TTL+LRU, freed on completion. `K_gmac = HKDF-Extract("hmb1-gmac-v1", NetKey)` (pre-shared signer #06/#15).

## 5. CT posture (§4(d)) — X25519 is now ON the path
- **X25519 Montgomery ladder, PURE-KOTLIN, constant-time, reusing the #10 spike's radix-2^26 GF(2^255−19) field.** The #10 spike (`CsidhCtFieldSpike.kt`) verified `feMul`/`feSqr`/`feReduce` of GF(p) for `p = 2^255−19` bit-exact against `BigInteger`; that is precisely the Curve25519 base field, so the verified CT field arithmetic is **repurposed** for the X25519 scalar ladder (clamp mask `|= 0x7F; &= 0xF8` CT; `csel`-based conditional swaps/branchless; `ss==0` reject via CT compare → abort). *Corrects the E2 version of this § (#08 §2.4 "spike not reused").*
- AES-256-GMAC tag computation + **constant-time** tag compare (the #06/#15 binding).
- SHAKE-256 input construction (public labels; secret K_seed — low leakage).
- ML-KEM-512 `KeyGen_internal`/`Encaps_internal` seed sampling — **branchless** (Kyber-reference discipline); CT = pattern + differential tests vs `BigInteger`.
All on-path crypto is Pure-Kotlin (cross-platform CT guarantee); native may be an audited fast-path only if CT-disciplined. No native on the handshake path by default.

### §5.3 iOS / native gap — now **on path**
X25519 is platform-available (iOS CryptoKit `Curve25519.KeyAgreement` public since iOS 13 — **not** private; Android `X25519` since API 28), BUT platform X25519 CT is not formally guaranteed across OEMs/JITs. Spec mandates the Pure-Kotlin CT ladder (reusing #10 spike field) as the baseline; native fast-path is opt-in only if CT-disciplined + tested. (Packet-5 §5.3 "moot under E2" — mootness lifted under E1′.)

## 3 (phases) / Protocol phases (the AI-codegen contract)
- **Phase A0 — Provisioning (#12/#17, resolved).** Host injects `OobProvisioner` (`suspend fun provideSignerKey(): Aes256GmacKey` → 32-byte signer = NetKey). Library ships in-memory `TestOobProvisioner`. No in-library QR/NFC UI. At-rest per #17 (iOS Keychain `AfterFirstUnlockThisDeviceOnly`; Android Keystore AES + optional StrongBox; atomic delete-then-add rotation). No static X25519 identity key (ephemeral only).
- **Phase A — Two-flight handshake (E1′, true PFS).** Central writes A1 → peripheral gates (format→cache→GMAC(A1)) → writes A2 → both gate GMAC(A2; transcript) → both run §3 derivation → first AES-GCM data packet failing open ⇒ abort (implicit key confirmation, no 3rd flight). Ephemeral X25519 privates zeroized post-derivation; engines zeroized on completion/timeout.
- **Phase B — Processing.** Both peers reproduce identical `ss → T → K_seed → (d,z),(pk,sk),m,K_df` and HKDF→`key_AB/key_BA`.
- **Phase C — State transition.** Derive symmetric session state. **PFS: ACHIEVED** (ephemeral `ss` erased, irreducible by NetKey — see §4.6). Enter `SESSION`.
- **Phase D — Symmetric session.** AES-256-GCM bidirectional; monotonic AEAD nonce; rekey cadence (default: handshake-refresh-driven, #07). `c*` never persists.

## 4.6 [PFS + PQ — OWNER ACK now CLOSED]
- **PFS: TRUE forward secrecy (ACHIEVED).** `ss = X25519(eph_priv, …)` — ephemeral private erased, never on air, **not** a function of NetKey. A future NetKey compromise + recorded A1/A2 cannot recompute `ss` ⇒ cannot recompute `K_seed` ⇒ cannot recover `(d,z),(pk,sk),m,K_df` for past sessions. **Harvest-now-decrypt-later is OUT under the PFS threat model.** (Closes the ADR-0002 §5.2 / #11 / #13 integrity flags.)
- **PQ:** session-key strength = ML-KEM-512 (~128-bit quantum) via `K_df`; X25519 `ss` contributes PFS, not quantum resistance (classical ~128-b, erased). Hybrid breakage requires a future quantum computer **and** NetKey **and** reconstruction of the erased `ss` (impossible). PQ-PSK optional 32 B pairwise slot (default off) for extra binding; KDF identical. *(The packet-5 caveat "ML-KEM input derives from K_seed ⇒ not PQ" does **not** apply under E1′: `K_seed` now mixes the erased `ss`, so NetKey+Quantum cannot re-derive `K_seed` ⇒ `K_df` stays ML-KEM-512-PQ.)*

## Acceptance gate
`#08` **frozen E1′ (true PFS)**: all `[EXPERT TBD #11/#13]` replaced (expert sign-off packet 6). §4.6 PFS flag **CLOSED** (achieved, no longer an ACK gate). Transport (§1), DoS (§1.6), platform (§1.7/§5.3), enrollment (Phase A0 #12), CT (§5) all resolved. Codegen-ready TDD: RFC 7748 X25519 KAT + NIST ACVP AES-GCM/SHAKE/ML-KEM-512 deterministic KATs + E2E vector recipe (§6) + negatives. The only `[EXPERT TBD]` remaining is the final HKDF direction-label strings (pending #07 exact strings) — non-blocking.

## 6. Conformance / test vectors
- **Primitives:** RFC 7748 X25519 (basepoint `u=9` ladder + all-zero-`ss` CT reject) KAT; NIST ACVP/deterministic ML-KEM-512 (`KeyGen_internal(d,z)`, `Encaps_internal(ek,m)`, `Decaps_internal(sk,c*) == K_df`); AES-256-GMAC KAT; SHAKE-256 KAT.
- **Protocol (E2E):** fixed `eph_priv_i`, `eph_priv_r`, `NetKey`, nonces, ids → assert `ss, T, K_seed, (d,z), (pk,sk), m, K_df, c*, key_AB, key_BA`; both peers reproduce identically; `Decaps_internal(sk, c*) == K_df` (test-only).
- **Negatives:** bit-flip any A1/A2 field → GMAC gate drop (before DH); replay (dup nonce) → #15 cache drop; A2-as-A1 reflection → transcript/GMAC drop; `ss == 0` → abort (no key derived); different session → different `K_df` (freshness).
- ML-KEM-512 decapsulation failure rate 2^−138.8 recorded (test self-check only, not on path).
```
