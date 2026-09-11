# ChatGPT

## Expert gate result

 **#11: conditionally APPROVE E1, with two mandatory corrections.**\
 **#13: REJECT as specified. Replace deterministic ML-KEM self-encap with a KDF directly over the airborne secret.**

 The important point is that FIPS 203 does **not** give you a security argument for “deterministic self-encapsulation as a KDF.” FIPS 203's internal `Encaps_internal` is deterministic, but the standardized `ML-KEM.Encaps` interface requires fresh randomness for every invocation, and NIST explicitly says those internal derandomized interfaces are for testing/module purposes rather than application use.  NIST Publications+1

 ### #11 — recommended binding

 I would approve **E1: ephemeral X25519**, but define it as a **classical authenticated entropy/key-establishment component feeding the local ML-KEM state**, not as a PQ KEM by itself.

 Use:

```
Packet_A =
    version        1 B
    x25519_eph_pk 32 B
    session_nonce  8 B
    sender_id      4 B
    flags           1 B
    GMAC           16 B
                  ------
                   62 B
```

 That is **2 bytes over the stated 60-byte requirement**, so the packet must be compressed/adjusted. The cleanest layout is:

```
version        1 B
x25519_eph_pk 32 B
session_nonce  8 B
sender_id      3 B
flags           1 B
GMAC           15 B
                ------
                 60 B
```

 However, I **do not recommend truncating the GMAC to 120 bits merely to hit the arbitrary 60-B ceiling** unless #08 explicitly accepts that security level.

 The better answer is to exploit the fact that the existing `sender_id` can be encoded in **2 bytes** if the protocol's node namespace permits 65,536 identities:

```
version        1
x25519_eph_pk 32
session_nonce  8
sender_id      2
flags           1
GMAC          16
----------------
               60 B
```

 **This is the layout I recommend freezing.**

 The GMAC-covered authenticated string must be:

```
version || x25519_eph_pk || session_nonce || sender_id || flags
```

 —not merely the old four-field AAD with the X25519 public value omitted.

 ### Binding proof

 The receiver has a provisioned/derived expectation that `sender_id` identifies the peer. The received X25519 ephemeral public key is authenticated by the GMAC because it is inside the authenticated transcript.

 Therefore an active MITM has two choices:

 1. Modify `x25519_eph_pk` → GMAC verification fails.
2. Preserve `x25519_eph_pk` → the attacker cannot substitute the DH contribution.

 Consequently the attacker cannot cause the receiver to derive a different `K_seed` while retaining a valid authentication tag.

 This is the crucial correction to the original #11 flaw: **never recompute a GMAC over the received fields and call that authentication.** The receiver must verify the transmitted tag against the exact received transcript using constant-time tag comparison.

 X25519 itself should also be domain-bound into the KDF. RFC 7748 specifically recommends deriving the symmetric key using the DH result together with both public shares, and warns against subtle identity/public-key binding mistakes. It also specifies the all-zero shared-secret check and constant-time Montgomery-ladder/cswap approach.  RFC Editor

 I would therefore define:

```
K_dh = X25519(sender_eph_sk, receiver_static_pk)

K_seed =
    HKDF-SHA3-256(
        salt = "ABKM-v1" || version,
        IKM  = K_dh,
        info = "airborne-seed" ||
               sender_id ||
               receiver_id ||
               x25519_eph_pk ||
               receiver_static_pk ||
               session_nonce
    )[0..63]
```

 Both public keys should be included in the derivation even though only the sender's ephemeral key crosses the wire; the receiver's static public key is locally known.

 The X25519 all-zero result is an abort condition. RFC 7748 explicitly permits this check and recommends a constant-time zero test.  RFC Editor

 ### Freshness/replay

 Keep the existing #15 nonce cache:

```
key = sender_id || session_nonce
TTL = 30 s
capacity = 2^10
```

 Reject a duplicate **before X25519 and before ML-KEM work**.

 The nonce must be freshly generated per `Packet_A`; it is not a KDF secret. The X25519 ephemeral private key is independently freshly generated for the session.

 This gives two different protections:

 - nonce → replay suppression;
- ephemeral X25519 → fresh secret contribution.

 HKDF is appropriate for extracting/expanding the DH material and binding protocol context; RFC 5869 explicitly supports contextual `info` binding.  RFC Editor

 ### CT review

 For E1, the #10 CSIDH radix-2²⁶ code is **not applicable**.

 The required CT review is instead:

 - X25519 scalar clamping;
- Montgomery ladder;
- conditional swaps;
- field multiplication/reduction;
- inversion;
- all-zero test;
- HKDF/SHA3 implementation;
- constant-time GMAC/tag comparison.

 RFC 7748 specifically describes X25519 as designed to facilitate constant-time implementations and gives the constant-time conditional-swap construction.  RFC Editor

 On iOS, given your stated platform constraints, the implementation therefore needs the **Pure-Kotlin X25519 path** rather than relying on a non-public CryptoKit primitive.

 ### Important security boundary

 This construction is **not quantum-safe because of X25519**. Its PQ security comes from the subsequent ML-KEM state.

 That distinction should be explicit in #08:

 > X25519 supplies the compact airborne authenticated/fresh secret contribution; ML-KEM-512 supplies the post-quantum key-establishment security of the resulting session.

 Hybrid KEM designs combining X25519 and ML-KEM are a well-established pattern, although the standardized TLS constructions use a normal transmitted ML-KEM ciphertext rather than your unusual local-state construction.  RFC Editor

---

 # #13 — deterministic self-encap: NO

 I would **not sign off on #13 as currently designed.**

 FIPS 203's application-level `ML-KEM.Encaps` requires fresh 32-byte randomness for every invocation. NIST explicitly says:

 > “A fresh string of random bytes must be generated for every such invocation.”

  NIST Publications  The fact that `Encaps_internal(ek,m)` is mathematically deterministic for fixed `(ek,m)` does **not** make it a standardized deterministic KDF.

 More importantly, in your architecture the ML-KEM key pair is already derived from `K_seed` and is never transmitted. Thus deterministic self-encapsulation adds no meaningful key-establishment property. The real secret is already `K_seed`.

 ## Recommended replacement

 Delete:

```
K_df = ML-KEM.SelfEncaps_deterministic(pk, rnd)
```

 and define:

```
K_df =
    HKDF-SHA3-256(
        salt = "ABKM-v1" || version,
        IKM  = K_seed,
        info = "mlkem-session-kdf" ||
               sender_id ||
               receiver_id ||
               session_nonce
    )[0..31]
```

 Then derive the AES-GCM key from `K_df` with a separate label:

```
K_gcm =
    HKDF-SHA3-256(
        salt = "ABKM-v1" || version,
        IKM  = K_df,
        info = "aes-256-gcm-session"
    )[0..31]
```

 This is much easier to reason about, conforms to the intended KDF role, and avoids pretending that ML-KEM is providing security where it isn't.

 FIPS 203 itself says that when further key derivation is needed, the ML-KEM shared secret is to be passed into an approved KDF; NIST also cautions that combining KEMs requires its own security assessment rather than automatically inheriting ML-KEM's IND-CCA claim.  NIST Publications

 ## PFS consequence

 With E1:

```
past session
    ↓
ephemeral X25519 secret
    ↓
K_seed
    ↓
ephemeral ML-KEM state
    ↓
K_df
    ↓
AES-GCM
```

 If the sender's ephemeral X25519 private key and derived ML-KEM state are destroyed after the session, compromising the long-term GMAC/signer key **does not recover past `K_seed` values**.

 That is the PFS condition:

 > **Past-session secrecy holds provided the ephemeral X25519 private key, `K_seed`, ML-KEM `(d,z)/(pk,sk)`, K\_df and session key are erased and are never persisted.**

 A later compromise of the long-term signer key therefore permits future authentication forgery, but does not by itself reconstruct past X25519 shared secrets.

 This is another reason **E2 should not be selected**: a static NetKey-derived `K_seed` would let compromise of that NetKey reconstruct past session state, defeating the claimed PFS.

---

 # One further correction: don't call the local ML-KEM state itself the source of PFS

 There is a conceptual issue in #07/#13 worth making explicit.

 If both peers independently derive the **same** ML-KEM `(pk,sk)` from `K_seed`, then the ML-KEM key pair is not contributing independent entropy. It is merely a deterministic transformation of `K_seed`.

 So:

```
K_seed → ML-KEM.KeyGen → (pk,sk)
```

 does **not** increase the entropy or PFS of `K_seed`.

 The PFS comes from E1's fresh ephemeral X25519 secret.

 Likewise, deterministic self-encapsulation is not what establishes PFS.

---

 # Conformance vector

 I would **not put a made-up ML-KEM `(ct,K_df)` vector into the spec**. Since I am rejecting the mechanism, its vector should disappear rather than become a misleading compliance artifact.

 The replacement test vector should instead be:

```
fixed:
  version
  sender_id
  receiver_id
  session_nonce
  receiver_static_X25519_pk
  sender_ephemeral_X25519_sk

derive:
  sender_ephemeral_X25519_pk
  K_dh
  K_seed[64]
  K_df[32]
  K_gcm[32]
```

 and assert that both peers produce byte-identical `K_seed`, `K_df`, and `K_gcm`.

 For X25519, RFC 7748 already supplies a canonical test vector and shared-secret result suitable for validating the primitive independently.  RFC Editor

 The protocol-level vector should additionally test:

 - change one bit of `x25519_eph_pk` → GMAC failure;
- change one bit of `sender_id` → GMAC failure;
- change one bit of `session_nonce` → GMAC failure;
- duplicate nonce → replay rejection;
- X25519 all-zero result → abort;
- same inputs on both peers → identical KDF outputs;
- different nonce → different KDF outputs.

---

 ## Final disposition

 | Ticket | Decision | Freeze action |
| --- | --- | --- |
| **#11** | **APPROVE E1**, with 60-B packet layout and X25519 public key included in the GMAC transcript and KDF context | Freeze the airborne binding around authenticated ephemeral X25519 |
| **#13** | **REJECT deterministic ML-KEM self-encap** | Replace it with HKDF-SHA3-256 over `K_seed`; no deterministic `rnd` |
| PFS | **YES**, conditional on destruction of all ephemeral state | Long-term signer compromise does not retroactively recover E1 sessions |
| E2 | **REJECT** for the stated PFS goal | Static NetKey-derived `K_seed` is not acceptable |
| CSIDH | **NO** | Remains completely off hot path |
| #10 CT primitives | **Do not reuse as X25519 implementation** | Separate RFC-7748 X25519 CT review required |

**One caveat before calling #11 fully closed:** the phrase “peer identity” must mean an identity that the attacker cannot freely claim. A single fleet-wide symmetric GMAC key authenticates possession of the fleet key, **not cryptographically unique sender identity**. If the threat model includes a malicious but authorized node impersonating another node, #06's single shared signer key is insufficient and #11 remains open until there is a per-peer authentication key or another identity-binding mechanism. If the threat model is an external MITM without the long-term key, the authenticated `sender_id || x25519_eph_pk` transcript closes the substitution attack described in the packet.

 That distinction should be explicitly recorded in #11 rather than left implicit.

 FIPS 203 — ML-KEM \
  RFC 7748 — X25519/X448 \
  RFC 5869 — HKDF \
  NIST SP 800-227 — Recommendations for Key-Encapsulation Mechanisms

# Google AI

## 🛠️ Crypto-Expert Review Packet: #11 & #13 Resolution
Status: Approved for Spec Freeze (#08)
Target: Architecture B (Local FIPS 203 ML-KEM-512 State Engine)
------------------------------
## 💡 Executive Analysis of Architecture B
The retirement of CSIDH-over-air (#10) removes the architectural bottleneck of expensive, variable-time isogeny walks. However, it shifts a critical cryptographic burden to the local-remote handoff: because ML-KEM-512 ciphertexts (768 bytes) exceed your strict single-frame BLE transport ceiling (ATT_MTU = 247, target payload $\le$ 60 bytes), we cannot transmit an ML-KEM ciphertext across the air.
Instead, we must rely on a hybrid architecture: an airborne key transport mechanism that securely establishes a shared K_seed over the air, which both peers then use locally to deterministically generate an identical ML-KEM-512 key pair (pk, sk) via SHAKE-256.
Below is the formal expert resolution for #11 (Airborne KEM Binding) and #13 (Deterministic Self-Encapsulation) to unblock the #08 spec freeze.
------------------------------
## 📊 #11 — Replacement Airborne KEM Binding## (a) Payload Layout & Size Analysis
To satisfy the strict $\le$ 60-byte payload target for Packet_A within a single ATT_MTU = 247 frame, we select an Ephemeral-Static X25519 Hybrid (E1). Because the long-term identity keys are symmetric (AES-256-GMAC for #06/#15), we introduce a long-term, static X25519 identity key pair for each peer, distributed out-of-band (OOB) alongside the GMAC key (#17).
## Packet_A Binary Layout (Total: 58 Bytes)

* 
* Version (1 byte): Protocol versioning.
* Flags (1 byte): Protocol state indicators.
* Sender_ID (8 bytes): Unique peer identifier (u64).
* Nonce (8 bytes): Freshness token (u64), monitored by the #15 sliding-window cache.
* Ephemeral_X25519_PK (32 bytes): The sender's ephemeral public key (Public).
* Key_Confirmation_Tag (8 bytes): Truncated MAC binding the transcript and identity (Secret/Verifiable).
* 

## (b) Binding Correctness vs. #06 Q3 Tampering Threat
The core vulnerability of the original design was a Key Substitution Attack: because the #06 authentication model relies on a symmetric pre-shared key (AES-256-GMAC) shared among a cluster or pair, an attacker who compromises or intercepts a packet could swap out the key exchange components. If the GMAC only covers the transport envelope, a modified key would still pass the DoS gate if the GMAC tag is forged or if a valid peer's packet is manipulated by a malicious insider.
## The Fix: Transcript Identity Binding (TIB)
We eliminate this vulnerability by forcing the derived keying material to be mathematically dependent on both the transport layer parameters and the long-term identities.

   1. The Sender generates an ephemeral X25519 keypair ($x, X$).
   2. The Sender computes the ECDH shared secret: $SS_{x25519} = \text{X25519}(x, \text{Receiver\_Static\_PK})$.
   3. Both peers derive K_seed by incorporating the full exchange transcript into SHAKE-256:
   $$\text{K\_seed} = \text{SHAKE-256}(SS_{x25519} \mathbin{\Vert} \text{Sender\_ID} \mathbin{\Vert} \text{Receiver\_ID} \mathbin{\Vert} \text{Nonce}, 64)$$ 
   4. The Gatekeeper: The 8-byte Key_Confirmation_Tag is computed as:
   $$\text{Tag} = \text{AES-256-GMAC}_{\text{K\_seed}}(\text{Version} \mathbin{\Vert} \text{Flags} \mathbin{\Vert} \text{Sender\_ID} \mathbin{\Vert} \text{Nonce} \mathbin{\Vert} X)$$ 

If an attacker substitutes $X$ with a malicious $X'$, the receiver computes a completely different $SS_{x25519}'$, yielding an incorrect $\text{K\_seed}'$. The Key_Confirmation_Tag validation will fail prior to executing local ML-KEM operations, completely mitigating the injection vector.

[Sender]                                                     [Receiver]
   │                                                             │
   │ ─── Packet_A (Version ‖ Flags ‖ ID ‖ Nonce ‖ X ‖ Tag) ───>  │
   │                                                             │
   │                                                   [1. DoS GMAC Gate Passes]
   │                                                   [2. Compute SS_x25519]
   │                                                   [3. Derive K_seed]
   │                                                   [4. Verify Tag via K_seed]
   │                                                       🛑 Abort if Invalid

## (c) Domain Separation, Freshness, & Replay

* 
* Domain Separation: The initialization vector for the local state engine utilizes structured context strings. When feeding K_seed into SHAKE-256 for deterministic ML-KEM.KeyGen(d, z), the input stream must be formatted as:
$$\text{Input} = \text{K\_seed} \mathbin{\Vert} \text{"Architecture-B-MLKEM-512-Derivation-v1"}$$ 
* Freshness & Replay Bounds: The #15 nonce cache (size $2^{10}$, 30-second TTL with LRU eviction) provides a hard window for network-layer replay protection. Because Nonce is folded directly into the $SS_{x25519}$ transcript derivation, any replayed Packet_A within the 30-second window is caught by the LRU cache. Any replay attempt outside the 30-second window fails because the timestamp/sequence sync triggers a state mismatch at the application layer.
* 

## (d) Constant-Time (CT) Posture
The verification path of the airborne element involves decoding the 32-byte X25519 public key and executing the scalar multiplication.

* 
* Pure-Kotlin Safe-Zone: You must not reuse the #10 radix-$2^{26}$ field primitives as-is. CSIDH primitives were optimized for different internal field arithmetic. Instead, the X25519 layer must use a dedicated radix-$2^{25.5}$ or radix-$2^{51}$ constant-time field implementation for $\mathbb{F}_{2^{255}-19}$.
* All conditional swaps during the Montgomery ladder execution must utilize bitwise masks (cswap) rather than conditional branching (if-else) to defend against data-cache timing attacks during background execution (#16).
* 

------------------------------
## 📈 #13 — Deterministic Self-Encapsulation Soundness
The proposed mechanism leverages a deterministic self-encapsulation loop to derive the final key-derivation function input ($K_{df}$).

[Local Peer State Engine]
   │
   ├─► 1. Run ML-KEM.KeyGen(SHAKE-256(K_seed)) ──► yields (pk, sk)
   ├─► 2. Run ML-KEM.Encap(pk) deterministically using fixed seed ──► yields (c, K_shared)
   └─► 3. Derive K_df = HKDF-SHA3-256(K_shared ‖ c)

## Cryptographic Soundness Assessment
Yes, this construction is cryptographically sound, provided strict parameters are maintained.
In standard FIPS 203 deployments, ML-KEM.Encap draws 32 bytes of randomness from a system RNG to generate the shared secret $K$ and ciphertext $c$. By substituting this system RNG with a deterministic seed derived from our transcript-bound K_seed, both peers—who have already synchronized K_seed via the airborne channel—can independently compute the identical $(c, K)$ pair without transmitting the 768-byte ciphertext $c$ over the air.
## Security Properties & Proof Framework## 1. IND-CCA2 Security Preservation
Because the ciphertext $c$ never traverses the untrusted air channel, it is immune to active intercept-and-modify attacks in transit. The execution happens entirely inside each peer's memory space. The security reduces to the hardness of the Module Learning With Errors (M-LWE) problem; an attacker observing the BLE air traffic sees only the X25519 ephemeral key, meaning they gain zero advantage in distinguishing $K_{shared}$ from a random bitstring.
## 2. Mitigation of Multi-Recipient Seed Re-use Defects
Deterministic encapsulation normally introduces vulnerabilities if the same seed is used to encrypt different payloads to different recipients. Here, because K_seed is unique per session (derived from an ephemeral X25519 key and a unique Nonce), the deterministic seed fed into ML-KEM.Encap is guaranteed to be globally unique per session execution.
## 3. Prevention of Failure-Boosting Attacks
In LWE-based schemes, attackers can sometimes craft malicious ciphertexts to intentionally trigger decryption failures, leaking information about the private key. Because $c$ is generated locally using a verified, structured transcript, there is zero attacker control over the inputs to ML-KEM.Decaps, nullifying this attack vector entirely.
## 4. Wealth-Degrading Guardrail (Entropy Collapse)
To ensure that any potential mathematical correlation between the X25519 layer and the ML-KEM layer does not result in entropy collapse, the input to the deterministic encapsulation must be domain-separated from the key generation parameters.
$$\text{Seed}_{\text{encap}} = \text{SHAKE-256}(\text{K\_seed} \mathbin{\Vert} \text{"Deterministic-Encap-Domain-v1"}, 32)$$ 
The final session key setup must follow the HKDF-SHA3-256 implementation path established in #07:
$$\text{K\_session} = \text{HKDF-Extract-and-Expand}(\text{PRK} = K_{shared}, \text{Info} = c \mathbin{\Vert} \text{Sender\_ID} \mathbin{\Vert} \text{Receiver\_ID}, 32)$$ 
This structural framework safely seals the #08 Spec Freeze.
------------------------------
To finalize the implementation architecture for the upcoming code-gen sessions, please confirm:

* 
* The storage format for the new static X25519 identity public keys within your provisioning packet.
* If you want the exact Pure-Kotlin method signatures for the constant-time cswap Montgomery ladder integration to prevent background side-channels.
* 

# GLM-5.3-Flash

**CLAIMED: crypto-expert (S6/S7). Below is the sign-off packet for §4/§6. Both #11 and #13 are resolved; no `[EXPERT TBD]` remains except one flagged non-blocking config decision (§4.6 below). Code-gen sessions still must not act on this until the agent folds it into #08.**

---

## 1. #11 — Replacement airborne-KEM binding: **DECIDED**

### 1.1 Family choice: **E1′ — ephemeral↔ephemeral X25519, transcript-bound by the existing GMAC gate.**

**E2 is REJECTED, and the reason is a finding the packet got half-right:** the packet asks whether PFS "still holds end-to-end with a static `K_seed`." **It does not.** If `K_seed = f(NetKey, public nonces)`, then compromise of the signer/NetKey at time *t* lets the attacker *recompute* `K_seed → (d,z) → (pk,sk) → m → K_df → session key` for every recorded past session. The per-session ephemeral ML-KEM engine contributes **zero** PFS in that case — "non-persisted ⇒ PFS" (#02/#07) is only true when the seed has *independent per-session entropy that is erased*. Since PFS is asserted twice in the decided table, E2 contradicts decided constraints and is out. (If the program ever formally waives PFS, E2 is the correct simple fallback — record that in #08 as a contingency, not a choice.)

E1-static (ephemeral→receiver's static X25519) is also rejected: receiver-static-key compromise breaks past sessions (no PFS), *and* it adds a new long-term key to #17 provisioning. Dominated.

E1′ properties: PFS against all post-erasure compromise (both scalars ephemeral); **no new long-term key** (§5.1 unchanged); 2-flight handshake, each flight ≤60 B, single frame.

### 1.2 Payload layouts (exact)

Flight 1 — `Packet_A1` (initiator→responder), **59 B on air**:

| Field | Bytes | Notes |
|---|---|---|
| ver\|type | 1 | hi nibble ver=0x1, lo nibble type=0x1 (HELLO) |
| nonce_i | 8 | 4B coarse-time/counter + 4B random; unique per #15 cache |
| sender_id | 2 | mesh address |
| eph_pub_i | 32 | RFC 7748 little-endian u-coordinate |
| GMAC tag | 16 | **AAD = ver\|type ‖ nonce_i ‖ sender_id ‖ eph_pub_i** |

Flight 2 — `Packet_A2` (responder→initiator), **59 B on air**:

| Field | Bytes | Notes |
|---|---|---|
| ver\|type | 1 | type=0x2 (HELLO_ACK) |
| nonce_r | 8 | fresh |
| sender_id | 2 | |
| eph_pub_r | 32 | |
| GMAC tag | 16 | **AAD = A2 fields ‖ received-A1 fields (nonce_i ‖ sender_id ‖ eph_pub_i)** |

GCM IV (per packet, both flights and data): `0x11 ‖ direction(1) ‖ nonce(8) ‖ 0x00 0x00` (12 B). `eph_pub` sits **inside the authenticated region**, not merely alongside it — that is the substitution fix.

### 1.3 Binding proof vs. §4(b) substitution threat

Claim: any `Packet_A` accepted into derivation is bit-identical to what a key-holder emitted.
- Modify `eph_pub` (or any field) in transit → GMAC tag invalid → **dropped at the #15 gate, before any derivation**. Unforgeability of the tag under the signer key is the binding; the receiver's possession of the key lets it *verify*, never *forge on behalf of an attacker-chosen input*, because the tag must cover the attacker's modified bytes — which the attacker cannot compute.
- Replay A1 within 30 s TTL → #15 nonce cache. After TTL → bounded waste only (see 1.4).
- Reflection (A2 replayed as A1) → type nibble is inside the tag, and `nonce_i ≠ nonce_r` fails the pending-handshake state check.
- Unknown-key-share → both `sender_id`s and both ephemerals enter the transcript `T` (below), which is salt for every derivation step.
- Insider (holds `K_auth`) is out of model per #06 (symmetric trust, non-repudiation out of scope). Residual: `K_auth` compromise permits active MITM on *future* sessions — inherent to symmetric auth; see §1.6 for the confidentiality caveat this implies.

Handshake is 2 flights; key confirmation is implicit in the first AES-256-GCM data packet failing to open → abort. No third flight.

### 1.4 Seed derivation, domain separation, freshness/replay (§4(c))

```
ss      = X25519(eph_priv_local, eph_pub_remote)          // reject if all-zero (CT compare)
T       = SHA3-256("HMB1-TR" || A1fields || A2fields)     // transcript
K_seed  = HKDF-SHA3-256-Extract(salt = T, IKM = ss || PSK_opt)   // PSK_opt = 32B or 32×0x00
(d, z)  = SHAKE-256("HMB1-DZ" || T || K_seed, 64)         // #02 shape + labels
(pk,sk) = ML-KEM-512.KeyGen(d, z)                          // local only, never on air
m       = SHAKE-256("HMB1-EM" || T || K_seed, 32)
(K_df, c*) = ML-KEM-512.Encaps(pk, m)                      // c* NEVER transmitted
key_AB / key_BA = HKDF-SHA3-256-Expand(Extract(salt=T, IKM=K_df),
                   "HMB1-K-AB"||id_i||id_r  /  "HMB1-K-BA"||id_i||id_r, 32)
```

Replay analysis vs the #15 cache (2^10 / 30 s): handshake rate ≪ cache capacity → in-TTL replays blocked. **Out-of-TTL replays pass the cache** (GMAC is timeless) — so the spec mandates two caps: ≤1 pending incomplete handshake per remote `sender_id`, ≤8 pending engines globally, engines freed on 30 s TTL. Worst attacker-induced waste per replay = one ephemeral keygen + one DH + one ML-KEM KeyGen/Encap (sub-ms–ms), post-GMAC-gate, fail-closed. **Verdict: the 30 s cache is sufficient with these two caps added; #15 needs no extension, only the caps.** Data-plane replay beyond TTL is killed by the #14 seqno layer, as already decided. `c*` and `K_df` never cross the air; relays (same fleet key) may re-verify GMAC per hop; handshake is e2e, transparent to #14 forwarding; bg-safe (2 flights fit in throttled connection events; ≤2 connection intervals ≥100 ms — acceptable per #16).

### 1.5 CT posture (§4(d), §5.2)

- **The #10 spike field IS reusable, contra the packet's aside:** `p = 2^255−19` *is* the Curve25519 prime. The spike's radix-2^26 CT field is directly the base for an X25519 Montgomery ladder. Net-new surface = ladder + clamping + encode/decode only, ~300 LoC, differential-tested vs `BigInteger` exactly as the spike already does.
- CT checklist (mandatory, goes to #08 verbatim): ladder with masked conditional swap; clamped scalar; no secret-dependent branches or array indexing; all-zero-`ss` check via OR-accumulation; constant-time tag comparison in the GMAC gate; ML-KEM seed/noise sampling branch-free (Kyber-reference discipline); SHAKE/HMAC inputs secret but hash side-channels accepted as low-risk.
- JVM/ART JIT caveat stated honestly: CT is enforced by pattern + review + differential arithmetic tests, not runtime measurement. This satisfies ADR-0001's "Pure-Kotlin CT fallback" for this path.

### 1.6 Key finding — correct the PQ claim in E1's pros/cons (record in #08, non-blocking)

The packet's E1 note says "PQ-ness is preserved by the local ML-KEM-512 tail." **False as stated.** In X-Wing the ML-KEM secret contributes *independent* entropy to the combiner; here every ML-KEM input (`d,z,m`) derives from `K_seed`, which derives from X25519. All entropy is classical. Post-#10, Arch B with a ≤60 B airborne element is a **classical-confidentiality** design; the ML-KEM-512 tail is a FIPS-203-aligned engine/KDF, not a PQ guarantee. Spec language must not claim hybrid PQ confidentiality. If harvest-now-decrypt-later is in scope, the minimal fix costs **zero on-air bytes**: provision a 32 B **PQ-PSK** per pair at OOB time (#17 storage, rotation as-is) — it already has the `PSK_opt` slot above (config bit, default all-zero). **This is the one open config decision I flag to the spec owner; it does not block #08 freezing** because the derivation spec is identical either way.

---

## 2. #13 — Deterministic self-encap-as-K_df: **SOUND (YES), with conditions**

**Q1: Yes.** Argument: in this construction the ML-KEM instance is never exposed to an adversary — `c*` is never transmitted, `pk` is secret-derived and never on air, and `ML-KEM.Decaps` runs only on locally computed `c*` (test self-check) — so the CCA game's decryption oracle is structurally absent and the implicit-rejection path never fires. What remains required of Encaps is only that `K_df = J(m ‖ H(pk))` be a pseudorandom function of unpredictable inputs; with `m` transcript-bound and `K_seed` secret, that holds in the SHAKE-256 (ROM) composition, i.e., the whole chain is a two-step extract-then-expand KDF (SP 800-56C shape). Determinism is not the FO "randomness-reuse" hazard: final FIPS 203 Encaps is *already* deterministic in `m` (`K, r ← J(m ‖ H(ek))`), and the standard's own conformance KATs use fixed seeds — deterministic encapsulation is a normative, testable mode. **Mandatory conditions:** (i) `m` bound to `T` — never constant across sessions (a fixed `m` + static seed ⇒ identical `K_df` every session: catastrophic; this is why "bound" was strongly preferred and is now **required**); (ii) `K_seed` high-entropy (guaranteed: X25519 output / PSK); (iii) `(d,z)` never reused across different `K_seed` lines. Multi-key subtlety: both devices holding the identical `(pk,sk)` is benign — one logical trust principal, no independent relying parties. Reference SP 800-227 (draft) for KEM-output-as-key-material guidance alongside FIPS 203.

**Q2: PFS condition, stated precisely:** PFS holds ⟺ every per-session secret input to the `K_df` chain (`ss`, `K_seed`, `m`, `K_df`, `sk`) is irrecoverable after session erasure from any long-term key plus recorded traffic. Under E1′: **yes** — retroactive `K_auth` compromise does *not* break past sessions (session keys never derive from `K_auth`; it only enables active MITM on future handshakes, inherent to #06). Under E2: **no**, per §1.1. Residual (record): `K_auth` + quantum capability + recorded traffic defeats past sessions unless PQ-PSK (§1.6) is provisioned.

**Q3: Test vector recipe** (recipe spec'd here; hex vectors generated by two independent implementations for the corpus):
- Primitive level: run the official FIPS 203 ACVP deterministic KATs (`ACVP-Server`, seed-based `(d,z)`, fixed `m`) to lock KeyGen/Encaps/Decaps.
- Protocol level: fixed inputs `id_i=0x0001, id_r=0x0002`, fixed `nonce_i/nonce_r`, fixed `eph_pub` pairs → assert hex for `ss`, `T`, `K_seed`, `(d,z)`, `H(pk)`, `m`, `K_df`, `H(c*)`, `key_AB`, `key_BA`. Both peers reproduce from the same transcript. `m` is **bound** (transcript-chained), never reused. Optional self-check `Decaps(sk, c*) == K_df` in tests only. Record: ML-KEM-512 decapsulation failure 2^−138.8 (not exercised on path; effectively zero in-band failure probability since `c*` is never transmitted).

---

## 3. §5 tension resolutions

- **§5.1 Single key: APPROVED** with mandated separation. `K_auth` carries signer + DoS-gate + transcript-auth roles, separated by GCM IV domain prefix + AAD structure (no cross-domain nonce reuse). Do **not** derive per-role subkeys: the key must stay keystore-resident for the #15 background gate (#17), and derived subkeys would force export. Residual risk (compromise = total active compromise) is already accepted by #06.
- **§5.2 Scope:** enumerated in §1.5. X25519 ladder is the only genuinely new review surface, and it inherits the spike's verified field arithmetic.
- **§5.3 iOS gap: DISSOLVED.** Under E1′, nothing on the handshake path needs platform crypto — X25519, SHAKE-3, HMAC, ML-KEM all Pure-Kotlin; native is used only for at-rest storage (#17). For the record, two factual corrections to the packet, both moot under this decision: iOS CryptoKit's `Curve25519.KeyAgreement` has been **public** API since iOS 13 (not private); and Android Keystore X25519 at "API 28+" is dubious (XDH arrived much later and fragmentedly) — which further supports not relying on platform X25519 at all.

## 4. Sign-off → what the agent freezes into #08

1. §2: the two `Packet_A` byte tables (§1.2) + IV format; 59 B ≤ 60 B, single frame at MTU 247.
2. §3 Phases A/B/C: handshake flow (§1.3), the derivation block (§1.4) verbatim with labels, the two pending-handshake caps, engine zeroization requirement.
3. Test corpus: ACVP KATs + E2E vector recipe (§2 Q3); negative tests — bit-flip→gate drop, replay→cache drop, A2-as-A1 reflection→drop, all-zero-`ss`→abort; differential field tests vs `BigInteger`; bg handshake ≤2 connection events.
4. One `[DECISION-FLAGGED, non-blocking]` line: PQ-PSK provisioning on/off (§1.6); KDF is identical either way.

With these inserted, #08 contains no remaining `[EXPERT TBD]` and is **cleared for freeze**. Wayfinder note: §1.6's PQ claim correction and §3's two factual footnotes should be back-annotated to `issues/05` and the #16/#17 research files so the packet record stays truthful.

# Claude Sonnet 5

# Expert review: #11 (airborne-KEM binding) + #13 (deterministic self-encap-as-K_df)

Status: **#13 sign-off (conditional)** — sound, with one required correction to the PFS claim.
**#11 sign-off (conditional)** — recommend **E1**, but only after fixing a binding gap that is present in the packet as specified. **E2 is rejected outright** for any deployment where PFS is a stated requirement (it is — see #07/#17).

---

## #13 — Is deterministic self-encap-as-KDF sound?

### 13.1 Yes/no + argument

**Yes, sound** — with the construction anchored correctly. Here's why it isn't the CCA-transform footgun it looks like at first glance.

FIPS 203's `Encaps` is `(K, c) ← Encaps(ek; m)` where `m` is 32 bytes of randomness ("the coin"), and NIST's own reference algorithms define a deterministic entry point — `Encaps_internal(ek, m)` — that takes the coin as an explicit argument specifically so validation suites can run known-answer tests against fixed inputs. That's precisely the operation you're proposing to use in production, just pointed at a different `m`. Reusing that internal deterministic surface is legitimate *engineering* — it's literally what NIST built it for — but it changes the security argument you get to make, and it's worth being explicit about which argument that is:

Standard ML-KEM security (IND-CCA2) is a statement about an adversary who **knows `ek`** and gets to choose ciphertexts to feed to `Decaps`. That's not your threat model here. In this design, `ek` (and `dk`) are **never transmitted** — both peers derive the identical keypair locally from a value (`K_seed`) that is secret. So the thing you're actually relying on for `K_df`'s secrecy isn't ML-KEM's CCA game at all; it's that `G` (SHA3-512, per FIPS 203) is a good PRF/hash and that `ek` — the thing you're hashing — is unknown to the attacker. Concretely: `(K_df, c) = G(m ‖ H(ek))`-derived, and since `ek = f(K_seed)` for a one-way `f` (ML-KEM KeyGen), this is functionally a KDF over secret material with public salt `m`. It doesn't need `m` to be secret or fresh for *this* property to hold, because the standard threat model's premise (adversary knows `ek`) never applies here.

**The one place this bites you:** a recent analysis of ML-KEM's internal coin (*"On the Secrecy of the Encapsulation Coin in ML-KEM,"* IACR eprint 2026/1117) proves that if an adversary who *also* knows `ek` learns the coin `m`, they trivially recompute `K` with zero interaction. That's exactly the failure mode you must not reintroduce: if `ek` ever leaks or is ever transmitted (e.g., a future protocol revision, a debug log, a KAT harness left wired into a release build), a fixed/public `m` becomes an immediate break. The same paper flags that in real libraries this deterministic entry point is "not allowed to be used directly by callers" in normal operation, and that the boundary between test-only and production-reachable is enforced "only by convention." **Recommendation:** wall this off hard — a dedicated, clearly-named `selfEncapKdf()` function that is the *only* caller of the deterministic internal API, `ek`/`dk` never serialized to a wire format or a log, and a code-review gate (or lint rule) that anything calling the randomized `Encaps` path can't accidentally be swapped for this one and vice versa.

### 13.2 PFS inheritance — **the claim as written is wrong for E2, correct for E1**

This is the load-bearing finding of this review, so stating it plainly: **`K_df` inherits PFS if and only if `K_seed` itself has forward secrecy.** The self-encap step is just a local hash; it cannot manufacture PFS that isn't already in its input. So the PFS question fully reduces to #11's choice:

- If `K_seed` is **static** (candidate E2 — pre-shared NetKey), then `KeyGen(SHAKE-256(K_seed))` — even with a session nonce mixed in — produces a keypair that an attacker who later steals `K_seed` can **recompute for every past session**, because the nonce is public (it travels in `Packet_A` in the clear) and `K_seed` is the only secret input. Record-now-decrypt-later against the *entire session history* becomes viable the moment the long-term key is compromised. The packet's own framing ("PFS still holds end-to-end with a static K_seed... mitigated by per-session ephemeral ML-KEM engine") does not hold up: the ML-KEM engine is only "ephemeral" in the sense that its *keys aren't stored on disk*, not in the cryptographic sense of being unrecoverable from long-term secrets + transcript. **This directly contradicts #07's stated design goal.** Flag §07 for re-review if E2 is chosen.
- If `K_seed` includes a genuine **per-session Diffie-Hellman contribution** whose ephemeral private half is generated fresh and destroyed after use (candidate E1), then compromising the long-term/static key later does *not* let an attacker recover that ephemeral scalar, and PFS holds for the component that was actually forward-secret. See §11.3 below for the precise scope of what is and isn't covered.

**Bottom line for #13.2:** the condition is "K_seed must itself be the output of a Diffie-Hellman (or equivalent) exchange with a discarded ephemeral private component; a symmetric PSK alone, no matter how it's mixed with nonces, cannot supply PFS." This settles the E1-vs-E2 question in §11 as much as anything in §11 itself does.

### 13.3 Test vector / conformance guidance

- Use `KeyGen_internal(d, z)` and `Encaps_internal(ek, m)` explicitly — don't reverse-engineer determinism by seeding an RNG, since that couples correctness to your PRNG implementation instead of to the standard's own deterministic algorithms (which is what auditors and any future NIST ACVP-style conformance check will expect).
- **Bind `m`, don't hardcode it.** Even though §13.1's argument doesn't strictly require `m` to vary (secrecy rides on `ek`, not `m`), a fixed constant `m` is fragile defense-in-depth: it means *any* future code path that manages to leak `ek` (a debugging build, a serialization bug, a side-channel) immediately gives full recovery per the eprint result above, with no second factor. Bind it: `m = HKDF-Expand(K_seed, "airborne-kem-v1/self-encap-coin" ‖ role ‖ sender_id ‖ session_nonce, 32)`. This costs nothing (it's a local computation) and removes an entire failure class for free. This is the "bound, strongly preferred" option the handoff packet itself flags — take it.
- Minimal vector: fix `K_seed`, `role`, `sender_id`, `session_nonce` → derive `(d,z)` → `KeyGen_internal` → `ek,dk` → derive `m` per the binding above → `Encaps_internal(ek,m)` → `(K_df, c)`. Both peers must reproduce identical `(ek, K_df)` from identical inputs; `c` never leaves the device (it's discarded — you don't need Decaps at all here, since both sides run Encaps independently rather than one side encapsulating and the other decapsulating).
- The 2⁻¹³⁸·⁸ decapsulation-failure rate is irrelevant to this vector as the packet notes (Decaps is never invoked in the self-encap path) — record it for the corpus for completeness only.

**#13 sign-off:** ✅ construction is sound, subject to (a) walling off the deterministic API as described, (b) binding `m` per the HKDF derivation above, (c) correcting §07's PFS claim to depend on #11's choice rather than asserting it unconditionally.

---

## #11 — Replacement airborne-KEM binding

### 11.a — Recommended family: **E1 (ephemeral-X25519-as-seed), with a binding fix**

**E2 is rejected** as the sole mechanism: per §13.2, a static pre-shared `K_seed` cannot deliver PFS, full stop, regardless of nonce mixing. If the product genuinely doesn't need PFS, say so explicitly and re-open #07's stated design goal — don't let it stand as an implicit contradiction. Given #07 already asserts non-persisted ⇒ PFS as a goal, treat that as authoritative and rule out E2.

**E1 as *specified* in the packet has a real gap**, though — not in the DH itself, but in what the packet's own §4(b) is warning about. The draft field map is:

```
version ‖ seed/nonce ‖ sender_id ‖ flags
```

...with the #15 GMAC computed over `(version ‖ nonce ‖ sender_id ‖ flags)`. Read literally, the **airborne seed (the X25519 ephemeral public key) is not itself inside the MAC's covered bytes** — "seed/nonce" reads as the nonce field, with the seed noted almost parenthetically. If that's an accurate reading of the current framing, this **is exactly the substitution flaw #11 was opened to fix**: an attacker who doesn't hold the shared signer key still can't forge `sender_id`/`nonce`/`flags`, but *can* splice in their own ephemeral X25519 public key, complete the DH against the receiver's known static public key, and produce a packet whose GMAC still verifies — because the GMAC never covered the one field that determines `K_seed`. The receiver would derive an attacker-controlled `K_seed`/`K_df` while the authentication check passes.

**The fix is not new crypto — it's correct framing.** The AES-256-GMAC (or its AAD, if you keep it structured as AEAD-style framing) must cover the **entire `Packet_A` byte string, including the ephemeral public key field**, not just the metadata around it. This is a one-line change to the #15 AAD scope, and it is the actual "binding" mechanism §4(b) asks for — you don't need a separate key-confirmation MAC or transcript hash on top, because the pre-shared symmetric signer key already gives you exactly what's needed (proof the packet, in full, came from a party holding the long-term identity secret) as long as it actually authenticates the full packet.

### 11.b — Payload layout (≤60 B)

| Field | Size | Secret? | Notes |
|---|---|---|---|
| `version` | 1 B | no | protocol version |
| `flags` | 1 B | no | role bit (initiator/responder), etc. |
| `sender_id` | 4–8 B | no | per #15 framing |
| `session_nonce` | 8 B | no | freshness; feeds #15's cache and the `m`-binding in §13.3 |
| `epk_x25519` | 32 B | **public value, but must be authenticated** | sender's ephemeral X25519 public key |
| `GMAC tag` | 16 B | — | AES-256-GMAC over **all preceding fields** |

Total ≈ 62–66 B depending on `sender_id` width — trim `sender_id` to 4 B or drop `flags` into spare bits of `version` if you need to land under the hard 60 B target; either is a minor packing exercise, not a design change.

### 11.c — Domain separation, freshness, replay

- `K_seed = X25519(sender_esk, receiver_static_pk)` (symmetric via `X25519(receiver_static_sk, sender_epk)`) — do **not** feed this raw into `SHAKE-256`; run it through a proper extract step first: `K_seed' = HKDF-Extract(salt = "airborne-kem-v1", ikm = K_seed ‖ session_nonce ‖ sender_id ‖ receiver_id)` before it hits `SHAKE-256(K_seed', 64) → (d,z)`. This gives you clean domain separation between this protocol and any other use of the same static X25519 identity key, and ties the derived keypair to the specific session/pair of peers rather than to the raw ECDH output alone.
- The existing #15 nonce-freshness cache (2¹⁰ entries, 30 s TTL+LRU) is **sufficient** for replay bounding of `Packet_A` itself, *provided* the GMAC now covers `epk_x25519` per §11.a. Without that fix, the cache doesn't help — a replayed-with-substituted-epk packet would carry a *new*, attacker-chosen nonce and sail through the freshness check with a validly-recomputable-looking (but wrongly-scoped) tag. With the fix, no extension to the cache is needed.

### 11.d — Constant-time posture

- X25519 CT arithmetic is a **different, well-trodden problem** from the #10 CSIDH spike (Montgomery ladder over 𝔽\_{2²⁵⁵₋₁₉}, not an isogeny walk) — do not attempt to repurpose the CSIDH field code, as the packet itself notes. If you need a Pure-Kotlin implementation for iOS (see §11.e), base it on a well-reviewed reference ladder (e.g., the classic djb Curve25519 constant-time ladder structure: fixed-iteration Montgomery ladder, no secret-dependent branches, constant-time conditional swap), not a fresh derivation.
- The decode/reduce path for `epk_x25519` needs the standard field-element validation (reject low-order/non-canonical points per RFC 7748 §5 recommendations) done in constant time before the ladder runs, so a malformed 32-byte field can't be used to force timing-observable early rejection that leaks receiver-static-key bits.
- `KeyGen_internal`/`Encaps_internal` (§13) should already be constant-time if you're using a conformant ML-KEM implementation (NTT-based ops are naturally branch-free on secret data in good implementations) — confirm this for whatever Pure-Kotlin ML-KEM implementation is actually in the codebase; it's a property of the implementation, not something this review can certify in the abstract.

### 11.e — iOS native gap

Two things to verify before committing to E1, since the packet's own claims here should be double-checked rather than taken as given:
- **X25519 in AndroidKeyStore:** worth re-confirming the exact API level — recollection is that Curve25519/XDH support landed in AndroidKeyStore around Android 13 (API 33), not API 28 as stated in the packet's E1 description. If your minSdk is below whatever the actual floor is, you're doing Pure-Kotlin X25519 on Android too, not just iOS — which simplifies the story (one CT implementation, both platforms) but changes the "native where possible" framing. Confirm against current Android documentation before locking the plan.
- **iOS:** the packet's assessment that CryptoKit's `Curve25519` API is unavailable for this general-purpose use is worth a fresh check — CryptoKit has shipped a public `Curve25519.KeyAgreement` API for some time, which would mean iOS gets *native* constant-time X25519 without a Pure-Kotlin fallback. If that's confirmed available at your deployment target, the "Pure-Kotlin CT X25519 likely required on iOS" conclusion in the packet's E1 description should be revised — that would remove one of E1's stated costs entirely. Recommend a quick platform-API spike (similar in spirit to #10) before finalizing, since it materially affects the CT-review scope in §5.2.

### 11.e (packaging) — new key material and #17

E1 requires each peer to hold a **static X25519 identity keypair** in addition to the existing symmetric signer key. This is new long-term secret material and must go through #17's at-rest handling — but note it's *asymmetric*, so unlike the symmetric GMAC key it **can** be Secure-Enclave/StrongBox-backed on both platforms (subject to the CryptoKit/Keystore availability check in §11.e above). This is a net win for §5.1's tension: it splits "signer + DoS-gate key" (symmetric, stays as-is) from "KEM seed key" (asymmetric, new, hardware-backable) instead of loading a third role onto the single existing symmetric key. Recommend closing §5.1 by keeping the symmetric key at its current two roles (signer + DoS gate) and giving the new X25519 identity key its own storage entry in #17.

---

## Summary against §6 acceptance criteria

**#11:** ✅ conditional sign-off on **E1**. Required before this closes: (1) fix the GMAC/AAD scope to cover `epk_x25519` — this *is* the binding fix §4(b) asked for; (2) confirm the platform-native-X25519 availability facts in §11.e before finalizing the CT implementation plan; (3) route the new static X25519 identity key through #17 as its own key, not folded into the signer key.

**#13:** ✅ sign-off on the construction, conditional on (1) using `KeyGen_internal`/`Encaps_internal` explicitly rather than an ad-hoc deterministic RNG seed, walled off from the randomized production path; (2) binding the encapsulation coin `m` via HKDF as specified in §13.3 rather than a fixed constant; (3) correcting #07's PFS claim — PFS is inherited from #11's choice (E1), not from the self-encap mechanism itself, and does **not** hold under E2 regardless of nonce mixing.

Once the GMAC-scope fix (§11.a) and the `m`-binding (§13.3) are reflected in the #08 draft, both tickets are closeable and #08 can freeze.

# Gemini 3.1 Pro

# Expert review: #11 (airborne-KEM binding) + #13 (deterministic self-encap-as-K_df)

Status: **#13 sign-off (conditional)** — sound, with one required correction to the PFS claim.
**#11 sign-off (conditional)** — recommend **E1**, but only after fixing a binding gap that is present in the packet as specified. **E2 is rejected outright** for any deployment where PFS is a stated requirement (it is — see #07/#17).

---

## #13 — Is deterministic self-encap-as-KDF sound?

### 13.1 Yes/no + argument

**Yes, sound** — with the construction anchored correctly. Here's why it isn't the CCA-transform footgun it looks like at first glance.

FIPS 203's `Encaps` is `(K, c) ← Encaps(ek; m)` where `m` is 32 bytes of randomness ("the coin"), and NIST's own reference algorithms define a deterministic entry point — `Encaps_internal(ek, m)` — that takes the coin as an explicit argument specifically so validation suites can run known-answer tests against fixed inputs. That's precisely the operation you're proposing to use in production, just pointed at a different `m`. Reusing that internal deterministic surface is legitimate *engineering* — it's literally what NIST built it for — but it changes the security argument you get to make, and it's worth being explicit about which argument that is:

Standard ML-KEM security (IND-CCA2) is a statement about an adversary who **knows `ek`** and gets to choose ciphertexts to feed to `Decaps`. That's not your threat model here. In this design, `ek` (and `dk`) are **never transmitted** — both peers derive the identical keypair locally from a value (`K_seed`) that is secret. So the thing you're actually relying on for `K_df`'s secrecy isn't ML-KEM's CCA game at all; it's that `G` (SHA3-512, per FIPS 203) is a good PRF/hash and that `ek` — the thing you're hashing — is unknown to the attacker. Concretely: `(K_df, c) = G(m ‖ H(ek))`-derived, and since `ek = f(K_seed)` for a one-way `f` (ML-KEM KeyGen), this is functionally a KDF over secret material with public salt `m`. It doesn't need `m` to be secret or fresh for *this* property to hold, because the standard threat model's premise (adversary knows `ek`) never applies here.

**The one place this bites you:** a recent analysis of ML-KEM's internal coin (*"On the Secrecy of the Encapsulation Coin in ML-KEM,"* IACR eprint 2026/1117) proves that if an adversary who *also* knows `ek` learns the coin `m`, they trivially recompute `K` with zero interaction. That's exactly the failure mode you must not reintroduce: if `ek` ever leaks or is ever transmitted (e.g., a future protocol revision, a debug log, a KAT harness left wired into a release build), a fixed/public `m` becomes an immediate break. The same paper flags that in real libraries this deterministic entry point is "not allowed to be used directly by callers" in normal operation, and that the boundary between test-only and production-reachable is enforced "only by convention." **Recommendation:** wall this off hard — a dedicated, clearly-named `selfEncapKdf()` function that is the *only* caller of the deterministic internal API, `ek`/`dk` never serialized to a wire format or a log, and a code-review gate (or lint rule) that anything calling the randomized `Encaps` path can't accidentally be swapped for this one and vice versa.

### 13.2 PFS inheritance — **the claim as written is wrong for E2, correct for E1**

This is the load-bearing finding of this review, so stating it plainly: **`K_df` inherits PFS if and only if `K_seed` itself has forward secrecy.** The self-encap step is just a local hash; it cannot manufacture PFS that isn't already in its input. So the PFS question fully reduces to #11's choice:

- If `K_seed` is **static** (candidate E2 — pre-shared NetKey), then `KeyGen(SHAKE-256(K_seed))` — even with a session nonce mixed in — produces a keypair that an attacker who later steals `K_seed` can **recompute for every past session**, because the nonce is public (it travels in `Packet_A` in the clear) and `K_seed` is the only secret input. Record-now-decrypt-later against the *entire session history* becomes viable the moment the long-term key is compromised. The packet's own framing ("PFS still holds end-to-end with a static K_seed... mitigated by per-session ephemeral ML-KEM engine") does not hold up: the ML-KEM engine is only "ephemeral" in the sense that its *keys aren't stored on disk*, not in the cryptographic sense of being unrecoverable from long-term secrets + transcript. **This directly contradicts #07's stated design goal.** Flag §07 for re-review if E2 is chosen.
- If `K_seed` includes a genuine **per-session Diffie-Hellman contribution** whose ephemeral private half is generated fresh and destroyed after use (candidate E1), then compromising the long-term/static key later does *not* let an attacker recover that ephemeral scalar, and PFS holds for the component that was actually forward-secret. See §11.3 below for the precise scope of what is and isn't covered.

**Bottom line for #13.2:** the condition is "K_seed must itself be the output of a Diffie-Hellman (or equivalent) exchange with a discarded ephemeral private component; a symmetric PSK alone, no matter how it's mixed with nonces, cannot supply PFS." This settles the E1-vs-E2 question in §11 as much as anything in §11 itself does.

### 13.3 Test vector / conformance guidance

- Use `KeyGen_internal(d, z)` and `Encaps_internal(ek, m)` explicitly — don't reverse-engineer determinism by seeding an RNG, since that couples correctness to your PRNG implementation instead of to the standard's own deterministic algorithms (which is what auditors and any future NIST ACVP-style conformance check will expect).
- **Bind `m`, don't hardcode it.** Even though §13.1's argument doesn't strictly require `m` to vary (secrecy rides on `ek`, not `m`), a fixed constant `m` is fragile defense-in-depth: it means *any* future code path that manages to leak `ek` (a debugging build, a serialization bug, a side-channel) immediately gives full recovery per the eprint result above, with no second factor. Bind it: `m = HKDF-Expand(K_seed, "airborne-kem-v1/self-encap-coin" ‖ role ‖ sender_id ‖ session_nonce, 32)`. This costs nothing (it's a local computation) and removes an entire failure class for free. This is the "bound, strongly preferred" option the handoff packet itself flags — take it.
- Minimal vector: fix `K_seed`, `role`, `sender_id`, `session_nonce` → derive `(d,z)` → `KeyGen_internal` → `ek,dk` → derive `m` per the binding above → `Encaps_internal(ek,m)` → `(K_df, c)`. Both peers must reproduce identical `(ek, K_df)` from identical inputs; `c` never leaves the device (it's discarded — you don't need Decaps at all here, since both sides run Encaps independently rather than one side encapsulating and the other decapsulating).
- The 2⁻¹³⁸·⁸ decapsulation-failure rate is irrelevant to this vector as the packet notes (Decaps is never invoked in the self-encap path) — record it for the corpus for completeness only.

**#13 sign-off:** ✅ construction is sound, subject to (a) walling off the deterministic API as described, (b) binding `m` per the HKDF derivation above, (c) correcting §07's PFS claim to depend on #11's choice rather than asserting it unconditionally.

---

## #11 — Replacement airborne-KEM binding

### 11.a — Recommended family: **E1 (ephemeral-X25519-as-seed), with a binding fix**

**E2 is rejected** as the sole mechanism: per §13.2, a static pre-shared `K_seed` cannot deliver PFS, full stop, regardless of nonce mixing. If the product genuinely doesn't need PFS, say so explicitly and re-open #07's stated design goal — don't let it stand as an implicit contradiction. Given #07 already asserts non-persisted ⇒ PFS as a goal, treat that as authoritative and rule out E2.

**E1 as *specified* in the packet has a real gap**, though — not in the DH itself, but in what the packet's own §4(b) is warning about. The draft field map is:

```
version ‖ seed/nonce ‖ sender_id ‖ flags
```

...with the #15 GMAC computed over `(version ‖ nonce ‖ sender_id ‖ flags)`. Read literally, the **airborne seed (the X25519 ephemeral public key) is not itself inside the MAC's covered bytes** — "seed/nonce" reads as the nonce field, with the seed noted almost parenthetically. If that's an accurate reading of the current framing, this **is exactly the substitution flaw #11 was opened to fix**: an attacker who doesn't hold the shared signer key still can't forge `sender_id`/`nonce`/`flags`, but *can* splice in their own ephemeral X25519 public key, complete the DH against the receiver's known static public key, and produce a packet whose GMAC still verifies — because the GMAC never covered the one field that determines `K_seed`. The receiver would derive an attacker-controlled `K_seed`/`K_df` while the authentication check passes.

**The fix is not new crypto — it's correct framing.** The AES-256-GMAC (or its AAD, if you keep it structured as AEAD-style framing) must cover the **entire `Packet_A` byte string, including the ephemeral public key field**, not just the metadata around it. This is a one-line change to the #15 AAD scope, and it is the actual "binding" mechanism §4(b) asks for — you don't need a separate key-confirmation MAC or transcript hash on top, because the pre-shared symmetric signer key already gives you exactly what's needed (proof the packet, in full, came from a party holding the long-term identity secret) as long as it actually authenticates the full packet.

### 11.b — Payload layout (≤60 B)

| Field | Size | Secret? | Notes |
|---|---|---|---|
| `version` | 1 B | no | protocol version |
| `flags` | 1 B | no | role bit (initiator/responder), etc. |
| `sender_id` | 4–8 B | no | per #15 framing |
| `session_nonce` | 8 B | no | freshness; feeds #15's cache and the `m`-binding in §13.3 |
| `epk_x25519` | 32 B | **public value, but must be authenticated** | sender's ephemeral X25519 public key |
| `GMAC tag` | 16 B | — | AES-256-GMAC over **all preceding fields** |

Total ≈ 62–66 B depending on `sender_id` width — trim `sender_id` to 4 B or drop `flags` into spare bits of `version` if you need to land under the hard 60 B target; either is a minor packing exercise, not a design change.

### 11.c — Domain separation, freshness, replay

- `K_seed = X25519(sender_esk, receiver_static_pk)` (symmetric via `X25519(receiver_static_sk, sender_epk)`) — do **not** feed this raw into `SHAKE-256`; run it through a proper extract step first: `K_seed' = HKDF-Extract(salt = "airborne-kem-v1", ikm = K_seed ‖ session_nonce ‖ sender_id ‖ receiver_id)` before it hits `SHAKE-256(K_seed', 64) → (d,z)`. This gives you clean domain separation between this protocol and any other use of the same static X25519 identity key, and ties the derived keypair to the specific session/pair of peers rather than to the raw ECDH output alone.
- The existing #15 nonce-freshness cache (2¹⁰ entries, 30 s TTL+LRU) is **sufficient** for replay bounding of `Packet_A` itself, *provided* the GMAC now covers `epk_x25519` per §11.a. Without that fix, the cache doesn't help — a replayed-with-substituted-epk packet would carry a *new*, attacker-chosen nonce and sail through the freshness check with a validly-recomputable-looking (but wrongly-scoped) tag. With the fix, no extension to the cache is needed.

### 11.d — Constant-time posture

- X25519 CT arithmetic is a **different, well-trodden problem** from the #10 CSIDH spike (Montgomery ladder over 𝔽\_{2²⁵⁵₋₁₉}, not an isogeny walk) — do not attempt to repurpose the CSIDH field code, as the packet itself notes. If you need a Pure-Kotlin implementation for iOS (see §11.e), base it on a well-reviewed reference ladder (e.g., the classic djb Curve25519 constant-time ladder structure: fixed-iteration Montgomery ladder, no secret-dependent branches, constant-time conditional swap), not a fresh derivation.
- The decode/reduce path for `epk_x25519` needs the standard field-element validation (reject low-order/non-canonical points per RFC 7748 §5 recommendations) done in constant time before the ladder runs, so a malformed 32-byte field can't be used to force timing-observable early rejection that leaks receiver-static-key bits.
- `KeyGen_internal`/`Encaps_internal` (§13) should already be constant-time if you're using a conformant ML-KEM implementation (NTT-based ops are naturally branch-free on secret data in good implementations) — confirm this for whatever Pure-Kotlin ML-KEM implementation is actually in the codebase; it's a property of the implementation, not something this review can certify in the abstract.

### 11.e — iOS native gap

Two things to verify before committing to E1, since the packet's own claims here should be double-checked rather than taken as given:
- **X25519 in AndroidKeyStore:** worth re-confirming the exact API level — recollection is that Curve25519/XDH support landed in AndroidKeyStore around Android 13 (API 33), not API 28 as stated in the packet's E1 description. If your minSdk is below whatever the actual floor is, you're doing Pure-Kotlin X25519 on Android too, not just iOS — which simplifies the story (one CT implementation, both platforms) but changes the "native where possible" framing. Confirm against current Android documentation before locking the plan.
- **iOS:** the packet's assessment that CryptoKit's `Curve25519` API is unavailable for this general-purpose use is worth a fresh check — CryptoKit has shipped a public `Curve25519.KeyAgreement` API for some time, which would mean iOS gets *native* constant-time X25519 without a Pure-Kotlin fallback. If that's confirmed available at your deployment target, the "Pure-Kotlin CT X25519 likely required on iOS" conclusion in the packet's E1 description should be revised — that would remove one of E1's stated costs entirely. Recommend a quick platform-API spike (similar in spirit to #10) before finalizing, since it materially affects the CT-review scope in §5.2.

### 11.e (packaging) — new key material and #17

E1 requires each peer to hold a **static X25519 identity keypair** in addition to the existing symmetric signer key. This is new long-term secret material and must go through #17's at-rest handling — but note it's *asymmetric*, so unlike the symmetric GMAC key it **can** be Secure-Enclave/StrongBox-backed on both platforms (subject to the CryptoKit/Keystore availability check in §11.e above). This is a net win for §5.1's tension: it splits "signer + DoS-gate key" (symmetric, stays as-is) from "KEM seed key" (asymmetric, new, hardware-backable) instead of loading a third role onto the single existing symmetric key. Recommend closing §5.1 by keeping the symmetric key at its current two roles (signer + DoS gate) and giving the new X25519 identity key its own storage entry in #17.

---

## Summary against §6 acceptance criteria

**#11:** ✅ conditional sign-off on **E1**. Required before this closes: (1) fix the GMAC/AAD scope to cover `epk_x25519` — this *is* the binding fix §4(b) asked for; (2) confirm the platform-native-X25519 availability facts in §11.e before finalizing the CT implementation plan; (3) route the new static X25519 identity key through #17 as its own key, not folded into the signer key.

**#13:** ✅ sign-off on the construction, conditional on (1) using `KeyGen_internal`/`Encaps_internal` explicitly rather than an ad-hoc deterministic RNG seed, walled off from the randomized production path; (2) binding the encapsulation coin `m` via HKDF as specified in §13.3 rather than a fixed constant; (3) correcting #07's PFS claim — PFS is inherited from #11's choice (E1), not from the self-encap mechanism itself, and does **not** hold under E2 regardless of nonce mixing.

Once the GMAC-scope fix (§11.a) and the `m`-binding (§13.3) are reflected in the #08 draft, both tickets are closeable and #08 can freeze.

# Grok 4.5 Fast

**Expert sign-off on #11 (airborne-KEM binding) + #13 (deterministic self-encap-as-K_df).**  
This closes both tickets so that `#08` can freeze without residual `[EXPERT TBD]` markers.

---

## #11 — Replacement airborne-KEM binding

**Chosen family: E2 — Pre-shared `K_seed` (NetKey-derived).**

### Rationale (trade-offs vs. constraints)
- Size, DoS, background, CT, and zero-new-primitive constraints dominate. E1 (ephemeral X25519) adds a new primitive that must be Pure-Kotlin CT on iOS (CryptoKit X25519 is not publicly usable in the required form) and expands the CT review surface beyond the already-accepted ML-KEM path. E2 reuses the existing long-term symmetric material already required by #06/#15/#17.
- PQ security of the session is supplied entirely by the **local** per-session ML-KEM-512 engine (Architecture B). The airborne element only needs to supply a high-entropy, identity-bound seed; it does not need to be PQ itself.
- PFS is preserved end-to-end by the ephemeral `(pk,sk)` (never persisted) — see #13 below.
- No new long-term key is introduced, so #17 at-rest / rotation rules are unchanged.

### (a) Payload layout (`Packet_A` ≤ 60 B)
```
version (1 B) ‖ session_nonce (16 B) ‖ sender_id (8 B) ‖ flags (1 B) ‖ GMAC (16 B)
```
Total: 42 B (comfortably under 60 B; single ATT_MTU=247 frame, zero fragmentation).

- All fields except the GMAC are public and form the AAD for the #15 AES-256-GMAC gate (exactly matching the existing framing `(version‖nonce‖sender_id‖flags)`).
- The 16-byte `session_nonce` is the only value that must be unique per session under the 30 s nonce-cache window.
- No secret material travels on the air. `K_seed` is the already-provisioned NetKey (or a domain-separated derivation of it — see (c)).

### (b) Binding correctness vs. #06 Q3 / in-transit substitution
The GMAC is computed with the long-term signer key over the entire public header. An attacker who substitutes any field (including a forged `session_nonce` or `sender_id`) produces a GMAC that the receiver rejects **before** any ML-KEM work.  

Because both peers already share the NetKey, the derived `K_seed` is identical only when the GMAC verifies. There is no public key that can be rewritten while still producing a valid GMAC (the original CSIDH flaw). Peer identity is bound by the combination of:
- authenticated `sender_id` inside the GMAC AAD, and  
- the fact that only a correctly provisioned peer possesses the NetKey that yields the matching `K_seed`.

### (c) Domain separation + freshness + replay
```
K_seed = SHAKE-256( NetKey ‖ "airborne-seed-v1" ‖ version ‖ role_bit ‖ sender_id ‖ session_nonce , 64 )
```
(or simply the NetKey itself if domain separation is preferred at the HKDF layer later).  

- Freshness is supplied by the 16-byte `session_nonce` checked against the existing #15 2¹⁰-entry / 30 s TTL+LRU cache.  
- The cache bound is sufficient: an attacker can force at most 1024 Decaps attempts inside any 30 s window, each of which still costs only the cheap GMAC check before any ML-KEM work. Extending the cache is unnecessary.  
- Role bit prevents reflection; version prevents cross-protocol reuse.

### (d) Constant-time posture
The only airborne verification path is AES-256-GMAC (already required to be CT by #15 / ADR-0001) followed by a SHAKE-256 derivation that is inherently CT. No arithmetic reduction or field arithmetic is performed on attacker-controlled data before the GMAC gate. The #10 radix-2²⁶ patterns are **not** needed.

### (e) Key-reuse confirmation (§5.1)
Acceptable. The single AES-256 key already serves three tightly related roles (signer, DoS-gate, seed source). Domain separation of the GMAC AAD and of the SHAKE input keeps the roles cryptographically distinct. A separate key would only increase #17 rotation complexity with no measurable security gain under the current threat model.

### iOS / Pure-Kotlin (§5.3)
No new native primitives. Everything runs under the existing Pure-Kotlin CT requirements already accepted for ML-KEM and AES-GMAC.

---

## #13 — Deterministic self-encap-as-K_df soundness

**Yes — sound under the stated conditions.**

### 1. Soundness argument
Both peers derive the identical ephemeral `(pk, sk)` from the same `K_seed` via the already-validated deterministic KeyGen path (#02 / Federal Register seed-regeneration language). They then run the **derandomized** ML-KEM.Encaps_internal with a fixed (or session-bound) 32-byte `m` (the “rnd” of the ticket).

FIPS 203 explicitly defines the internal derandomized interfaces (`KeyGen_internal`, `Encaps_internal`) precisely so that deterministic testing and seed-based constructions are possible. The FO transform (implicit rejection via `J(z ‖ ct)`) still holds because:
- the underlying K-PKE is deterministic once the coins are fixed,
- the re-encryption check is performed exactly as specified,
- the only randomness that matters for CCA is the secrecy of `sk` and of `z`, both of which are derived from the session-secret `K_seed` and never leave the device.

Because `(pk, sk)` is **ephemeral and secret to both honest peers**, an external adversary never obtains a public key against which it can mount a classical CCA oracle. Multi-key / reuse subtleties that appear in the static-key setting therefore do not arise. The construction is equivalent to both parties jointly sampling a shared secret and then expanding it through the ML-KEM KDF; the FO machinery simply guarantees that a malformed or substituted ciphertext yields an independent pseudorandom value.

Decapsulation failure probability remains 2⁻¹³⁸·⁸ (ML-KEM-512) and is irrelevant to soundness.

### 2. PFS inheritance
`K_df` inherits PFS from the **ephemeral** `(pk, sk)` pair.  
Condition: `(pk, sk)` (and the intermediate `K_seed`-derived material) are never written to durable storage and are zeroized at session end (#07).  

A later compromise of the long-term NetKey / signer key allows an adversary to recompute past `K_seed` values, but **not** the corresponding `(pk, sk)` pairs that were generated and discarded. Consequently past session keys remain secure (classic “ephemeral DH + static authentication” PFS). Only future sessions are affected by a NetKey compromise, which is the expected behaviour under #17 rotation.

### 3. Minimal deterministic test vector
Use a **bound** `rnd` (strongly preferred):

```
rnd = SHAKE-256( "mlkem-self-encap-rnd-v1" ‖ role_bit ‖ sender_id ‖ session_nonce , 32 )
```

Fixed test inputs (illustrative; replace with concrete KAT values once the Pure-Kotlin ML-KEM is available):

- `K_seed` = 64 zero bytes (or any fixed 64-byte value)
- `session_nonce` = 16 zero bytes
- `sender_id` = 8 zero bytes
- `role_bit` = 0

Both peers must produce identical `(ct, K_df)`. Record the pair in the test corpus; the agent will lock the Phase B/C derivation in `#08`.

---

## Acceptance criteria met

| Ticket | Status |
|--------|--------|
| **#11** | E2 selected; 42 B payload matching #15 GMAC AAD; identity binding via GMAC + shared NetKey; domain separation + 30 s nonce cache; CT statement (AES-GMAC + SHAKE only); key-reuse accepted. |
| **#13** | Deterministic self-encap sound under ephemeral secret `(pk,sk)`; PFS condition stated; bound-rnd test-vector recipe supplied. |

The agent may now freeze `hybrid_pqc_ble_mesh_spec.md` (fill `#08` §2 Packet_A, binding lines in Phases A/B/C, HKDF labels, and the deterministic vector). No further expert input is required for these two tickets.
