# Research: Verify FIPS 203 ML-KEM-512 deterministic KeyGen from SHAKE-256-derived seeds

Status: resolved
Type: research
Blocked by: (none)

## Question

Phase C derives the ML-KEM-512 state engine locally from the CSIDH shared secret:

```python
seeds = hashlib.shake_256(K_seed).digest(64)
seed_d    = seeds[0:32]
seed_z    = seeds[32:64]
ml_kem_engine = FIPS203_ML_KEM_512.instantiate_with_deterministic_seeds(seed_d, seed_z)
```

FIPS 203 §7.1 `KeyGen(d, z)` takes `d` (32-byte seed) and `z` (32 bytes of randomness used for implicit rejection). §7.2 / the reference also supports deterministic key generation.

Question: (1) Is deriving **both** `d` and `z` from a single SHAKE-256 output of the CSIDH shared secret a conformance-valid **deterministic** ML-KEM-512 key generation per FIPS 203? In particular, is repurposing K_seed as both the seed material and the `z` entropy acceptable, and does this match the deterministic KeyGen procedure (not the randomized variant)?

(2) What concretely is `ml_kem_engine` after `KeyGen(d, z)` — just the `(pk, sk)` pair, or a state from which a **local encapsulation** is then run to obtain the session key `K_df`? If both peers independently derive the same `(pk, sk)` from the same `K_seed`, can they each perform a deterministic self-encapsulation to agree on `K_df`?

Sources: NIST FIPS 203 (esp. §7.1, §7.2, implicit-rejection discussion), the reference ML-KEM implementation (NIST/PQClean/liboqs), and security notes on deterministic key generation.

## Answer

**Resolving: deriving (d, z) from SHAKE-256(K_seed, 64) is conformance-valid deterministic ML-KEM-512 KeyGen — with a domain-separation / z-freshness caveat.**

- FIPS 203 makes `ML-KEM.KeyGen` and its internals **deterministic**: "their output is completely determined by their input" (NIST FIPS 203 §7 internals). Inputs are `d` (32-byte seed) and `z` (32 bytes, randomness for implicit rejection) — matching the SHAKE-256(d || z) split in PROMPT.md. The 2024-08 Federal Register issuance notice confirms NIST "revised FIPS 203 to clarify that keys can be regenerated from saved seed values." **So `ml_kem_engine = KeyGen(d=seed_d, z=seed_z)` from SHAKE-256(K_seed, 64) is valid.**
- **Caveat:** NIST added **domain separation** to deterministic key generation when saving seeds "to prevent the misuse of keys generated to target one security level from being used for a different security level." Also `z` is intended as *fresh* randomness for implicit rejection; reusing K_seed as both d and z is deterministic (allowed) but makes the implicit-rejection masking a deterministic function of the same secret. Whether to accept this, or inject separate/derived entropy + domain-separation labels, is a #07 decision.
- **What `ml_kem_engine` is & the K_df path:** After `KeyGen(d, z)`, the engine holds `(pk, sk)`. The session key `K_df` comes from `ML-KEM.Encaps(pk)` → (K_df, ciphertext). Because both peers derive the *same* (pk, sk) from the same K_seed, each can independently encapsulate — but agreement requires identical randomness, i.e. encapsulation must be deterministic (K_df a deterministic function of K_seed). This collapses the KEM to a deterministic PRF-like expansion of K_seed; #07 must ratify the security model.
- Reference sizes (local only, zero over-the-air): ML-KEM-512 pk=800 B, ct=768 B, shared secret=32 B.

Sources:
- NIST FIPS 203 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf): §7 KeyGen(d, z), deterministic internals, implicit rejection.
- Federal Register 2024-08-14 (FIPS 203 issuance): seed regeneration + domain-separation revision.
- "NIST PQC Standards Explained" (qcecuring.com): ML-KEM-512 sizes & Fujisaki-Okamoto transform.

