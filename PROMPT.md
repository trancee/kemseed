# Ultra-Compact Post-Quantum Cryptography (PQC) over BLE

Implementing Post-Quantum Cryptography (PQC) over Bluetooth Low Energy (BLE) presents a fundamental paradox: **PQC algorithms rely on large mathematical structures (resulting in big keys and ciphertexts), whereas BLE is optimized for tiny, highly fragmented packets**. 

When moving from classical Elliptic-Curve Cryptography (ECC) to PQC over BLE, the primary bottleneck is not CPU cycles—it is **radio transmission energy and link-layer packet fragmentation**. If you stream standard NIST PQC primitives over BLE, a single handshake can fragment into dozens of packets, exponentially increasing airtime, packet drop rates, and battery drain.

Below is an architectural breakdown of the absolute smallest and most efficient custom PQC paradigm designed specifically for BLE's physical and link-layer constraints.

---

## 1. Understanding the BLE-Specific Constraints

To achieve hyper-efficiency, your design must exploit and accommodate specific parameters of the BLE stack:

*   **The MTU Trap:** Standard BLE 4.0 has an Effective ATT MTU of 23 bytes. BLE 4.2 and 5.x allow an extended ATT MTU up to 247 bytes (with a 251-byte Link Layer PDU). Your maximum single-packet payload without fragmentation is exactly **244 bytes** (247 minus the 3-byte ATT header). Any primitive exceeding 244 bytes forces link-layer fragmentation, spiking the radio budget.
*   **Energy Asymmetry:** Transmitting 1 bit of data over a BLE radio consumes orders of magnitude more battery juice than executing dozens of CPU instructions on an ARM Cortex-M4 microcontroller. Therefore, your protocol must aggressively trade **higher local computation for smaller over-the-air payloads**.

---

## 2. Designing the Smallest PQC Primitives

Standard NIST algorithms like ML-KEM-512 (Kyber) or ML-DSA (Dilithium) require public keys and ciphertexts/signatures ranging from 800 bytes to over 2 KB. This is unacceptable for unfragmented BLE. To fit into the constraints, we must utilize alternative or custom primitives.

### For Public Key Encryption / Key Encapsulation (KEM)
*   **The Primitive:** Instead of ML-KEM, leverage an ultra-compact Ring/Module Learning With Errors (R-LWE/M-LWE) scheme customized with a smaller polynomial ring size ($n=128$ or $n=256$) and heavy ciphertext compression (e.g., severe rounding of coefficients). Schemes like *Rudraksh* or *Smaug* modify LWE parameters to target constrained devices.
*   **Payload Footprint:** This drops the Public Key to **$pprox 300\text{ bytes}$** and the Ciphertext down to **$pprox 250\text{ bytes}$**.
*   **Alternatively (Stateful):** If the two devices share a coarse time-sync or counter, a State-Space or Hash-based key progression can be used, but for pure public-key asymmetry, aggressive LWE rounding is required.

### For Digital Signing
*   **The Primitive:** State-of-the-art lattice signatures (like ML-DSA) are too large. State-based hash signatures (like LMS/XMSS) offer very small public keys but massive signatures. The absolute layout winner here is **Falcon-512**. Falcon uses Fast Fourier Sampling over NTRU lattices, achieving the tightest data packaging of any post-quantum signature scheme. 
*   **Payload Footprint:** Falcon-512 yields a Public Key of **897 bytes** and a Signature of **666 bytes**. 
*   **The "Zero-Signature" Custom Shift:** To make it smaller for everyday BLE transactions, **eliminate asymmetric signing altogether during the session phase**. Instead, use Falcon *only once* during an initial out-of-band or first-time deployment phase to sign an identity/root key. For subsequent messages, transition completely to symmetric **Message Authentication Codes (MACs)** powered by **AES-256 (in GCM or CCM mode)** or **KMAC/SHA-3**, which are inherently quantum-safe and introduce an overhead of only 8 to 16 bytes.

---

## 3. The Custom "Zero-Fragmentation" Exchange Protocol

Instead of heavy frameworks like TLS 1.3 or IKEv2, we must craft a lean, flat, asynchronous state machine tailored for GATT characteristics or L2CAP Connection-Oriented Channels.

```
       Peripheral (BLE Device)                       Central (Gateway/Phone)

                 |                                              |
                 | ----- 1. Connection & MTU Exchange --------> | (Set ATT_MTU = 247)
                 |                                              |
                 | <---- 2. Ephemeral Public Key (Seed) ------- | [Payload: ~320B]
                 |                                              (Fragmented into 2 packets)

                 |                                              |
                 | ----- 3. Encapsulated Key + Auth Tag ------> | [Payload: ~270B]
                 |                                              (Fragmented into 2 packets)

                 |                                              |
      [Derive Shared Secret]                         [Derive Shared Secret]

                 |                                              |
                 | <==== 4. Post-Quantum Secure Session ======> | [AES-256-GCM / 16B Overhead]
```

### Step-by-Step Protocol Mechanics

1.  **Connection Optimization:** The peripheral and central explicitly negotiate an `ATT_MTU` of 247 bytes. They change the Connection Interval to match the cryptographic execution delay, ensuring the radio sleeps during heavy math computations to prevent timeouts.
2.  **The Initiation (Central to Peripheral):** The Central generates an ephemeral ultra-compact LWE public key ($pprox 320	ext{ bytes}$). It transmits this to the Peripheral across a custom GATT characteristic. Because it is 320 bytes, the BLE link layer splits it into exactly **2 packets** over the air, requiring minimal buffering.
3.  **The Response & Auth (Peripheral to Central):** 
    *   The Peripheral receives the 320 bytes, runs the KEM encapsulation to generate a symmetric master key, and produces a ciphertext ($pprox 250	ext{ bytes}$).
    *   To verify identity *without* sending a massive 666-byte Falcon signature, the peripheral includes a pre-calculated **Symmetric Mac/Implicit Auth Token** tied to a long-term key established during initial pairing. 
    *   The response packet ($pprox 266	ext{ bytes}$) is sent back, spanning exactly **2 packets** over the air.
4.  **Symmetric Transition:** Both sides derive the shared secret. From this point forward, all data packets use **AES-256-GCM**. AES-256 is highly resistant to Grover's quantum search algorithm, and its payload overhead is tiny (a 12-byte IV and a 16-byte authentication tag), fitting perfectly into a single, unfragmented BLE packet.

---

## 4. Summary of the Architectural Blueprint

| Phase | Primitive Selection | Size (Bytes) | BLE Packets (at 244B MTU) | Why it's optimal |
| :--- | :--- | :--- | :--- | :--- |
| **Key Exchange** | Custom Rounding M-LWE (e.g., Rudraksh style) | ~300B (PK) / ~250B (CT) | 2 Packets / 2 Packets | Minimizes radio airtime; cuts fragmentation overhead by 80% compared to standard ML-KEM. |
| **Authentication** | Falcon-512 (Enrollment) + Symmetric KMAC (Session) | 16B (Session MAC) | 1 Packet | Avoids transmitting asymmetric signatures during live transactions. |
| **Bulk Encryption** | AES-256-GCM | +16B overhead | 1 Packet | Quantum-safe, hardware-accelerated on almost all modern BLE SoCs (e.g., Nordic nRF52/nRF53 series). |

# Specification: Hyper-Efficient Isogeny-to-ML-KEM Hybrid PQC over BLE Mesh

## 1. Context & Architectural Constraints
This specification details a zero-trust, post-quantum secure Peer-to-Peer (P2P) mesh protocol designed for modern and legacy iOS and Android mobile phones operating in the background.

*   **No Multi-Packet GATT Chunking:** Standard PQC (ML-KEM/ML-DSA) requires multi-packet streaming over GATT, causing high drop rates on legacy Android stacks.
*   **The Hybrid Solution:** Use Isogeny-based cryptography (**CSIDH-512**) for a 1-packet over-the-air handshake, then deterministically expand the resulting shared secret into a local **ML-KEM-512** state engine to bypass subsequent heavy CPU operations.
*   **Authentication Mechanism:** Live asymmetric signing is omitted due to large payload sizes. Instead, **AES-256-GCM (GMAC)** acts as the digital signer using a long-term symmetric key pre-shared out-of-band.

---

## 2. Cryptographic Pipeline Layout

### Step 1: Over-the-Air Payload Mapping
Data packets must fit entirely under the 244-byte non-fragmentation limit of standard BLE `ATT_MTU = 247`.

```
Packet A: Handshake Initiation (Client to Server) -> Total: 65 Bytes (1 BLE Packet)
+-------------------+-----------------------------------------+
| Session ID (1 B)  | Ephemeral CSIDH-512 Public Key (64 B)   |
+-------------------+-----------------------------------------+

Packet B: Handshake Response & Sign (Server to Client) -> Total: 81 Bytes (1 BLE Packet)
+-------------------+--------------------------------+----------------------------+
| Session ID (1 B)  | CSIDH-512 Ciphertext (64 B)   | AES-256-GMAC Tag (16 B)    |
+-------------------+--------------------------------+----------------------------+
```

### Step 2: Deterministic Seed-Expansion (The Bridge)
Do not attempt to convert curve points directly to lattice polynomials. Use **SHAKE-256** to derive the deterministic seeds required by **FIPS 203 (ML-KEM)**.

```
       [ Raw CSIDH Shared Secret: K_isogeny ]
                        │
                        ▼
             SHAKE-256(K_isogeny, 64)
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
  Seed 'd' (32B)                 Matrix Seed 'z' (32B)
        │                               │
        └───────────────┬───────────────┘
                        ▼
          Locally Instantiate ML-KEM-512
             via ML-KEM.KeyGen(d, z)
```

---

## 3. Protocol Implementation Blueprint (For AI Execution)

An implementing AI agent must structure the core state machine across the following pseudocode phases:

### Phase A: GATT Initialisation & Packet A
1. Intercept background discovery via the custom 128-bit mesh Service UUID.
2. Central connects to Peripheral and negotiates `ATT_MTU = 247`.
3. Central invokes `csidh_512_crypto_kp_ephemeral()` -> outputs `pk_client` (64 bytes).
4. Construct `Packet_A = [Session_ID (0x01) || pk_client]`.
5. Transmit via single GATT `Write-Without-Response`.

### Phase B: Processing & Packet B (Peripheral Side)
1. Peripheral parses `Packet_A`. Extracts `pk_client`.
2. Invoke `csidh_512_encap(pk_client)` -> outputs `ciphertext` (64 bytes) and `K_isogeny` (64 bytes).
3. Compute identity signature: 
   `AuthTag = AES-256-GMAC(Key: LongTerm_Identity_Key, Data: Session_ID || ciphertext)`
4. Construct `Packet_B = [Session_ID (0x01) || ciphertext || AuthTag]`.
5. Transmit via single GATT `Notification`.

### Phase C: State Transition to ML-KEM
Both devices now execute the following routine inside volatile RAM synchronously:
```python
# Pseudo-implementation mapping for AI Agent reference
import hashlib

def transition_to_ml_kem(K_isogeny):
    # 1. Expand the isogeny secret into deterministic ML-KEM seeds
    seeds = hashlib.shake_256(K_isogeny).digest(64)
    seed_d = seeds[0:32]
    seed_z = seeds[32:64]
    
    # 2. Feed seeds into native FIPS 203 implementation to spin up the local state machine
    # No data travels over the air during this phase
    ml_kem_engine = FIPS203_ML_KEM_512.instantiate_with_deterministic_seeds(seed_d, seed_z)
    return ml_kem_engine
```

### Phase D: Symmetric Session Locking
1. Mix the final derived `ml_kem_engine` keys with the session transcript using `HKDF-SHA3-256`.
2. Secure all subsequent transient mesh messages with **AES-256-GCM**, appending a 12-byte IV and a 16-byte authentication tag to each transmission.

---

## 4. Threat Model & Risk Profile (STRIDE Framework)

### 🕵️‍♂️ Spoofing (Identity Theft)
*   **Threat:** A malicious actor attempts to impersonate a legitimate mesh phone to access private session data.
*   **Mitigation:** The protocol enforces explicit symmetric signing via **AES-256-GMAC** inside `Packet_B`. If the Peripheral does not possess the long-term identity key established out-of-band during provisioning, the generated `AuthTag` will be invalid. The Central will drop the link immediately before running any heavy decapsulation steps.

### 📝 Tampering (Data Modification)
*   **Threat:** An active Man-in-the-Middle (MitM) sniper manipulates the 64-byte CSIDH public key in transit to execute a key-replacement attack.
*   **Mitigation:** The `AuthTag` directly covers the `Session_ID` and the resulting `ciphertext`. Any physical over-the-air bit modification of the public key or ciphertext causes a mathematical breakdown during the GMAC authentication step, aborting the handshake instantly.

### 🛑 Repudiation (Denying Actions)
*   **Threat:** A peer asserts they never broadcasted a specific short-lived command through the mesh network.
*   **Mitigation:** This architecture explicitly trades asymmetric non-repudiation (omitting ML-DSA/Falcon) for smaller payloads. Because verification relies on a symmetric pre-shared master identity key, **technical non-repudiation is not achieved at the session layer**. For security contexts demanding absolute non-repudiation, the initial out-of-band provisioning phase must log an immutable cryptographic enrollment signature.

### 👁️ Information Disclosure (Data Leaks & Quantum Harvesting)
*   **Threat:** An adversary sniffs and logs all background BLE mesh traffic today, intending to decrypt it using a Cryptanalytically Relevant Quantum Computer (CRQC) when they become available.
*   **Mitigation:** The architecture provides **Perfect Forward Secrecy (PFS)**. The `K_isogeny` secret changes completely on every connection because it is derived from fresh ephemeral variables generated by the mobile phone's Hardware True Random Number Generator (TRNG). Even if a long-term master key is exposed in the future, past recorded transactions remain completely protected by quantum-hard mathematical problems (Supersingular Isogeny Path-Finding and Module Learning With Errors).

### 💥 Denial of Service (DoS & Battery Drain)
*   **Threat:** An attacker spams thousands of fake `Packet_A` structures into a crowded space. Processing CSIDH group actions is computationally heavy (~50-150ms), meaning the spam attack could stall background OS loops and drain user batteries.
*   **Mitigation:** 
    1. Implement OS-level **Connection Backoff Timers**: The app daemon tracks peer MAC addresses and restricts connection attempts to a maximum of once per 60 seconds per unique identifier.
    2. Before performing any heavy isogeny mathematics, the device checks the integrity of basic BLE link metrics. If an unknown entity attempts a connection blast, the processor delays execution threads, prioritizing the phone’s system responsiveness.

### 🔑 Elevation of Privilege (Unauthorized Access)
*   **Threat:** An attacker uses Simple Power Analysis (SPA) or timing side-channels to extract the long-term master key while the phone performs calculations in the background.
*   **Mitigation:** The implementing code must utilize strictly **constant-time** implementations for both the CSIDH polynomial calculations and the GMAC tag generation, ensuring execution times remain identical regardless of the cryptographic keys or data processed.

# Context Guide: Hybrid Isogeny-to-ML-KEM Protocol over BLE Mesh

## 1. Project Background & Architectural Problem
Standard post-quantum cryptography (PQC) suites recommended by regulatory bodies—specifically lattice-based mechanisms—rely on structurally heavy public keys and ciphertexts. When deployed over Bluetooth Low Energy (BLE) or BLE Mesh layers, this introduces severe data fragmentation, causing a cascading series of packet drops and buffer deadlocks, particularly on older or resource-constrained background mobile operating system stacks.

This architecture resolves the paradox of heavy PQC keys running on fragmented radio protocol constraints by implementing a **hybrid cryptographic pipeline**. It leverages the extremely tight byte footprints of Isogeny cryptography over the air while transitioning immediately to performance-friendly lattice modules locally in CPU volatile storage.

---

## 2. Deep Dive: Cryptographic Primitives & Specifications

### 2.1 Key Encapsulation (KEM): CSIDH-512
*   **Mathematical Concept:** Commutative Supersingular Isogeny Diffie-Hellman (CSIDH) evaluates group actions on supersingular elliptic curves over a finite field $\mathbb{F}_p$. 
*   **Payload Footprint:** **64-byte Public Key**, **64-byte Ciphertext**.
*   **Design Rationale:** CSIDH-512 yields the smallest quantum-safe public key size of any known asymmetric paradigm. At 64 bytes, a complete initiation payload easily sits inside a single unfragmented GATT command, remaining well below the 244-byte non-fragmentation limit imposed by a legacy standard `ATT_MTU`.
*   **Trade-off:** High computational cost. Evaluating the group action takes roughly 50ms to 150ms on modern ARM chips. This architecture assumes that because both endpoints are high-performance mobile devices, trading temporary local CPU computation to eliminate battery-heavy radio transmission bursts saves system energy overall.
*   **References:** 
    *   [CSIDH Academic Specification Paper (ePrint)](https://eprint.iacr.org/2018/383)
    *   [Reference Implementation C Repository](https://github.com/ioerror/csidh-reference-implementation)
    *   [Constant-Time ARMv8 Architecture Optimized Port](https://github.com/amirjalali65/ARMv8-CSIDH)
    *   [High-throughput and low-latency AVX-512 implementations of CSIDH](https://github.com/splight793/AVX-CSIDH)

### 2.2 Local State Scaling KEM: ML-KEM-512 (FIPS 203)
*   **Mathematical Concept:** Module Learning with Errors (M-LWE) problem over polynomial rings. 
*   **Payload Footprint (Expanded):** 800-byte Public Key, 768-byte Ciphertext.
*   **Over-the-Air Footprint:** **0 Bytes** (Fully virtualized).
*   **Design Rationale:** Rather than processing heavy isogeny group actions for all successive traffic or child key rotators inside an active session, the protocol performs a "Cryptographic Warm-Up." It expands the 64-byte CSIDH shared secret via `SHAKE-256` into a 64-byte dual seed `(d || z)`. Following the deterministic key generation guidelines set out in section 7.1 of the NIST standard, both endpoints locally construct a synchronized instance of the **ML-KEM-512 State Engine** without ever broadcasting lattice vectors over the air.
*   **References:**
    *   [NIST FIPS 203 Standard Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

### 2.3 Symmetric Signature & AEAD Layer: AES-256-GCM
*   **Mathematical Concept:** Galois/Counter Mode authenticated block cipher processing with a 256-bit symmetric key.
*   **Payload Footprint:** 12-byte IV/Nonce, 16-byte Integrity/Auth Tag (GMAC).
*   **Design Rationale:** Traditional PQC digital signatures—such as **ML-DSA (FIPS 204)** or **Falcon-512**—exhibit footprints too vast for clean, background-compatible single-packet BLE messaging (~500B to 2.4KB). Furthermore, Falcon relies on floating-point arithmetic that risks thread locks on legacy processors. This protocol eliminates live asymmetric signing. By assuming an initial, out-of-band identity pairing phase (e.g., swapping a static NetKey via physical contact or QR code), **AES-256-GMAC serves as the live digital signer**, providing implicit validation via a 16-byte tag.
*   **Quantum Safety Boundary:** While quantum computing speeds up brute force searches via Grover's Algorithm, it only halves the bit security of symmetric systems. An active 256-bit space maps down to an effective 128 bits of security, which is recognized globally as fully quantum-safe.
*   **References:**
    *   [NIST Special Publication 800-38D (GCM/GMAC)](https://csrc.nist.gov/pubs/sp/800/38/d/final)

---

## 3. Evaluated & Rejected Primitives

During the architectural engineering phase, several high-performing PQC options were discarded to support legacy smartphone back-ends:

1.  **HAWK-512 (Digital Signature):** 
    *   *Why considered:* An integer-only signature primitive based on the Lattice Isomorphism Problem (LIP) featuring small signatures (555 bytes) without floating-point bottlenecks.
    *   *Why rejected:* Even at 555 bytes, appending this to an asymmetric KEM packet pushes the composite frame past the 244-byte non-fragmentation ATT boundary, breaking background BLE execution stability on legacy Android engines.
    *   *Source:* [HAWK Reference Submission Package](https://github.com/hawk-sign/dev)
2.  **Falcon-512 (Digital Signature):**
    *   *Why rejected:* Requires fast Fourier sampling over NTRU lattices. The execution relies heavily on double-precision floating-point arithmetic which triggers significant background OS scheduling overhead and execution stalls on older Cortex-A series chipsets.
    *   *Source:* [NIST FIPS 205 / Falcon Project Architecture](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## 4. Key Takeaways for Implementing AI Agents
When parsing the accompanying `hybrid_pqc_ble_mesh_spec.md` for generation, the following operational bounds are mandatory:
*   Never split an isogeny array across separate BLE transmission loops. If a payload exceeds 1 packet, your transport wrapper is broken.
*   Ensure the `SHAKE-256` digest is precisely sliced: the first 32 bytes mapped as Seed `d` and the following 32 bytes mapped as Seed `z` when calling the native internal `ML-KEM.KeyGen` routine.
*   All low-level math tasks (both field arithmetic in CSIDH and matrix multiplication in ML-KEM) must be explicitly bound to **constant-time execution paths** to mitigate side-channel timing exploits.