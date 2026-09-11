# Research: cheap DoS pre-validation before ML-KEM-512 decapsulation

Status: open
Type: research (AFK)
Wayfinder: child of map (`map.md`); claims the "Cheap session validation before CSIDH decapsulation (DoS)" fog item — re-framed now that CSIDH is dropped and the airborne KEM is **local ML-KEM-512** (per ADR-0001 the 761 B ciphertext is *not* sent over the air; only a small seed/nonce is).

## Question

A BLE mesh peer receives `Packet_A` (≈65 B over the air under the 247-byte zero-fragmentation budget). The receiver must not perform the expensive decapsulation path on attacker spam. Even though CSIDH is dropped, the airborne element is now a small seed/nonce that *drives* a **local** ML-KEM-512 decapsulation (FIPS 203) — still a multi-hundred-µs to low-ms operation on mobile — followed by AES-256-GCM.

What is the **cheapest sound gate** that rejects malformed/DoS `Packet_A` traffic *before* the ML-KEM decap + AES-GCM, within the BLE connection-event latency budget (one connection interval ≈ 7.5–30 ms on Android/iOS background)?

Specifics to resolve:
1. **ML-KEM-512 decapsulation cost on mobile-class** (target Android arm64 + iOS arm64), in µs–ms (FIPS 203, deterministic KeyGen from `SHAKE-256(K_seed,64)` shared by both peers). Needed to size the DoS budget — if decap is < 100 µs the gate may be optional; if > 1 ms it is mandatory.
2. **Validation layers cheaper than decap**, in ascending cost:
   - (a) wire-format / length / version-byte / reserved-bit sanity (µs, no crypto) — reject garbage.
   - (b) **nonce freshness** cache (per-peer sliding-window or Bloom filter with TTL; reject replayed/duplicate nonces) — O(1) hash lookup, ~tens of ns–µs.
   - (c) **HMAC or GMAC prefix** keyed by a long-term peer key, checked *before* decap — but this needs the peer's long-term key (the AES-256-GMAC signer key from #06) and adds a key lookup. Cost: one AES-GMAC (~µs) or HMAC-SHA3-256 (~µs) — vs ML-KEM decap (ms). Net win iff decap ≳ 10× the HMAC.
3. **Where the gate sits in the state machine:** before `ML-KEM.Decap`, after `ML-KEM.Decap`? If (c) is the gate, the HMAC key = the #06 symmetric signer key (so this ticket depends on #06's auth-model being finalized: signer is AES-256-GMAC; non-repudiation out of scope).
4. **Replay/cache cost bound:** a stateful nonce cache per peer has memory + eviction cost on a backgrounded mobile process; specify the cap (e.g. ≤ N=2^10 recent nonces, 2^12-byte footprint) and eviction (time-based 30 s + LRU).

### Dependencies
- #06 (auth model / signer key) defines the long-term key available for a pre-decap HMAC/GMAC gate.
- #13 (ML-KEM deterministic encap-as-KDF) pins the exact `K_seed` / seed format consumed by `Packet_A`.

### Resolution

**Decision: YES — a pre-decap gate is justified, but at µs-scale (not the seconds-scale CSIDH case). Use a layered gate: format-check → nonce-freshness → AES-256-GMAC (reusing the #06 signer key) BEFORE `ML-KEM.Decaps`. This ticket depends on #06 (signer key) and #13 (seed/nonce format).**

#### 1. ML-KEM-512 decapsulation cost on the target (phone-class ARM)
Authoritative measurements on ARM (phone SoC, GHz, optimized NEON — *not* the µC baseline):
- **Kyber/ML-KEM-512 Decaps on aarch64 (Neoverse‑V2, optimized): ≈ 39 µs** [arxiv 2603.19340 — Cortex‑M0+/RP2040 reference C = 14.53 ms, 170× faster at 1.9× slowdown vs M4; phones are a further ~20–40× faster clock + HW crypto + NEON asm].
- **Modern ARM phone (Cortex‑A7xx / Apple A‑series) optimized PQClean Kyber: ≈ 30–70 µs** [qramm.org "ML-KEM explained"; quantumsecuritydefence.com "ML-KEM Key Sizes" — 1–2 ms only on Cortex‑M4 µC class].
- **Desktop ARM (Apple M‑series / x86): ~30 µs** [itzmeanjan/ml‑kem Google Benchmark: M4‑768 decaps 39.3 µs @ Neoverse‑V2; ML‑KEM‑512 ≈ 30 µs].
- Bottom line: **ML-KEM-512 Decaps on a phone ≈ 30–70 µs** (tens, not hundreds, of µs). The earlier CSIDH baseline was *minutes*; this is **~1000× cheaper** — but still **~50–70× more expensive than a single AES-GMAC/HMAC**.

> Note the airborne packet is **not** a 768 B ML-KEM ciphertext — per ADR-0001 the ciphertext is held locally and only a small seed/nonce is transmitted in Packet_A (≈65 B). So bandwidth is unconstrained; the DoS cost is the **local** decap (~50 µs) *triggered per received Packet_A*. An attacker flooding Packet_A across many peers forces Σ(decaps)/sec.

#### 2. Cheap gates, ascending cost (each ≪ decap)
- **(a) Wire-format / length / version / seed-size sanity:** no crypto, pure byte checks. Class: µs at most, rejects garbage payloads + mis-framed attacks. **Always on, first.**
- **(b) Nonce freshness cache (per peer):** O(1) hash-set / Bloom filter + TTL. Rejects replays/duplicates **before** any crypto. Class: ns → low-µs. **Mandatory** — a replayed seed would otherwise trigger a redundant local decap.
- **(c) AES-256-GMAC over (version ‖ nonce ‖ sender_id ‖ flags)** using the **existing #06 signer key** (KeyGen signer = AES-256-GMAC), verified **before** `ML-KEM.Decaps`. **Cost on phone HW (AES/PMULL): ≈ 0.3–1 µs** [notonbluray "AES-256 Apple Silicon" bulk ~50 GB/s ⇒ ~50 ns/B for 65 B ⇒ sub-µs GHASH+AES block; StackExchange 2018/621 notes software GMAC is slow/full of timing holes — but modern phones expose HW AES, making GMAC HW-constant-time]. **vs Decaps ≈ 30–70 µs ⇒ ~50–70× cheaper to reject.** Reuses the signer key ⇒ no second key-management surface. Fallback if HW AES absent: HMAC-SHA3-256 (~1 µs, still ≪ decap; CryptoKit HMAC natively available).

#### 3. State-machine placement
Gate ordering in the receive path: **(a) format/length → (b) nonce cache → (c) AES-256-GMAC verify → `ML-KEM.Decaps` → `AES-256-GCM(session)`**. The GMAC gate is *fail-closed*: any verify failure → drop+peer-score, never reach Decaps.

#### 4. Replay-cache sizing (per peer)
- Window: **sliding window of recent nonces or a 128-byte Bloom filter** keyed per peer; cap **2^10 entries** (~2^10·8 B ≈ 8 KB worst case, trivially small for ≤~6 peers).
- TTL: **30 s** (matches the iOS `BGTask` window and keeps memory bounded); eviction = time-based + LRU.
- Rationale: a mesh node processes at most ~1 Packet_A per connection interval per neighbour; 2^10 nonces / 7.5 ms ≈ far above line rate, so false-reject is ≈0 and memory is bounded.

#### 5. Cost summary vs budget
- One connection interval budget (background, throttled): ~100 ms. Decaps (~50 µs) + GMAC (~0.5 µs) is <0.1% of it — so a *single* legitimate Packet_A is cheap; the gate targets **sustained spam throughput** (thousands/sec), where the 50–70× per-packet rejection wins. The gate is **defense-in-depth**, not a single-point fix; pair with per-peer rate-limiting at (a).

### Decision status: ACCEPTED — implement format-check + nonce cache + AES-256-GMAC(gate before Decaps); depends on #06 signer key + #13 seed/nonce format.
