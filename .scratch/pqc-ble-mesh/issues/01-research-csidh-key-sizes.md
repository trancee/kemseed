# Research: Verify CSIDH-512 64-byte public/ciphertext key sizes and point encoding

Status: resolved
Type: research
Blocked by: (none)

## Question

`PROMPT.md` claims CSIDH-512 yields a 64-byte public key and a 64-byte ciphertext, leading to:

- Packet A = `Session_ID(1) || pk_client(64)` = **65 bytes** (1 BLE packet)
- Packet B = `Session_ID(1) || ciphertext(64) || AuthTag(16)` = **81 bytes** (1 BLE packet)

CSIDH operates on supersingular elliptic curves over a prime field F_p. A public key is a curve (a class representative), typically encoded as a single field element (e.g., a compressed j-invariant or point) — commonly **32 bytes** for ~256-bit fields, not 64.

Question: What are the actual serialized sizes of a CSIDH-512 public key and ciphertext under standard encodings (e.g., the ePrint reference implementation, or the variants referenced in `PROMPT.md`: `ioerror/csidh-reference-implementation`, `amirjalali65/ARMv8-CSIDH`, `splight793/AVX-CSIDH`)? Is 64 bytes achievable — e.g., because "512" denotes a ~512-bit prime giving 64-byte field elements? If 64 bytes does **not** hold, how does that change the packet framing and the 244-byte non-fragmentation budget?

Sources: the CSIDH ePrint paper (18/383), the listed reference implementations' READMEs/code, and any standard "CSIDH-512" parameter-set documentation.

## Answer

**Resolving: CSIDH-512 public/ciphertext key sizes are 64 bytes — PROMPT.md is size-correct, with a quantum-security caveat.**

- CSIDH-512 (512-bit prime field) encodes the public key as a single field element A ∈ F_p → **64 bytes**. ECRYPT IACR ePrint 2023/793 ("Optimizations and Practicality of High-Security CSIDH") states explicitly: "CSIDH-512… needs to transmit only 64 bytes each way, more than 10 times less than Kyber-512"; the CSIDH primer corroborates 64 bytes at 128-bit classical equivalence. **The framing holds: Packet A = 65 B, Packet B = 81 B — both far within the 244-byte non-fragmentation budget.**
- **Caveat — security level:** Bonnetain & Schrottenloher ("Quantum Security Analysis of CSIDH") show CSIDH-512 delivers only ~64 bits of **quantum** security (≈235 quantum queries), not the 128-bit quantum security implied by "quantum-safe." Reaching AES-128 / 128-bit-quantum equivalence under their analysis requires a 1024-bit prime field → **128-byte** keys/ciphertexts — still unfragmented (≤244 B) but a meaningful security-level tradeoff that #05 must resolve.
- Eprint 2023/793 additionally notes CSIDH is "unlikely to be practical in real-world applications, outside of those that specifically require NIKEs" at the larger parameters.

Sources:
- ECRYPT IACR ePrint 2023/793 (https://eprint.iacr.org/2023/793): CSIDH-512 = 64 B each way; AES-128 classical target; CTIDH constant-time ~2x speedup.
- "CSIDH Explained" / csidh.isogeny.org: 64-byte public key at 128-bit classical security.
- Bonnetain & Schrottenloher, "Quantum Security Analysis of CSIDH" (https://who.rocq.inria.fr/Xavier.Bonnetain/pdfs/csidh-attack.pdf): CSIDH-512 ≈ 64-bit quantum security; 1024-bit/128 B for 128-bit quantum.

