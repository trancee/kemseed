# Grill: Confirm session-layer authentication model

Status: resolved
Claimed by: work-through session (agent)
Type: grilling
Blocked by: (none)

## Question

The protocol authenticates the handshake with AES-256-GMAC over `(Session_ID || ciphertext)` using a long-term identity key pre-shared out-of-band, and omits live asymmetric signing (Falcon/ML-DSA were rejected). The Threat Model §Repudiation explicitly accepts that "technical non-repudiation is not achieved at the session layer."

Decision required:
1. Is symmetric-only authentication (GMAC-as-signer) acceptable for this deployment, given the explicit non-repudiation tradeoff? Or must there be a (smaller) asymmetric attestation at enrollment / first contact?
2. How is the long-term identity key provisioned, stored, and rotated? The out-of-band provisioning mechanism (QR code / physical contact / NetKey) is unspecified.
3. Does GMAC over `(Session_ID || ciphertext)` genuinely bind the peer's identity and defeat the key-replacement attack under §Tampering — or is additional binding (e.g., over the CSIDH shared secret `K_seed`) required?

## Answer

**Decision (work-through session, 2026-09-10): Session-layer authentication model CONFIRMED as symmetric-only.**

- **Q1 (symmetric-only vs asymmetric):** **Confirmed — symmetric-only.** PROMPT.md §2.3 ("AES-256-GMAC serves as the live digital signer") and §Threat/"Repudiation" ("technical non-repudiation is not achieved at the session layer") explicitly reject live asymmetric signing. ADR-0001 reinforces this: Pure-Kotlin KMP (zero external deps, no native Falcon/ML-DSA primitives) makes symmetric-only the only spec-compliant path. The non-repudiation gap is accepted as a documented risk — to appear in the spec's threat model, with optional immutable enrollment-time evidence per §Repudiation.
- **Q3 (GMAC key-replacement binding):** **Deferred to crypto-expert review → #11.** Whether `GMAC(Session_ID || ciphertext)` rejects a modified in-transit CSIDH public key (key-replacement) is a correctness question; the non-standard "CSIDH-as-KEM" framing (#04: CSIDH is a NIKE) must also be validated. Requires S6/S7 expert review + conformance reasoning — **not self-resolved.**
- **Q2 (OOB provisioning mechanism):** **Spun out as a separate grilling ticket → #12.** "Confirm the auth model" = "symmetric-only GMAC-as-signer." *Which* OOB provisioning channel (QR / physical tap / NetKey) is a deployment-UX decision, not part of the auth-model definition — scoped out and tracked in #12.

Net: #06 is closed. The auth model is symmetric-only GMAC-as-signer with accepted non-repudiation risk; the two remaining engineering questions are now separate tracked tickets (#11 binding-correctness, #12 provisioning). #08's auth section is specified; #11/#12 fill the gaps later.

Sources:
- PROMPT.md §2.3 (AES-256-GMAC as signer), §Threat/"Repudiation" (non-repudiation not achieved).
- ADR-0001 (Pure-Kotlin KMP; zero external deps; no native asymmetric primitives).
- #04 (CSIDH is a NIKE, not a KEM — surfaces the Q3 correctness risk).

