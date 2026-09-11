package ch.trancee.kemseed

/**
 * Public entry point for the `kemseed` library — a zero-dependency Kotlin Multiplatform
 * implementation of the symmetric-seed → ML-KEM-512 → AES-256-GCM protocol over BLE mesh
 * (docs/adr/0001-stack-and-dependency-constraints.md).
 *
 * Architecture: a small airborne seed/nonce (≤60 B, inside the ATT_MTU-247 non-fragmentation
 * budget; see #14) is verified by the DoS gate (AES-256-GMAC-before-Decaps, #15) and feeds a
 * *local* FIPS 203 ML-KEM-512 state engine — `ML-KEM.KeyGen(SHAKE-256(K_seed, 64))`, shared by
 * both peers (#02). The ML-KEM-derived secret `K_df` (via deterministic self-encaps, soundness
 * reviewed in #13) and `K_seed` are combined with the running transcript into the AES-256-GCM
 * session key (#07). CSIDH-over-air was ruled infeasible in Pure-Kotlin (#10) and is not on
 * the hot path; `K_seed` is sourced from the #11-approved airborne KEM (crypto-expert-gated,
 * handoff packet #18).
 *
 * Module: `kemseed` (package `ch.trancee.kemseed`). Targets: Android + iOS devices only
 * (KMP); ML-KEM is Pure-Kotlin; AES-GCM is wired via `expect/actual` against Android Keystore /
 * CryptoKit; the AES-256-GMAC signer key lives in Android Keystore / iOS Keychain
 * `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (#17).
 *
 * Implementation backlog (see `.scratch/pqc-ble-mesh/issues/`):
 * - #11 / #13 crypto-design review (airborne-KEM → K_seed binding; deterministic ML-KEM
 *   self-encapsulation as KDF) — crypto-expert-gated; handoff packet #18,
 * - #15 DoS pre-validation (GMAC-before-Decaps) — resolved, gate <100 µs,
 * - #16 iOS background peripheral (relay-over-live-links only) — resolved,
 * - #17 OOB at-rest provisioning (signer-key storage + atomic rotation) — resolved,
 * - #12 OOB identity-key provisioning mechanism (QR / NFC-tag / NetKey) — HITL human.
 */
public object KemSeed {

    public const val PROTOCOL_NAME: String = "hybrid-pqc-ble-mesh"
    public const val PROTOCOL_VERSION: Int = 1
}

/** Protocol phases described in `PROMPT.md` / `.scratch/pqc-ble-mesh/issues/08-prototype-spec-outline.md`:
 *  A (provisioning) -> B (airborne seed/nonce + DoS gate -> local ML-KEM KeyGen) ->
 *  C (ML-KEM engine + deterministic self-encap -> K_df -> HKDF session key) ->
 *  D (AES-256-GCM authenticated sessions). */
public enum class ProtocolPhase {

    PROVISIONING,
    KEY_EXCHANGE,
    KEY_DERIVATION,
    SESSION,
}
