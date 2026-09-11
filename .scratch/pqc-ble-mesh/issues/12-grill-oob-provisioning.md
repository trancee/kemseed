# Grill: Choose OOB identity-key provisioning mechanism

Status: resolved
Type: grilling
Blocked by: 06 → resolved (auth model #06 confirmed: symmetric-only GMAC-as-signer)

## Question

PROMPT.md §2.3 sketches three out-of-band provisioning mechanisms for the long-term
AES-256-GMAC identity key but does not choose one:

1. **QR-code enrollment** — scan once (HomeKit-style). One-time, fully out-of-band, auditable;
   needs a camera/QR reader on the enrollee.
2. **Physical contact / tap** — NFC tap or a BLE provisioning handshake. No camera; needs
   physical proximity; strong for mesh bootstrap.
3. **Pre-shared NetKey** — fleet/pre-provisioned; no out-of-band channel at enrollment; scales
   to fleets but requires a pre-distribution step.

Decision required: which OOB provisioning mechanism (or combination) does the deployment need?
This gates the enrollment UX and the long-term-key storage/rotation policy, and must be fixed
before #08 can specify the enrollment flow.

## Feasibility envelope (resolved AFK in `issues/17-research-oob-provisioning.md`)

All three candidates are feasible; the differentiators that drive the #12 choice are platform-parity and at-rest constraints — **do not re-derive these in the grilling; they are decided:**

1. **NFC / physical tap is iOS-degraded:** iOS CoreNFC is **read-only NDEF** (60 s modal session, entitlement `com.apple.developer.nfc.readersession.formats`+`NDEF`; no writer session on iOS; peer-to-peer NDEF push removed iOS 13). Android supports full read+write + Android-Enterprise NFC provisioning tags. → *If the product requires friction-free phone-to-phone tap, NFC is ruled out on iOS; phone↔NFC-tag (write-once manufacturer tag, or Android-provisioned tag) is the only path.* A 32-byte AES key fits any Type-1/2/5 tag (NDEF short-record payload cap = 255 B ≫ 32 B).
2. **QR-code:** cross-platform (32 B key → 43-char base64url → QR version 1); foreground UX; photo-exfil risk ⇒ single-shot display + teardown + no persist.
3. **Pre-shared NetKey (fleet):** enterprise-grade on both (Android Enterprise DPC + Managed Configs; iOS via Apple Business Manager / DeviceCheck / AppConfig). Whole-fleet blast radius if leaked ⇒ MDM/OTA-signed rotation.

### At-rest + rotation (binds #06/#15 — the signer key IS the #15 GMAC gate key)
- **iOS: the AES-256-GMAC signer key is symmetric ⇒ NOT Secure-Enclave-backed** (SE is asymmetric-only). It lives in the **Keychain** with **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** — required because the #15 pre-Decaps GMAC gate must fire in the **background** (`WhenUnlockedThisDeviceOnly` would block background BLE).
- **Android:** `AndroidKeyStore` AES, optional `StrongBox` TEE (one-time ~71 ms generation), `setUnlockedDeviceRequired(false)` so the `connectedDevice` foreground service can use it.
- **Rotation:** delete-then-add must be **atomic** (single key serves as both signer and gate; brief no-key window must drop traffic with an "unverified" verdict). Keep current + one previous to bound history.

### Decision drivers for the #12 picker
- **Pairing topology:** ad-hoc consumer mesh (favor QR or tag-mediated NFC) vs enterprise fleet (favor NetKey).
- **Friction budget:** QR = 1 scan; NFC tap = 1 tap *on Android only*; NetKey = invisible (zero-touch).
- **iOS constraint:** if NFC tap is the desired UX, it is **tag-mediated, not phone-to-phone** on iOS — QR is the friction-free phone-to-phone equivalent.

<!-- Spin-out from #06 (Q2); auth model (Q1) confirmed in #06. Feasibility envelope resolved AFK in #17; mechanism *choice* remains HITL. -->

## Resolution (2026-09-11, human input — grilling ticket closed)

**The library does NOT pick an OOB channel** — enrollment mechanism is a *host-app* responsibility, not a library decision. (`kemseed` is a KMP crypto+transport library per ADR-0001; QR-scan / NFC-reader / NetKey-entry UI/UX belongs to the consuming application.)

Outcome for the spec (#08):
- **Library surface:** expose an injectable provisioning abstraction so the app supplies the channel. Minimal contract:
  `interface OobProvisioner { suspend fun provideSignerKey(): Aes256GmacKey /* 32 B; see #11 §5.1 */ }`
  The single AES-256-GMAC key is **both** the #06 session signer **and** the #15 DoS-gate key (one key, two AAD domains — dual-use confirmed by #17 §5; #11 crypto-expert to finalise CT/binding acceptability of that dual-use).
- **Test hook only:** ship an in-memory `TestOobProvisioner` (deterministic fixture key) for tests — *no* production provisioning UI in the library, per the human direction.
- **At-rest binding unchanged** (#17, mechanism-independent): iOS Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` / Android Keystore AES (+ optional StrongBox); atomic delete-then-add rotation (#17 §5).
- **#08 impact:** §3 Phase A0 enrollment is resolved to "injectable `OobProvisioner` + `TestOobProvisioner`"; §4 explicitly excludes in-library enrollment UI/UX. Transport §1 / DoS §1.6 / platform §1.7 already resolved AFK. The **crypto** `[EXPERT TBD]` placeholders (#11 airborne-KEM binding; #13 deterministic self-encap-as-KDF) are **untouched** by this resolution.

**Decision drivers that would have flipped this:** headless Android devices needing an NFC-tag enrollment path, or a fleet-managed subset — both are app-layer and handled identically via the same `OobProvisioner` injection (the app supplies an NFC- or NetKey-backed provider); the library stays channel-agnostic.

