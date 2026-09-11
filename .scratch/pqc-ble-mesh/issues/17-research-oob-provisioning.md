# Research: OOB identity-key provisioning mechanisms — feasibility, native-keystore fit, and security bounds

Status: open
Type: research (AFK)
Wayfinder: informs #12 (grilling — the human "choose mechanism" decision); feeds #08 (enrollment flow) + #06 (auth model: symmetric-only AES-256-GMAC signer).

## Context

PROMPT §2.3 sketches three out-of-band provisioning mechanisms for the long-term **AES-256-GMAC identity key**, but does not choose one. ADR-0001 constrains the implementation to KMP + zero external deps, preferring **native-keystore** primitives (`expect/actual`) for the key at rest:

- **iOS:** CryptoKit `SymmetricKey` backed by the Keychain (hardware UID-derived file protection). *Note:* Secure Enclave backs **asymmetric** keys only (PINE/P256.Signing.PrivateKey etc.); a symmetric AES key lives in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, class `A`/`B`/`C`), protected by the device's hardware UID class key — not by the Secure Enclave itself.
- **Android:** `AndroidKeyStore` AES, optionally `StrongBox` TEE; can be bound to lock-screen auth or `setUnlockedDeviceRequired`.

The question is **feasibility + constraints** for each candidate, AFK from primary sources — to give the human a crisp #12 decision basis.

## Question (for resolution here)

1. **QR-code enrollment (HomeKit-style, one-shot):** What is the maximum QR payload that must be encoded, and does it fit a scannable QR (≤ 64–128 B practical)? How is the 256-bit AES identity key provisioned *into the keystore* from a scanned value on iOS (Keychain `SecKeyAdd`) and Android (Keystore `setKeyEntry`/`KeyGenerator`)? What native framework(s) exist for camera/QR (iOS `AVCaptureMetadataOutput` / `CameraController`; Android `CameraX` QR; or Apple/Google Vision)? What is the **security bound** (QR image at rest in photos/camera-roll = exfil risk; recommend single-use + screen-off + immediate deletion)?
2. **Physical contact / tap:** Can a peer phone's NFC *tag* carry the 32-byte AES key via NDEF (record limit / practical NDEF size)? iOS capability: `CoreNFC` `NFCNDEFReaderSession` reads NDEF tags (iOS 13+); **writer session is restricted** (NFCWriterSession exists on macOS Catalyst but iOS peer-to-peer NDEF *push* was removed in iOS 13) → iOS can **read a tag** but not **write/push to another phone** via NFC. Android: `NfcA` + NDEF read/write via foreground dispatch. Net: **NFC is tag-mediated, not phone-to-phone on iOS.** The "BLE provisioning handshake" variant is *not* truly OOB (same channel); if used it needs a short confirmation (e.g. 6-digit numeric comparison = BLE Just-Works pairing auth). What are the NFC-NDEF size + read/write asymmetries per platform?
3. **Pre-shared NetKey (fleet provisioning):** How is a fleet secret delivered to/burned into devices pre-deployment? iOS: Apple Business Manager / DeviceCheck / AppConfig; Android: Android Enterprise / Device Policy Controller / `DevicePolicyManager`. What are the key-rotation mechanics (MDM/OTA-signed push) and the blast radius if the NetKey leaks?
4. **Storage & rotation at rest (both platforms):** Confirm the AES-256-GMAC key is **symmetric** (so Secure Enclave SE-backending is **not** available on iOS — key goes to Keychain) and that Android can reach **StrongBox TEE** for AES. How does **rotation** work given the key is pre-shared OOB: re-provision via the same OOB channel, or fleet-managed push? What is the per-platform ceiling on symmetric-key count per app (to bound rotation history)?
5. **Constraint tie-back to #15 DoS gate:** the AES-256-GMAC pre-Decaps gate (#15 §2c) reuses the long-term identity key — confirm provisioning/rotation of that key is consistent (rotation invalidates both the signer and the gate key atomically; single key, rotated OOB).

### Resolution (answer lives here, on closure)

**Decision: all three mechanisms are *feasible*; they have sharply different platform parity. NFC tap is iOS-degraded (read-only tag-mediated), QR and NetKey are cross-platform. The *choice* stays HITL in #12; this ticket supplies the feasibility envelope. Key at-rest finding: the AES-256-GMAC signer key (per #06) must live in the **iOS Keychain** (Secure Enclave is asymmetric-only) with `AfterFirstUnlockThisDeviceOnly` so the #15 pre-Decaps GMAC gate works in the background.**

| Candidate | On-air / channel size | iOS feasible? | Android feasible? | Gate/rotation note |
|---|---|---|---|---|
| **QR-code enrollment** | 32 B key → 43-char base64url → QR v1 (21×21) | ✅ `AVCaptureMetadataOutput`/`CameraController` | ✅ `CameraX` QR analyzer | Foreground UX; photo-exfil risk ⇒ single-shot display + teardown |
| **NFC / physical tap** | 32 B key → single NDEF short record (payload cap 255 B short / 4 GiB long; 32 B ≪ cap) [USPTO NDEF §4.3] | ⚠️ **read-only tag only** | ✅ read+write `NfcA`/`NfcAdapter` + foreground dispatch | iOS cannot write/p2p ⇒ intermediary *tag* required, not phone-to-phone |
| **Pre-shared NetKey (fleet)** | 0 B (pre-burned) | ✅ AppConfig / Apple Bus Mgr / DeviceCheck | ✅ Android Enterprise DPC + Managed Configs | Fleet-wide blast radius if leaked ⇒ MDM/OTA-signed rotation |

Source for the NDEF sizing: USPTO NDEF spec §4.3 ("maximum size of the PAYLOAD field is 2^32-1 octets in the normal record layout and 255 octets in the short record layout"); a 32-byte AES key is a single short record — fits every Type-1/2/5 tag with margin (e.g. NTAG213 ≈ 144 B NDEF area).

#### 1. QR-code enrollment — feasible, cross-platform
- **Payload:** 32-byte AES-256 identity key in `base64url` = **43 chars** → QR **version 1** (21×21 modules), scannable by any phone camera at a few cm. Fits well under the 244 B zero-fragmentation budget *as provisioning metadata* (one BLE packet if needed).
- **Storage:** iOS — `CryptoKit.SecureEnclave.P256…` NO (asymmetric); the symmetric key is generated (`SecKeyCreateRandom` or `CryptoKit SymmetricKey(size:.bits256)`) then stored via `SecItemAdd` as a `kSecClassGenericPassword` item [Apple "Storing CryptoKit Keys in the Keychain"]; Android — `AndroidKeyStore` `KeyGenerator` with `KeyGenParameterSpec` [Android Enterprise Security Paper: "MasterKeys allows developers to create a safe AES 256 GCM key"].
- **Security bound:** the QR encodes a **secret at rest** in an image → a photo in Camera Roll / screenshot leaks it. Mitigation: render the QR **once, full-screen, then tear down the UI + advise the user to discard**; never persist the QR. Rotation = `SecItemDelete`+`SecItemAdd` (iOS) / `KeyStore.deleteEntry` (Android) — atomic by delete-then-add.

#### 2. Physical-contact / NFC tap — Android yes, iOS degraded to tag-mediated read
- **iOS:** `CoreNFC` exposes only `NFCNDEFReaderSession` — **read-only** NDEF from NFC Forum **tags** (Type 1–5) [Apple "Building an NFC Tag-Reader App"; PunchThrough "CoreNFC missing link"]; writer sessions exist **only on macOS Catalyst, not iOS**. Requires entitlement `com.apple.developer.nfc.readersession.formats`=`NDEF` + `NSNFCReadUsageDescription`. Reader session is **modal, 60-second time limit**, single active session, `invalidateAfterFirstRead` available. **Peer-to-peer NDEF push was removed in iOS 13** — a phone can neither write a tag nor push to another phone. → "tap your two phones together" is **impossible on iOS**; only phone↔NDEF-tag works, and iOS cannot author the tag.
- **Android:** `NfcA` + `NfcAdapter` + foreground-dispatch supports **full read AND write** of NDEF; Android Enterprise even lists **NFC provisioning tag** as a supported provisioning method [Android Enterprise / jasonbayton 11ty: NFC is a documented provisioning vector for DPC bootstrap]. → phone-to-phone tap is replaced by (a) an Android-written tag read by the other phone, or (b) an Android Enterprise pre-burned tag.
- **Conclusion:** NFC tap is a viable OOB channel **only as tag-mediated** (a write-once manufacturer tag, or an Android-provisioned tag). If the product requires friction-free *phone-to-phone* tap, **NFC is ruled out on iOS** — QR or NetKey must carry the key on iOS.

#### 3. Pre-shared NetKey (fleet)
- Android: full **Android Enterprise** DPC path (zero-touch / QR / NFC provisioning tables) [Android Developers "Build a DPC"; jasonbayton 11ty provisioning matrix]; fleet AES keys managed by the EMM/DPC with OTA-signed rotation.
- iOS: **Apple Business Manager** + **DeviceCheck** / **AppConfig** for pre-burned fleet secrets [Android Enterprise AE Security Paper for the parallel enterprise model]; no iOS equivalent of Android NFC provisioning tags.
- **Blast radius:** a compromised NetKey = **whole fleet**; rotation must be fleet-wide (MDM/OTA-signed). Mitigation: NetKey is *only* for bootstrap/rotation channel; per-peer identity keys are still individually derived thereafter.

#### 4. Native-keystore storage & rotation (the at-rest gate)
- **iOS — the AES-256-GMAC signer key is NOT Secure-Enclave-backed.** Secure Enclave supports **asymmetric (P-256/P-384) keys only** ("Cannot store an AES-256 key directly in the Secure Enclave; CryptoKit Secure Enclave isn't general-purpose symmetric-key" — Swift Forums); envelope schemes wrap an AES key with an SE P-256 pair and keep the AES key in the Keychain [KSafe CHANGELOG]. → the **symmetric identity signer key lives in the Keychain** (`kSecClassGenericPassword`), accessible via `SymmetricKey`↔`SecKeyConvertible`.
- **Background-readability is REQUIRED** for the #15 gate (the peripheral must compute a GMAC over incoming Packet_A while backgrounded). Therefore `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is **wrong** (foreground-only); use **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** (device unlocked once since boot ⇒ available to background BLE). [KSafe: "AfterFirstUnlockThisDeviceOnly … enabling background access patterns."] Note this trades some theft-resistance vs `WhenUnlocked`; document as a threat-model line.
- **Android:** `AndroidKeyStore` AES, `setUserAuthenticationRequired(false)` + optionally `setUnlockedDeviceRequired(false)` so the key is usable by the background `connectedDevice` foreground service (#16); `setIsStrongBoxBacked(true)` if a TEE is present [KeyDroid: AES-256 StrongBox generation 71 ms on Pixel 8 — cost is one-time at provisioning]. Symmetric-key count ceiling: Keychain is practically unbounded; AndroidKeystore is bounded by TEE/StrongBox memory — keep only the *current + one rotated-previous* to bound history.
- **Rotation mechanics (single shared signer = gate key, per #15 tie-back):** delete-then-add is *not* atomic across processes — instead rotate to a **temp key ID**, re-encrypt/decommit peers, then swap the active alias. Document the brief no-key window (drop traffic with "unverified" verdict until rotation completes).

#### 5. Tie-back to #15 DoS gate
The AES-256-GMAC pre-Decaps gate (#15 §2c) **reuses the long-term signer key** (single AES-256 key — signer *and* gate). Provisioning therefore **provisions one key for two jobs**; rotation must invalidate both atomically. Confirm in #11 that this dual-use is acceptable (the gate authenticates `version‖nonce‖sender_id‖flags`; the signer authenticates `Session_ID‖ciphertext` — distinct AAD, same key; no cross-use weakness if AAD never collides — flag for expert).

### Decision status: FEASIBILITY envelope closed. Mechanism *choice* (QR / NFC-tag / NetKey, or a combination) → deferred to #12 (HITL). #08 enrollment section inherits §4 (at-rest) + §5 (rotation atomicity) + the iOS `AfterFirstUnlockThisDeviceOnly` background requirement.