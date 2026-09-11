# Research: Verify BLE background ATT_MTU=247 + GATT notification reliability on iOS/Android

Status: resolved
Type: research
Blocked by: (none)

## Question

The protocol's core premise is a single-packet, zero-fragmentation exchange over BLE with `ATT_MTU = 247` (effective payload 244 bytes), operating in the mobile background on iOS and Android — including **legacy Android stacks** that `PROMPT.md` says fragment/deadlock under multi-packet GATT. It assumes a 65-byte Write-Without-Response (Packet A) and an 81-byte Notification (Packet B) both fit in a single LL_DATA PDU and are reliable.

Question:
1. **iOS** background peripheral/central role: is `ATT_MU=247` negotiable and honoured for background GATT writes and notifications? Are there documented drops in background execution (e.g., 30 s background tasks, connection-interval floors, iOS 13+ CB restrictions)?
2. **Android**, especially legacy/OEM-fragmented stacks: is `ATT_MTU=247` (247-byte Link-Layer PDU) supported in the background? Are GATT notifications reliable, or do legacy Android stacks still fragment/deadlock on multi-packet sequences?
3. Is a 65/81-byte single Write-Without-Response / Notification genuinely delivered as a single LL_DATA PDU? What are the real constraints of the 251-byte max BLE 5 LL PDU (LLID, MIC, LL Control overhead) — i.e., is 244 bytes truly usable, or does L2CAP/ATT framing eat into it?

Sources: Apple CoreBluetooth docs (background BT), Android `BluetoothLeGatt`/`BluetoothLeAdvertiser` docs, Bluetooth 5.x Core Spec (LL_DATA PDU max 251 bytes), and known legacy-Android background BLE limitations.

## Answer

**Resolving: zero-fragmentation holds on iOS & Android, but the 244-byte ceiling is Android-only; Packet A/B (65/81 B) fit even at iOS's capped 182 B. `requestMtu(247)` is required on Android; reliability (not size) is the real risk.**

- BLE ATT_MTU: default 23 B; negotiable via Exchange MTU. "Most stacks cap ATT_MTU at 247… 247 fits cleanly inside a DLE-extended link-layer PDU of 251 bytes" (Hubble, "BLE MTU Negotiation Explained"). At 247 → 244 B usable payload. **This confirms the 244-byte figure — but only where negotiated.**
- **Gotcha 3 — iOS caps:** "iOS negotiates MTU automatically shortly after connection. Recent iOS versions land at 185 bytes (so 182 bytes of payload). You can't force it higher." So on iOS the max payload is **182 B, not 244**. **However**, Packet A (65 B) and Packet B (81 B) are both ≤ 182 → **zero fragmentation still holds even at iOS's capped MTU.**
- **Gotcha 4 — Android requires an explicit request:** Android does **not** auto-negotiate; the app must call `BluetoothGatt.requestMtu(247)` after `onServicesDiscovered()` (supports up to 517). **Critical:** at the legacy default ATT_MTU=23, usable payload = 20 B, so Packet B (81 B) *would* fragment into 4 packets. Therefore `requestMtu(247)` (or a high value) is **mandatory**, even though 65/81 B are small relative to 244.
- **Reliability (the real risk):** Write-Without-Response (Packet A) is unacknowledged and Android can silently drop `writeWithoutResponse` calls (capacitor-community/bluetooth-le discussion #751). Mitigations: pace via `peripheralIsReady(toSentWriteWithoutResponse:)` (iOS) / connection-interval timers; consider Write-with-Response for the handshake; gate on `att_mtu_updated`; verify with an nRF Sniffer (stack callbacks lie). iOS background execution limits (≈30 s background tasks, connection-interval floors) also threaten persistent mesh relay.
- **LL PDU:** 247 ATT_MTU ↔ 251-byte Link-Layer Data PDU (Bluetooth 5 DLE). Confirmed.

Sources:
- Hubble, "BLE MTU Negotiation Explained" (https://hubble.com/community/guides/ble-mtu-negotiation-explained-how-to-send-more-data-per-packet): ATT/L2CAP/LL-PDU definitions, 247 cap, 251-byte LL PDU, iOS cap=185/182, Android requestMtu(247), timing gotchas, sniffer verification.
- Punchthrough, "Android BLE Guide" & "BLE Write Requests Vs Write Commands": write-without-response reliability drops + pacing.

