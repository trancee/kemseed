# Research: BLE mesh transport — p2p GATT vs SIG Bluetooth Mesh routing model

Status: open
Type: research (AFK)
Wayfinder: child of map (`map.md`); claims the "How the mesh actually routes between peer phones" fog item.

## Question

The destination spec (`hybrid_pqc_ble_mesh_spec.md`) assumes a **connection-oriented GATT handshake** ("peer-to-peer GATT connections, not SIG mesh; 'mesh' semantics undefined") but also advertises **mesh relay** (phones forwarding traffic). These are in tension:

- **p2p GATT**: a phone is *central* to one *peripheral* at a time (1:1 connection, ATT_MTU 247, connection events scheduled by the central). A phone can be central to several peripherals concurrently (Android: 6-7 connections in practice; iOS: limited background connections), relaying by reading/writing each GATT link — but there is no native multi-hop.
- **SIG Bluetooth Mesh**: a managed-flood mesh (relay nodes, friend, proxy) with its own bearer (advertising or GATT), connectionless, but with heavy overhead (TTL, relay, friend polling, 30-60 s background task limits on iOS) and iOS **does not support Bluetooth Mesh peripheral/central roles in the background** (no background `CBPeripheralManager`/`CBCentral` mesh advertising except via the `bluetooth-central`/`bluetooth-peripheral` background modes with connection-oriented constraints).

What is the **actual intended routing topology** for peer phones in this design? Pick one model and state, precisely:
1. **p2p GATT multi-connection (connection-graph):** each phone is central to N peers' GATT links; "mesh" = application-layer forwarding (phone A reads a characteristic from B and writes it to C). Bounded by per-platform concurrent-connection limits; each hop = one additional connection interval (7.5–30 ms min).
2. **SIG Bluetooth Mesh bearer:** connectionless managed-flood; iOS background support is **not available** for mesh roles → infeasible on iOS in the background.

Constraint surface that gates the routing decision:
- **iOS background:** `bluetooth-central` / `bluetooth-peripheral` background modes allow **connected** (GATT) events in the background, **not** background advertising-based mesh relay. 30 s background-task budget for long operations.
- **Android background (API 36):** `NEARBY_DEVICES` permission (replaces location for BLE 12+); foreground service (`connectedDevice`/`CompanionDeviceService`) with a persistent notification required for sustained relay; background advertising capped.
- **Non-fragmentation budget:** Packet A ≈ 65 B, Packet B ≈ 81 B must fit a single ATT_MTU (247) — satisfied under p2p GATT with `requestMtu(247)`. Under SIG mesh the bearer overhead differs (Advertising bearer ~95 payload; GATT bearer ~512).
- **Reliability:** BLE writes are not guaranteed delivery (Write Without Response = no ACK). Mesh forwarding must account for loss/retransmit per hop; multihop multiplies loss.

### Resolution (answer lives here, on closure)

**Decision: the mesh is a p2p GATT *connection-graph* relay (model 1). SIG Bluetooth Mesh (model 2) is INFEASIBLE on the target platforms.**

#### Why SIG Bluetooth Mesh is ruled out
- SIG Bluetooth Mesh is a **connectionless managed-flood** over the BLE *advertising/scanning* bearer only (no GATT) [novelbits "Bluetooth Mesh Networking… Ultimate Guide"]; its proxy nodes use the GATT bearer, but the relay/friend roles never connect [CitrusDev "Bluetooth Mesh in Mobile Devices (2025)"].
- **iOS has no native Bluetooth-mesh support; iOS devices act only as proxy clients, not full mesh nodes** [CitrusDev]. No relaying role is reachable from any iOS API.
- **Android phones cannot act as full mesh nodes or relays — they operate as proxy clients only** [CitrusDev].
- Therefore a *connectionless flood mesh between peer phones* is impossible on both mobile OSes. The "mesh" semantics in the destination cannot be SIG mesh.

#### What is actually supported → the adopted model
- **p2p GATT multi-connection, central-to-N-peripherals.** A phone in the central GAP role holds GATT links to several peripherals [novelbits "Hitchhiker's Guide to BLE"; TI E2E "BLE with multiple connections" — iOS confirmed connecting to 5 peripherals concurrently; spec allows 231, vendors cap ~5–10]. The central decides connection parameters (interval, latency, channel map) [novelbits "ATT and GATT Explained"].
- **"Mesh relay = application-layer forwarding."** Phone A (central) reads/notifies a characteristic from peripheral B and writes it to peripheral C. There is **no native multi-hop** in BLE; hops are app-layer, each costing ≥1 connection interval + ATT RTT.
- **Link budget is safe:** ATT_MTU negotiated to **247** (`requestMtu(247)`); Packet_A (≈65 B) and Packet_B (≈81 B) fit in a single L2CAP/ATT frame with large headroom — no fragmentation, consistent with the zero-fragmentation budget.
- **Reliability is NOT free:** BLE offers *Write Without Response* (no ACK, fire-and-forget) and *Write With Response* (ACK). Because loss compounds per hop, **relay writes MUST use Write With Response + app-layer seqno + retransmit window**; Write-Without-Response is only acceptable for loss-tolerant telemetry. Effective per-link throughput ≈ 100–250 kbps (CoreBluetooth observed ceiling), lower under background throttling.

#### Platform constraints (gates the adopted topology; detail resolved in #16)
- **iOS background:** `UIBackgroundModes` = `bluetooth-central` + `bluetooth-peripheral`. A backgrounded iOS app can **maintain existing GATT connections** and is woken by the system for BT events, but **new-peer discovery/scan while backgrounded is throttled** (connection intervals stretch to ≥~100 ms; ~30 s `BGTask`/`beginBackgroundTask` budget). iOS 26 *Live Activity* re-enables unrestricted background scanning, but only behind an on-screen Live Activity (opt-in, rare). Net: an iOS phone **cannot bootstrap new relay links in the background** — mesh formation must happen in the foreground. An iOS node stays useful as a relay only over *already-established* GATT links.
- **Android (API 36 / Android 15):** scan needs `NEARBY_DEVICES` (replaces location for BLE 12+) and `BLUETOOTH_SCAN`/`BLUETOOTH_ADVERTISE`/`BLUETOOTH_CONNECT`/`BLUETOOTH_BACKGROUND`; sustained background relay **requires a `connectedDevice` foreground service + persistent notification** [argenox "Android 15 BLE"]; bare background services are killed within minutes [StackOverflow b4x SDK36: scan stops after 5–15 min]. Scan cadence self-limits (5 scans / 30 s).

#### Spec-level consequences
1. **Routing abstraction:** *bounded connection graph.* Each node holds GATT links to ≤~5 immediate neighbours (degree ≤5 to stay under iOS/Android concurrency + scheduling limits); "mesh forward" = a node re-advertising a queued payload to each *other* neighbour it already holds a link to. Diameter ≤ small constant (≈5–8). This matches the destination spec's "peer-to-peer GATT connections, not SIG mesh" framing and removes the undefined routing semantics.
2. **Bootstrap is foreground-gated:** connection + primary-service/characteristic discovery must complete before handoff to background; background only *maintains & forwards over* live links.
3. **Per-hop latency floor = 1 connection interval** (7.5 ms foreground-min / 30 ms foreground-sustainable / ≥100 ms background-throttled) + ATT RTT; end-to-end = Σ per-hop, so keep diameter small.
4. **Transport reliability = application-layer:** seqno + ACK + retransmit per forwarded record; never assume in-order or delivery across a hop.
5. **MTU = 247** at every link; packets ≤240 B (headroom). Packet_A/Packet_B fit single-frame.

### Decision status: ACCEPTED (model 1). #16 (iOS background relay) inherits the iOS detail. #15 (DoS gate) inherits the connection-interval latency budget.
