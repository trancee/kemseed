# Research: iOS background peripheral/central constraints vs persistent-relay assumption

Status: open
Type: research (AFK)
Wayfinder: child of map (`map.md`); claims the "iOS background peripheral-mode constraints" fog item.

## Question

The destination assumes **persistent radio availability for mesh relay** on both platforms. On iOS, background BLE is heavily constrained. Resolve, precisely, what is **actually permitted** for a backgrounded iOS app doing BLE *relay* (forwarding traffic between peer phones), and whether the assumption can hold:

1. **Background modes & entitlements:** which `info.plist` background modes (`bluetooth-central`, `bluetooth-peripheral`, `bluetooth-non-connectable-ambient`) are permitted, and which require which entitlement / runtime permission (`BluetoothManager`/`CBManager` authorization, `Nearby Devices`-equivalent on iOS via the BT permission dialog).
2. **Connected vs non-connected in background:** iOS `CBPeripheralManager` background advertising is **severely limited** (and the "non-connectable ambient" mode is iOS 18+/restricted to specific entitlements). Does a backgrounded iOS phone **continue to relay** (scan + forward / advertise + forward) — or only **maintain existing GATT connections** (central→peripheral links) and act on connection events? The map's "persistent radio" assumption for mesh *relay* (multi-hop forwarding of *new* peers' traffic) may be impossible in the background.
3. **Timing budgets:** the ~30 s background-task budget for long-running work; connection-interval floors (7.5–30 ms for connected, but backgrounded connections throttle to ~100 ms+ intervals and may pause); advertising interval floors (min 152 ms in background for non-connectable).
4. **Apple Silicon / M-series Mac** is not the target; confirm scope is iPhone-only (arm64 iOS device, per ADR-0001 device-only KMP).
5. **Net:** can an iOS phone **relay** (forward) mesh traffic while backgrounded, or must relay be deferred to foreground / a foreground-service proxy? This determines whether the iOS node is a first-class mesh relay or a leaf-only peer.

### Resolution

**Decision: iOS can *maintain & forward over existing GATT links* in the background, but CANNOT *discover new peers or sustain advertiser-based relay* in the background. Mesh bootstrap/relay-link formation must occur in the foreground; background is relay-over-live-links only (with throttling). This matches #14's adopted p2p GATT model.**

#### 1. Background modes & entitlements (what is permitted)
- `UIBackgroundModes` array accepts two CoreBluetooth values:
  - `bluetooth-central` — app is woken from suspended to handle events for **already-connected** peripherals (connection established, characteristic updates, disconnects).
  - `bluetooth-peripheral` — app may **advertise while backgrounded** (but: `CBAdvertisementDataLocalNameKey` is ignored; local name not broadcast) [Apple CB Background Processing].
- iOS 26+ (current = macOS 26 / Xcode 26.6 → target iOS 26): the new `bluetooth-non-connectable-ambient` mode + **Live Activity** lets a backgrounded app scan *without service-UUID filtering* and with duplicates enabled, but **only if the app starts a Live Activity before backgrounding** → opt-in, on-screen, rare. Pre-iOS-26: background scanning is throttled (connectable-filtered only).

#### 2. Connected vs non-connected in background (the decisive constraint)
- A backgrounded iOS app **keeps existing GATT connections alive** and the system wakes it for BT events [Apple CB concepts: "woken up from a suspended state to process certain Bluetooth-related events"]. iOS forums confirm: an iOS BLE-forwarding app that stalls in background resumes via **CoreBluetooth state-preservation/restoration callbacks** and **re-attaches to the known node automatically** [Meshtastic-Apple#1402: "iOS delivers CoreBluetooth restoration callbacks; the app re-attaches to the node automatically on background wake"].
- **Discovery/scan of *new* peers while backgrounded is throttled/Restricted:** the Apple-forums MultipectorConnectivity mesh-relay post states exactly the failure we'd see: *"MPC stops browsing and advertising when the app is backgrounded, which means a node can no longer relay messages for the rest of the mesh"*; `beginBackgroundTask` buys only ~30 s [Apple forums 801973 / Stack Overflow fcc29e-07: "advertising … all the time, even when the app isn't running" — not supported without foreground]. iOS 26 Live Activity is the *only* unlocked path, and it requires a visible on-screen activity.

#### 3. Timing budgets
- **Background-task budget:** ~30 s hard cap via `beginBackgroundTask` / `BGTaskScheduler` (BGProcessing for deferrable; BGAppRefresh for <30 s). Any long non-connection work must fit or be deferred.
- **Connection interval (background, throttled):** the 7.5 ms spec minimum does not apply in the background; effective intervals throttle to **≥~100 ms** (iOS "throttling to save power"), so a relayed write round-trip per hop is ~100 ms+ floor [argenox "Bluetooth 6 Speed": iOS 15 ms short / 30 ms sustainable in foreground; background unstated → throttled above 100 ms]. Per-hop latency therefore ≥100 ms in background.
- **Advertising interval (background):** min 152 ms for non-connectable [Apple WWDC19 / CoreBluetooth].

#### 4. Net — what the iOS node can actually do
| Capability | In background | Requires |
|---|---|---|
| Hold & ATT-traffic on existing GATT links | ✅ yes (woken on events) | `bluetooth-central`+`bluetooth-peripheral` + restore IDs |
| Advertise (be a *new* peer source) | ✅ limited (local name stripped) / ❌ sustained | `bluetooth-peripheral`; foreground for full adv |
| Scan/discover *new* mesh neighbours | ❌ throttled (pre-iOS-26) / ✅ w/ Live Activity (iOS 26) | Live Activity entitlement (iOS 26) |
| Forward a queued packet to an *existing* neighbour link | ✅ yes | existing GATT connection |

**Consequence for the spec:** an iOS phone is **not** a persistent advertiser/discoverer for mesh flooding. The connection graph must be **formed in the foreground** (scan → connect → discover services/characteristics → negotiate MTU 247) before the app backgrounds. In the background the iOS node operates as a **relay over its already-established links**, tolerating ≥100 ms per-hop intervals, and survives process death via CoreBluetooth state restoration (re-attach to known peripherals). It is a **leaf-or-relay-over-pre-existing-links** node — never a bootstrap/discovery node in the background. Android has no such background-advertising throttle (it can scan/advertise in a foreground service), so the **topology is asymmetric**: Android phones can seed/maintain the graph from background; iOS phones cannot.
