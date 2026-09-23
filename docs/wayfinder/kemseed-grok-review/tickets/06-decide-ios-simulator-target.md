# D2: Add iosSimulatorArm64 target

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — claimed by: __
- **Blocked by:** (none)
- **Informs:** CI matrix, dev-ex for iOS path

## Question

Grok §5 proposes adding `iosSimulatorArm64` for CI/unit tests even though BLE is
non-functional in the iOS simulator. Const. E1 (`#08` spec) explicitly pins
"iOS (device only, no iOS-simulator targets — BLE is non-functional in
simulators)." Decide:

- **A — Keep device-only.** Honour E1. CI runs `:testAndroidHostTest` +
  `:compileKotlinIos` (cross-compile, no simulator). Mirrors current
  `ci.yml` (macos-14, no simulator).
- **B — Add `iosSimulatorArm64` (test-only).** Lets host-side pure-Kotlin tests
  (AES/GCM/GMAC/KAT, no BLE) run on the simulator in CI — fast local iteration +
  parallel CI matrix — while keeping BLE code `expect`ed-away on the simulator
  target. Adds a target + keeps `iosDeviceArm64` for real BLE.

## Recommendation

**B**, scoped narrowly: enable `iosSimulatorArm64` *only* for the pure-crypto
unit tests (AES/GCM/GMAC/Hmb1 KATs) — no BLE, no native fast-paths on the
simulator target. The crypto core is platform-agnostic; running it on the
simulator is free dev-ex. Keeps E1's "device-only BLE" intact.

## Assets

- #20 §kompact-adoption-path + `ci.yml` (macos-14 matrix).
- Const. E1 (device-only BLE).
