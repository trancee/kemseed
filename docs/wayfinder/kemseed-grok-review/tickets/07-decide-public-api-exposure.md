# D14: Public API surface exposure timing

- **Type:** `grilling` / HITL (owner decision)
- **Status:** OPEN — claimed by: __
- **Blocked by:** #20 (Phase-1b PDV framing sign-off)
- **Informs:** none (gate to library graduation)

## Question

Grok §6 + §8 note the public surface is nearly empty (`object KemSeed` + enums +
constants) and that exposing a real API is blocked on Phase-1b PDV-framing
(seqno-width / AAD / ACK) being finalized (#20 `1b BLOCKED`). Decide:

- **A — Block on #20 (current).** No public API until the Phase-1b PDV envelope
  (seqno width, AAD layout, ACK semantics) is signed off. Keeps the contract
  from freezing half-baked. Matches #20 + the handoff's "do NOT expose public
  API until that gate."
- **B — Ship minimal, forward-compatible surface now.** Expose *only* the
  already-stable Phase-1a pieces — `Aes256Gcm.seal/open` + `Gmac.gmacTag` +
  `Hmb1Handshake` — as the public API, explicitly versioned, with the PDV
  envelope (`#08` Phase D) documented as the upcoming breaking addition. Risks a
  second public-API revision once 1b lands.

## Recommendation

**A.** Phase-1b framing is the real constraint, and #20 is `BLOCKED on owner
sign-off`. A minimal public surface now buys little (consumers still can't build
a full mesh node) and invites a breaking revision. Park D14 in the fog; graduate
it the moment #20 `1b` is unblocked.

## Assets

- #20 (`1b BLOCKED on owner sign-off for PDU framing`).
- #08 (PDV envelope §1.6 §3 Phase D).
- `KemSeed.kt` (current near-empty public surface).
