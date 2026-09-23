# T1: AES/GCM alloc optimizations

- **Type:** `task` (AFK — mechanical, KAT-gated, no decision needed)
- **Status:** OPEN — claimed by: __
- **Blocked by:** 00 (expanded key schedule — done; T1 builds on it)
- **Informs:** D7, D11 (perf measurements feed the native-vs-pure call)

## Question

Implement the three remaining mechanical allocation cuts from Grok §2/#2 +
§2/#3, all KAT-gated (no output-byte changes):

1. **In-place encrypt/decrypt** — add `Aes256Key.encryptBlock(block, out)` /
   `decryptBlock(block, out)` overloads writing into a caller-provided 16-byte
   buffer; `ctrTransform` + `gcmAuthTag` H/S switch to in-place to drop the
   per-block `block.copyOf()` alloc.
2. **Pre-size `ct‖tag` in `Aes256Gcm.seal`** — allocate one `ByteArray(ct.size + 16)`
   and `copyInto` the two halves, instead of `ct + tag` (which still allocates
   but is one extra transient).
3. **Drop the two `copyOfRange` in `Aes256Gcm.open`** — keep `copyOfRange` for the
   tag (must be isolated for `ctEquals`), but feed `ct` as an offset/length view
   into `gcmAuthTag`/`ctrTransform` instead of copying it out.

## Recommendation

Yes. Low-risk (KAT-gated), in the now-green Phase-1a layer. Claim and implement;
re-run the full gate (§Notes on MAP.md) — no decision required beyond "ship it."

## Assets

- `Aes256Gcm.kt` (seal:open:ctrTransform), `Gmac.kt`, `Aes256.kt`.
- Grok §2/#2 (in-place), §2/#3 (allocs).
