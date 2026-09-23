# T1: AES/GCM alloc optimizations

- **Type:** `task` (AFK — mechanical, KAT-gated, no decision needed)
- **Status:** RESOLVED — shipped `59c620e` (full gate green: 94 tests byte-exact +
  `compileKotlinIos` + `spotlessCheck`).
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

## Implementation (59c620e)

Shipped, all KAT-gated (no output-byte changes):

1. **In-place AES ✓** — `Aes256` exposes `encryptBlock(block,out,schedule)`/`decryptBlock(block,out,schedule)`
   (write 16B into a caller buffer; `out` may alias `block`); `Aes256Key` exposes the same.
   `ctrTransform` now reuses **one** 16-byte `ks` buffer for all CTR blocks (was allocating per block).
2. **Pre-size `ct‖tag` in `seal` ✓** — single `ByteArray(ct.size+16)` + `copyInto` (drops the `ct+tag` transient).

Deferred (out of scope — marginal gain vs. slice-threading surface):

3. **`open` `copyOfRange` drop ⏸** — keeping the two existing `copyOfRange` calls. Dropping the `ct`
   copy would require threading `(buffer, off, len)` slices through the GHASH helpers
   (`gcmAuthTag` → `ghashFold`/`padToBlockLen`/`lenBlock`) — real surface, and the `tag` copy
   is still needed for `ctEquals` isolation. Carries to D7/perf budgeting (feed the native-vs-pure
   call). NOTE: T1 never ships a `value class` `Aes256Key` — that was rejected pre-#1 (per KBP/AGP9.4
   `VALUE_CLASS_WITHOUT_JVM_INLINE_ANNOTATION`); the schedule stays an `IntArray`.

## Recommendation

Yes. Low-risk (KAT-gated), in the now-green Phase-1a layer. Done — shipped `59c620e`;
full gate green (94 tests byte-exact + `compileKotlinIos` + `spotlessCheck`). No decision required.

## Assets

- `Aes256Gcm.kt` (seal:open:ctrTransform), `Gmac.kt`, `Aes256.kt`.
- Grok §2/#2 (in-place), §2/#3 (allocs).
