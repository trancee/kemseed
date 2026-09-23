# Expand AES-256 key schedule once per GCM op

- **Type:** decided/implemented
- **Status:** RESOLVED (committed `85775f6`)
- **Blocks:** D11, T1, D7 (all build on this refactor)

## Question

Can the AES-256 key schedule (`keyExpansion`, 60 words) be computed once per
key and reused across the per-block calls in the GCM/CTR/GMAC hot path, without
changing any output bytes?

## Resolution

Yes. `Aes256.expandKey(key)` now returns an `Aes256Key` (reusable schedule).
`Gmac.gcmAuthTag` and `Aes256Gcm.ctrTransform`/`seal`/`open` expand once per
op and thread the schedule to H, S, and every CTR keystream block. The
one-shot `Aes256.encryptBlock(key, block)` KAT path delegates to
`expandKey(key).encryptBlock(block)` (byte-identical). A single GCM `seal` of a
60-byte PDU drops from ~6 key expansions (4 CTR + H + S) to 1.

Verified green: `Aes256Test` FIPS-197, `Aes256GcmTest` (14 vectors incl.
OpenSSL `cryptography.hazmat.AESGCM` oracle + GMAC-consistency + tamper/reject),
`GmacTest`, `AdPduTest`, `Hmb1HandshakeTest`, `:compileKotlinIos`,
`:spotlessCheck --rerun-tasks`.

## Findings / assets

- `src/commonMain/kotlin/ch/trancee/kemseed/Aes256.kt` — `expandKey` + `Aes256Key`.
- `src/commonMain/kotlin/ch/trancee/kemseed/Gmac.kt` — `gcmAuthTag` takes the schedule.
- `src/commonMain/kotlin/ch/trancee/kemseed/Aes256Gcm.kt` — expand-once + thread.
