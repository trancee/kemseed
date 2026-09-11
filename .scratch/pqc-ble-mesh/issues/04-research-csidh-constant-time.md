# Research: Survey constant-time CSIDH reference implementations

Status: resolved
Type: research
Blocked by: (none)

## Question

Threat Model §Elevation of Privilege demands strictly **constant-time** execution for CSIDH group-action math (and AES-256-GMAC generation) to mitigate SPA/timing side-channels — a viability requirement on mobile background.

`PROMPT.md` references four CSIDH implementations: `ioerror/csidh-reference-implementation`, `amirjalali65/ARMv8-CSIDH`, `splight793/AVX-CSIDH`, and the "High-throughput and low-latency AVX-512" port.

Question: Of these (and any others), which are **(a)** constant-time or ship a constant-time variant, **(b)** license-compatible for reuse, and **(c)** usable from a mobile target (ARM / iOS / Android)? Note that the upstream reference implementation is known to be variable-time, and the AVX-512 port optimises throughput, not side-channel resistance.

Sources: the implementations' READMEs/code, accompanying papers' side-channel notes, and CSIDH literature on constant-time implementation (e.g., CSIDHki / constant-time CSIDH work).

## Answer

**Resolving: constant-time CSIDH exists and runs on ARM, but costs ~seconds per group action — feasible only with strict DoS/rate-limiting; the upstream reference is variable-time.**

- Upstream CSIDH reference (Castryck–Lange–Martindale–Panny–Renes): **variable-time** (basis of the "80 ms" / 64-byte figures).
- **amirjalali65/ARMv8-CSIDH** (listed in PROMPT.md): "implements CSIDH in both constant-time and variable-time. The constant-time implementation… is **free of any if or while statement**" (Jalali et al., 64-bit ARM). ✓ Confirms PROMPT's own reference ships a CT variant.
- First constant-time C CSIDH: Meyer, Campos, Reith (Eprint 2019/837) — dummy operations + masking.
- **CTIDH** (Banegas, Bernstein, Campos, Chou, Lange, Meyer, Smith, Sotáková; Eprint 2023/793): a new constant-time key space + batched algorithms, "an almost twofold speedup," reducing isogeny count ~half. Available for 512- and 1024-bit primes.
- **Performance:** constant-time CSIDH on 64-bit ARM Cortex-A72 ≈ ~12 s/group action; CTIDH ≈ half. Campos et al. evaluated on Cortex-M4 (mobile-class). The variable-time PoC is ~80 ms but NOT side-channel safe. So a constant-time CSIDH-512 handshake costs seconds — acceptable **only** if the DoS mitigation is strict enough to rate-limit CSIDH before the heavy math.
- **Licenses vary:** upstream reference is MIT/BSD; CTIDH/ARM ports' licenses must be audited downstream for mobile reuse.

Sources:
- arxiv 2508.11082 ("A Constant-Time Hardware Architecture for the CSIDH Key-Exchange Protocol"): survey of Meyer/Campos/Reith/Jalali CT work + CTIDH, ~12 s on A72.
- ECRYPT IACR ePrint 2023/793: CTIDH ~2x speedup, constant-time, 512/1024-bit support.
- amirjalali65/ARMv8-CSIDH README: "both constant-time and variable-time… free of any if or while statement."
- Eprint 2019/837 (Meyer/Campos/Reith): first constant-time CSIDH.

