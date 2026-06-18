# Performance — MOIRAI v4

## Performance Targets (the 18 ACs are the source of truth)

- AC1: cold start <800ms
- AC2: end-to-end review <90s per PR
- AC3: peak memory <700 MB with 6 agents + Band WS + frontend
- AC10: BAAAR HALT visible in <90s in demo
- AC12: PRC PDF download <2s
- AC13: PRC offline verification <30s

If any AC is at risk during Phase 1-3, raise it before polish phase.

## Rust-Specific Performance Discipline

- **Compile in release mode for benchmarks.** `cargo build --release` enables LTO and codegen-units=1.
- **Measure before optimizing.** `cargo bench` (criterion) for any hot path. Don't guess.
- **Avoid `clone()` on hot paths.** Use `&str` or `Cow<str>` if you don't need ownership.
- **Use `Vec::with_capacity`** when the size is known.
- **Tokio: `tokio::spawn` for fan-out, `tokio::join!` for fan-in.** Don't block the runtime with `std::thread::sleep` or synchronous I/O.

## Token Economy (Compressor, WS5)

- **AC7: ≥30% token reduction measured vs no-Compressor baseline.** The AGORA-like pattern at r=0.5 measured -27.9% in a real RCT. Target ≥30%.
- Track per-agent token counts in `CostBreakdown` (already in `moirai-evidence::certificate`).
- Live counter in UI (AC9) shows the per-agent spend in real time.

## Memory Budget

| Component | Budget |
|---|---|
| Binary base | ~30 MB RSS |
| Tokio runtime + 6 agents | ~150 MB RSS |
| Band WS + HTTP server | ~50 MB RSS |
| turbovec index (100 PRs, 1536-dim, 4-bit) | ~40 MB (10 MB vectors + index overhead) |
| Ed25519 + BLAKE3 buffers | <10 MB |
| Frontend (HTML served, no SSR) | <5 MB |
| **Headroom** | ~400 MB |

## When to optimize

- AC3 at risk → profile with `cargo flamegraph`, find the hot spot, fix it
- AC2 at risk → measure per-agent latency, find the bottleneck, parallelize or compress
- AC8 at risk → review Compressor config, increase compression rate, swap to cheaper model
- Binary >30 MB → enable `lto = "fat"` and `strip = "symbols"` in release profile

## When NOT to optimize

- Premature optimization in Phase 0 (1h) or Phase 1 (5h parallel). The trait surface doesn't need to be fast — it needs to be correct.
- "Speculative" caching that adds complexity without measuring. If AC8 passes at $1.49/run, don't add a cache.

## [MOIRAI-specific]

- **Concurrency limit on Featherless**: 4 concurrent requests. 6 agents × 1 call each = 6 concurrent at peak. **Stagger spawn by 5-10ms** (Clotho @ 0ms, Lachesis @ 5ms, ...) to stay under the ceiling.
- **GLM-5.1 8h sustained is a vendor claim.** Don't claim 8h in the pitch. Claim what we measure.
- **Claude Sonnet 4.5 with 95% cache hit** is the cost lever. If cache hit drops below 90%, investigate the system prompt stability.
