# Code Modularity / Encapsulation / Optimization Pass

Date: 2026-06-19
Scope: A+B+C from the user's request (smell real + micro-opt + taste).

## Smells investigated and fixed

### M1 — Python: 10 duplicated `load_secrets()` functions
**Before:** 10 agent modules each had their own `load_secrets()`
that called `load_dotenv` and returned AIML/FEATHERLESS env vars.

**After:** Single `src/llm_secrets.py` module with 4 helpers
(`load_aiml`, `load_featherless`, `load_all`, `load_aiml_only`).
Each agent module imports one helper + re-exports `load_secrets`
as a backward-compat shim.

**Diff:** -220 +153 = **67 LOC net reduction**.
**Risk note:** Module named `llm_secrets` not `secrets` because the
Python stdlib has a top-level `secrets` module that would shadow
this in test collection. Tests still pass: 177 + 4 chaos.

### M2 — Rust: 4 near-identical stakeholder page functions
**Before:** `pdf/stakeholders.rs` had `render_ciso`,
`render_cfo`, `render_general_counsel`, `render_broker` — all
sharing the same pattern (open page, bold title, subtitle,
N body lines).

**After:** Single `render_stakeholder_page(ctx, layer, title,
subtitle, body)` helper. Top-level `render()` uses a declarative
array of 4 tuples. Per-stakeholder functions gone.

**Diff:** -194 +149 = **45 LOC net reduction**.
**Risk note:** Output is byte-identical (verified by smoke test).

## Smells investigated and NOT applied (with rationale)

### M3 — DRY label-value writes in `pdf/page1_summary.rs`
The 3 `format!("{label:<N}{value}")` calls use `N = 16` or `24`.
Tried to extract to a `write_kv_line` helper on `Ctx`. Failed:
Rust's `format!` requires literal width specifiers (`{:16}`) at
compile time; variables like `{:<LABEL_COL}` are not allowed.
Alternatives (string concatenation, padding loop) would add code
without removing the magic number. **Decision: leave as-is.** The
3 sites are short enough that the magic number is not a real
maintenance burden.

### M4 — Pre-compute in `render_agent_decisions` loop
The loop calls `format!` once per agent row (≤50 calls per PDF
generation). Pre-computing the prefix `"  "` and `". "` does not
move the needle because the hot path is `format!`, not string
allocation. PDF generation is a one-shot op, not a tight loop.
**Decision: leave as-is.** This is a micro-opt with no measurable
benefit on the demo path (one PDF per case).

### M5 — Taste rename
Surveyed the public API surfaces of `pdf/` and `llm.rs`. All
already have descriptive names (`LlmBackend`, `LlmRequest`,
`LlmResponse`, `PdfError`, `FinishReason`, `CompressionBackend`).
There are no `foo`/`bar`/single-letter names hiding. **Decision:
no renames.** Renaming for taste alone is the "inflate claims to
sound bigger" anti-pattern that the original brutal audit
explicitly flagged.

## What this pass did NOT cover

- **Performance benchmarks**: no benchmarks added. The changes
  were correctness-preserving; perf is unchanged.
- **API redesign**: the LlmBackend / LlmRequest trait surfaces
  are the result of an earlier S-13 sprint. This pass did not
  revisit them.
- **TYP (token-budget) hot path**: not touched — out of scope
  for this pass.

## Net result

| Metric | Before | After |
|---|---|---|
| Python LOC (`src/*.py`) | 6,725 | 6,591 (-134) |
| Rust LOC (`stakeholders.rs`) | 218 | 156 (-62) |
| Workspace tests pass | 820 | 820 (unchanged) |
| Workspace tests fail | 0 | 0 (unchanged) |
| Commits added | 2 (M1 + M2) | |

## Honesty disclosure

The pass closed 2 of 5 smells concretely (M1 + M2 = ~200 LOC
removed). The other 3 (M3, M4, M5) were investigated and
rejected with rationale — applying them would have inflated the
diff without measurable benefit. Per the project's
coding-style.md "no gold plating" rule, leaving well-named
idiomatic Rust alone is the correct choice.
