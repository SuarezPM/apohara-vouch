# Judge Quickstart — Apohara VOUCH

> 1 page. 3 commands. ~5 minutes cold start.

Apohara VOUCH is a 9-agent procurement court on Band. Every agent
runs on a different framework (LangGraph, CrewAI, Pydantic AI,
Anthropic SDK), every LLM call routes through AI/ML API or
Featherless, every `@mention` handoff is a real Phoenix Channels
event, and every decision flows through an Evidence Layer that
produces a cryptographically-sealed, offline-verifiable receipt.

This page is the path of least resistance for a judge who wants
to verify the product in under 5 minutes.

---

## 0. Demo live right now (no install)

**`https://vouch.apohara.dev`** — 3-panel UI, cold fetch <800 ms.

- **Left panel** — Band room transcript (live, auto-scroll).
- **Top-right** — Per-agent cost panel (AI/ML API $ + Featherless $).
- **Bottom-right** — EU AI Act Art. 12 dashboard (8/8 fields).
- **Submit a procurement request** → 9 agents collaborate →
  Evidence Packet downloads as PDF → human types approval code →
  `vouched: true` closes the case.

If you only have 30 seconds, click the demo URL above and watch
the agents debate. The BAAAR HALT fires visibly when the
`stark-001` fixture runs (cross-tenant double-spend).

---

## 1. Run it locally (3 commands)

```bash
# 1. Get the repo + enter it
git clone https://github.com/SuarezPM/apohara-vouch.git
cd apohara-vouch

# 2. Configure API keys (interactive — only on first run)
./scripts/apohara_init.sh

# 3. Build + run the orchestrator + the frontend
cargo run --release --bin themis-orchestrator &
cargo run --release --bin vouch-frontend
# → open http://localhost:7879
```

Cold start: ~35 s for the first release build (cached after that:
~2 s). End-to-end review: <90 s per procurement request.

### Optional: 1-page judge demo runner

```bash
./scripts/judge_demo.sh
# → PDF + JSON written to ~/Escritorio/apohara-vouch-judge-demo.{pdf,json}
```

This runs the canned `stark-001` fixture (cross-tenant
double-spend, BAAAR HALT, risk_score = 0.92) and produces a
printable Evidence Receipt on your desktop. Total runtime: ~40 s
(no API keys needed — uses the mock LLM provider).

---

## 2. Verify offline

After the demo runner (or after hitting `/packets/:id/pdf` on the
live demo), you have a `SealedPacket.json`. Verify it:

```bash
cargo run --release --bin vouch-verify -- ~/Escritorio/apohara-vouch-judge-demo.json
```

Expected output:

```
vouch-verify: /home/thelinconx/Escritorio/apohara-vouch-judge-demo.json
  PASS  structural
  PASS  hash_format
  PASS  ed25519_signature
  PASS  hash_chain_prev_format
  PASS  eu_ai_act_art12_coverage
  SKIP  rfc3161_timestamp: no DER block in packet (synthetic)
  PASS  tenant_key_match

Result: PASS
```

The `SKIP` is honest: when the demo runner skips the FreeTSA
roundtrip (mock timestamp), the DER block is synthetic. The
**production SealedPacket** (from `vouch.apohara.dev`) does carry
a real RFC 3161 timestamp from the public TSA at `freetsa.org`.

---

## 3. What to look at in the PDF

Open `~/Escritorio/apohara-vouch-judge-demo.pdf` (or the one you
downloaded from the live demo). It's 1 page, A4, print-friendly:

- **Verdict pill (top)** — HALT (red) for `stark-001`; APPROVED
  (green) for clean fixtures.
- **Reason (under verdict)** — `risk_score_exceeded — cross-tenant
  double-spend (Globex Industrial, $50k vs wayne-002 5 days ago)`.
- **# AGENT table** — per-agent decision (kind, severity, evidence,
  cost USD cents).
- **EU AI Act Art. 12 dashboard** — 8 fields, ✓ per populated one.
  At least 7 must be ✓ for AC15 compliance.
- **QR code (bottom-right, 48 mm)** — scan with your phone to verify
  offline against the public Rekor v2 transparency log.
- **Ed25519 signature + BLAKE3 chain tip** — at the bottom, in
  monospace. The signature is 64 bytes hex; the hash is 32 bytes
  hex.

---

## 4. The 7 claims you'll see in the pitch (all measurable)

| Claim | Where to verify |
|---|---|
| "9 agents, 4 frameworks" | `crates/vouch-agents/src/orchestrator.py` (top-of-file docstring) + `docs/SPEC.md` |
| "AI/ML API powers 5 of 9 agents" | `crates/themis-orchestrator/src/llm_backend.rs` (model_id_for_agent table) |
| "Featherless powers Qwen3-Coder-30B + DeepSeek-V3" | `crates/themis-orchestrator/src/llm_backend.rs` + `crates/vouch-agents/src/evidence_clerk.py` |
| "BAAAR HALT deterministic 10/10" | `crates/vouch-agents/tests/test_compliance_fallback_chaos.py` |
| "Ed25519 + BLAKE3 offline-verifiable" | `vouch-verify` (this page, §2) |
| "EU AI Act Art. 12 ≥7/8" | `crates/themis-compliance/src/framework.rs` (the compliance mapper) |
| "Cross-tenant isolation 10/10" | `crates/themis-orchestrator/tests/band_cross_account_chaos.rs` (G4) |

Every claim is backed by a test you can run.

---

## 5. Honest non-claims

We do NOT claim:

- ❌ A live Band chat room in this judge-quickstart. The PDF demo
  uses the in-process `ScriptedBandRoom` for determinism. The live
  demo at `vouch.apohara.dev` runs against the real Band runtime
  with `THEMIS_BAND_MODE=real` and `BAND_API_KEY` set.
- ❌ Real FreeTSA timestamp in the PDF you generate locally. See
  §2 SKIP note. The live demo signs with the real public TSA.
- ❌ Multi-tenant key-rotation. Ed25519 keys are baked at compile
  time (`include_bytes!`) so they survive Vercel's ephemeral FS.

---

## 6. If something is unclear

- **Repo**: <https://github.com/SuarezPM/apohara-vouch>
- **Spec**: `docs/SPEC.md`
- **Submission text**: `docs/submission-final.md`
- **Hackathon**: Band of Agents Hackathon · Track 3 · 12–19 jun 2026
- **Author**: Pablo M. Suarez · `@SuarezPM`