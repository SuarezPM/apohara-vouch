# Apohara VOUCH — Demo Video Script (5 min)

> **Brand**: Apohara VOUCH — *"Vouch for every agent decision."*
> **Track**: Band of Agents Hackathon · Track 3 — Regulated & High-Stakes Workflows
> **Target length**: ≤5 min (MP4)
> **Recording tool**: OBS Studio or ffmpeg + xdotool
> **Output**: `demo/video.mp4` (≤50 MB, H.264 8-12 Mbps, 1080p, 16:9)
> **Upload**: YouTube unlisted → paste URL into lablab.ai form
>
> The script is a single linear demo: cold start → submit a procurement
> case → watch 9 agents collaborate in the Band room → Evidence Packet
> download → 3 prize-category dedications → closing. Every shot
> references a real artifact produced by the S-01..S-12 stories.
>
> **Prize-category content budget: 3:00 of 5:00** (Shot A Main Track 3
> = 1:00, Shot B AI/ML API = 1:00, Shot C Featherless = 1:00). Remaining
> 2:00 covers the live demo + offline verify. Timestamps below are the
> authoritative duration table for `ffprobe` chapter markers.

---

## Prize-category time budget (authoritative for AC-12.2)

| Shot | Start | End | Duration | Prize category |
|---|---|---|---|---|
| Shot A — Main Track 3 | 1:40 | 2:40 | **60s** | Main Track 3 (1st / 2nd / 3rd) |
| Shot B — Best Use of AI/ML API | 2:40 | 3:40 | **60s** | Best Use of AI/ML API |
| Shot C — Best Use of Featherless | 3:40 | 4:40 | **60s** | Best Use of Featherless |
| **Total prize-category content** | | | **3:00** | All three prizes ≥60s each |

`ffprobe -i demo/video.mp4 -show_chapters` should report exactly these
chapter markers. The script's shot list below carries the same
timestamps so editors can verify without re-cutting.

---

## Shot 1 — 0:00..0:15 — HOOK

**Visual**: Black screen → slow zoom into a navy card with a gold
"VOUCH" wordmark. The tagline fades in below:
*"Vouch for every agent decision."*

**Voiceover**:

> "Every procurement decision needs a receipt. Not a summary — a
> signature. Apohara VOUCH runs a 9-agent procurement court on Band,
> backed by AI/ML API and Featherless, and produces a cryptographic
> Evidence Packet that any auditor can verify offline — in under
> thirty seconds, no network."

**B-roll**: `docs/cover.svg` (1200×630) rendered full-screen.

---

## Shot 2 — 0:15..0:40 — DEMO COLD START

**Visual**: Browser at <https://vouch.apohara.dev>. Three panels:
transcript (left), cost (top-right), compliance dashboard
(bottom-right). Below the fold: procurement request form.

**Actions on screen** (narrate each):

1. **Page loads** — terminal-style loading strip in the top-right
   corner reads `cold fetch <800ms`.
2. **Empty state** — the three panels show placeholders: "Waiting for
   first case…" (transcript), "$0.0000" (cost), "0/8 ✓" (EU AI Act
   Art. 12).
3. **Type the demo URL** — `vouch.apohara.dev` URL bar visible.

**Voiceover**:

> "Cold start under 800 milliseconds. Three panels: live Band room
> transcript on the left, per-agent cost on the top-right, EU AI Act
> Art. 12 dashboard on the bottom-right. Watch them all fill up at
> once as the agents deliberate."

---

## Shot 3 — 0:40..1:00 — SUBMIT A PROCUREMENT CASE

**Visual**: Same browser. Form fields: `buyer`, `vendor_name`,
`amount_eur`, `category`, `requested_action`, `urgency`.

**Actions on screen** (narrate):

1. **Buyer**: `Wayne Enterprises`
2. **Vendor name**: `Acme Shell Holdings Ltd`
3. **Amount**: `€4,200,000`
4. **Category**: `IT services`
5. **Requested action**: `Approve vendor onboarding`
6. **Urgency**: `Critical (24h SLA)`
7. **Click "Submit to procurement court"**.

**Voiceover**:

> "Wayne Enterprises wants to onboard Acme Shell Holdings for a
> four-million-euro IT contract on a 24-hour critical SLA. That's the
> case. Nine agents are about to deliberate in a real Band chat room.
> Every word they say becomes part of the Evidence Packet."

**B-roll**: Case ID generated: `case-WAYNE-2026-0173`.

---

## Shot 4 — 1:00..1:40 — NINE AGENTS, ONE BAND ROOM

**Visual**: Transcript panel scrolls rapidly. Each agent's message
appears with `@mention` arrow to the next agent. Right side shows
per-agent cost panel ticking up live.

**On-screen transcript moments** (narrate):

```
@Orchestrator        → @IntakeAgent           "Intake this case."
@IntakeAgent (Claude Haiku 4.5 / AI/ML API)
   → @VendorResearcher  "ProcurementCase. Find vendor profile."
@VendorResearcher (Llama-3.3-70B / Featherless)
   → @FinanceRiskAnalyst  "VendorProfile. Score the risk."
@FinanceRiskAnalyst (Claude Sonnet 4.6 / AI/ML API)
   → @LegalPolicyChecker  "RiskScore 0.91 CRITICAL. Check policy."
@LegalPolicyChecker (Qwen3-Coder-30B / Featherless)
   → @RedTeamAuditor  "PROC-001, AML-001, COI-001. Audit me."
@RedTeamAuditor (Claude Opus 4.7 / AI/ML API)
   → @ComplianceVeto  "VETO RECOMMENDED. risk_score 0.91."
@ComplianceVeto (Claude Haiku 4.5 / AI/ML API, SECOND account)
   → @EvidenceClerk  "VETO CONFIRMED. Seal the packet."
@EvidenceClerk (DeepSeek-V3 / Featherless)
   → @ApprovalManager  "EvidencePacket sealed. Ed25519 + BLAKE3 + RFC 3161."
```

**Voiceover**:

> "Four frameworks on two providers, every handoff a real @mention,
> the transcript IS the audit trail. The cost panel ticks up: AI/ML
> API for orchestration, intake, risk, red team, compliance, approval —
> Featherless for vendor research, legal policy, evidence aggregation.
> The Red Team Auditor found three Critical findings; the Compliance
> Veto — on a second Band account — confirmed them."

**B-roll**: cost panel reads approximately:
`Orchestrator $0.04 · Intake $0.01 · Vendor Research $0.02 ·
Finance Risk $0.06 · Legal Policy $0.03 · Red Team $0.12 ·
Compliance Veto $0.01 · Evidence Clerk $0.02 · Approval $0.05 ·
Total $0.36`.

---

## Shot A — 1:40..2:40 — PRIZE: MAIN TRACK 3 (60 seconds)

**Prize category**: **Main Track 3 — Regulated & High-Stakes
Workflows** (1st / 2nd / 3rd prize).

**Visual**: Split layout. Left half: still frame of the 9-agent
transcript from Shot 4 frozen with a gold border labelled "TRACK 3
ARTIFACT". Right half: large stat cards stacking in — "9 agents", "2
Band accounts", "8/8 EU AI Act Art. 12", "Ed25519 + BLAKE3 + RFC 3161
+ Rekor v2 + C2PA".

**Voiceover** (60 seconds — full minute dedicated to Track 3):

> "Prize number one: Main Track 3 — Regulated and High-Stakes
> Workflows. The artifact is a regulated enterprise procurement court
> with cryptographic evidence. Nine agents, four orchestration
> frameworks — LangGraph, CrewAI, Pydantic AI, and the Anthropic SDK —
> running on two independent Band accounts so the compliance veto
> cannot be overridden by the orchestrator. Every high-judgment LLM
> call produces a typed, signed finding. The final receipt is a real
> Evidence Packet: nine Ed25519 signatures, a BLAKE3 chain with ten
> sequence-monotonic entries, an RFC 3161 timestamp from freetsa.org,
> a Rekor v2 transparency log anchor, and a C2PA manifest. Offline
> verification runs in the vouch-verify CLI in under thirty seconds —
> no network, no trust in VOUCH. Coverage: eight of eight EU AI Act
> Article 12 fields populated, three of three DORA Article 9, 10, 17
> fields, four of four NIST AI RMF functions traced, ten of ten OWASP
> Agentic 2026 threats assessed. One procurement case, one signed
> receipt, one auditable verdict. That is the Track 3 artifact."

**B-roll**: slide "Slide 12 / 18 — Main Track 3" from
`docs/pitch-deck.pdf` rendered full-screen for the last 10 seconds of
the shot.

---

## Shot B — 2:40..3:40 — PRIZE: BEST USE OF AI/ML API (60 seconds)

**Prize category**: **Best Use of AI/ML API** ($1,000 cash + $1,000
credits).

**Visual**: The live cost panel from Shot 4 zooms into a centered
card. AI/ML API call sites pulse gold in sequence:
Orchestrator → Intake → Finance Risk → Red Team → Compliance Veto →
Approval. Each pulse reveals the model name and role in monospace.

**Voiceover** (60 seconds — full minute dedicated to AI/ML API):

> "Prize number two: Best Use of AI/ML API. Five of the nine agents
> sit on the critical decision path and route every high-judgment
> call through the AI/ML API gateway, across four distinct model
> families. OpenAI GPT-5.4 powers the nine-state orchestrator that
> emits a thenvoi_send_event on every transition. Claude Haiku 4.5
> handles structured intake into a nine-field ProcurementCase
> schema. Claude Sonnet 4.6 scores risk with citation grounding and
> stays monotonic in the euro amount — prompt-cache hit around
> ninety-five percent across runs, so the marginal cost stays low
> without sacrificing reasoning quality. Claude Opus 4.7 runs the
> red-team adversarial audit and produces deterministic Critical
> findings. A second Band account running Claude Haiku 4.5 holds the
> binding compliance veto — escalation routing is deterministic and
> cannot be overridden by the orchestrator. Claude Sonnet 4.6 closes
> the loop in the approval manager, producing the DecisionMemo, the
> C2PA PDF, and the human sign-off gate. Six AI/ML API call sites in
> the live demo, four distinct model families, one critical decision
> path. That is the AI/ML API prize."

**B-roll**: slide "Slide 13 / 18 — Best Use of AI/ML API" from
`docs/pitch-deck.pdf` rendered full-screen for the last 10 seconds of
the shot.

---

## Shot C — 3:40..4:40 — PRIZE: BEST USE OF FEATHERLESS (60 seconds)

**Prize category**: **Best Use of Featherless AI** ($500 cash + $300
+ $100 credits).

**Visual**: The Featherless call sites — VendorResearcher, LegalPolicy-
Checker, EvidenceClerk — pulse in sequence with their open-weight
model lineages displayed in monospace: `Llama-3.3-70B`,
`Qwen3-Coder-30B-A3B`, `DeepSeek-V3-0324`. A side card shows
`https://api.featherless.ai/v1` wiring and the MockLlmProvider
fallback contract.

**Voiceover** (60 seconds — full minute dedicated to Featherless):

> "Prize number three: Best Use of Featherless AI. Three of the nine
> agents run on Featherless open-weight models — three distinct
> lineages, each chosen by role. Meta Llama 3.3 70B Instruct drives
> the vendor researcher: sanctions, ultimate beneficial owner, and
> adverse-media resolution against the procurement fixture database.
> Qwen3 Coder 30B A3B Instruct drives the legal and policy checker:
> statutory citation grounding across EU Directive 2014/24/EU, GDPR,
> the Sixth Anti-Money-Laundering Directive, DORA, and SOX. DeepSeek
> V3 drives the evidence clerk: long-context aggregation of every
> agent's structured output into a single typed Evidence Packet
> envelope. All three agents wire to the Featherless OpenAI-compatible
> gateway at api.featherless.ai, and all three have a graceful
> MockLlmProvider fallback for tests — so the production path is
> never blocked by a provider outage. Three independent model
> lineages, zero consensus trap, zero two-agents-same-model
> deception. That is the Featherless prize."

**B-roll**: slide "Slide 14 / 18 — Best Use of Featherless" from
`docs/pitch-deck.pdf` rendered full-screen for the last 10 seconds of
the shot.

---

## Shot 5 — 4:40..4:50 — EVIDENCE PACKET DOWNLOAD + OFFLINE VERIFY (compressed)

**Visual**: Bottom-right panel flips to **8/8 ✓** on the EU AI Act
Art. 12 dashboard. A "Download Evidence Packet" button appears. Click
opens the C2PA-signed PDF in a new tab. A terminal overlay shows:

```bash
$ vouch-verify fixtures/sample_packet.json
BLAKE3 chain:  10 entries, sequence-monotonic
Ed25519 sigs:  9/9 verified
RFC 3161:      freetsa.org, genTime verified
Rekor v2:      log_index=1287, integrated_time verified
EU AI Act 12:  8/8 fields populated
✓ VERIFIED
```

**Voiceover** (10 seconds):

> "Eight of eight EU AI Act Article 12 fields. Verified offline, in
> under thirty seconds, by a single CLI binary."

---

## Shot 6 — 4:50..5:00 — HUMAN SIGN-OFF + CLOSING

**Visual**: Browser, transcript panel. A red modal appears: "HUMAN
SIGN-OFF REQUIRED — type the approval code to vouched=true". Type
`VOUCH-WAYNE-2026-0173`, press Enter. Modal turns green.
`vouched: true` posted by `@ApprovalManager`.

Then the screen fades to black with white text:

> **Apohara VOUCH**
> Vouch for every agent decision.
>
> 9 agents · 4 frameworks · 2 LLM providers · 1 chat room · 1 signed receipt
>
> vouch.apohara.dev
> github.com/SuarezPM/apohara-themis
>
> Built for Band of Agents Hackathon · Track 3 — Regulated & High-Stakes

**Voiceover** (last 5 seconds):

> "The verb is VOUCH. Three prizes, one submission. Submit yours."

---

## Production notes

- **Aspect ratio**: 16:9, 1920×1080 or 1280×720
- **Frame rate**: 30 fps
- **Audio**: 48 kHz mono, peak at -6 dB
- **Music**: optional, low-energy ambient
- **Export**: H.264 8-12 Mbps, MP4, ≤50 MB for 5 min @ 1080p
- **Editing**: DaVinci Resolve (free), kdenlive, or ffmpeg

### Hard time gate

```bash
ffmpeg -i raw.mp4 -t 300 -c copy final.mp4
```

### Chapter markers (for AC-12.2 verification)

```bash
ffmpeg -i final.mp4 \
  -metadata title="Apohara VOUCH" \
  -metadata artist="Apohara VOUCH" \
  -metadata comment="Track 3 + AI/ML API + Featherless" \
  -i chapters.txt \
  -map_metadata 1 \
  -codec copy final_chaptered.mp4
```

Where `chapters.txt` (ffmetadata format) is:

```
[CHAPTER]
TIMEBASE=1/1000
START=0
END=15000
title=00:00 Hook
[CHAPTER]
TIMEBASE=1/1000
START=15000
END=40000
title=00:15 Cold start
[CHAPTER]
TIMEBASE=1/1000
START=40000
END=60000
title=00:40 Submit
[CHAPTER]
TIMEBASE=1/1000
START=60000
END=100000
title=01:00 9 agents
[CHAPTER]
TIMEBASE=1/1000
START=100000
END=160000
title=01:40 PRIZE — Main Track 3
[CHAPTER]
TIMEBASE=1/1000
START=160000
END=220000
title=02:40 PRIZE — Best Use of AI/ML API
[CHAPTER]
TIMEBASE=1/1000
START=220000
END=280000
title=03:40 PRIZE — Best Use of Featherless
[CHAPTER]
TIMEBASE=1/1000
START=280000
END=290000
title=04:40 Packet + offline verify
[CHAPTER]
TIMEBASE=1/1000
START=290000
END=300000
title=04:50 Sign-off + closing
```

Verify with:

```bash
ffprobe -i final_chaptered.mp4 -show_chapters
```

The three PRIZE chapters (01:40, 02:40, 03:40) MUST each be exactly
60,000 ms long. That is the AC-12.2 measurement.

### What NOT to include

- No login flow (VOUCH has none)
- No `Cargo.toml` dependency list
- No "we're the only ones" claims — focus on what VOUCH does
- No marketing claims that aren't backed by the live demo
- No mention of "THEMIS" — the brand is Apohara VOUCH
- No time-anchors (no "by", no "tomorrow", no "sprint", no "week",
  no "deadline") — the demo speaks for itself

### Post-production checklist

- [ ] Total runtime ≤5:00
- [ ] Three PRIZE chapters each = 60,000 ms (verifiable with `ffprobe
      -show_chapters`)
- [ ] Sum of PRIZE chapters = 180,000 ms = 3:00
- [ ] The 9-agent transcript appears in Shot 4
- [ ] The cost panel ticks up in Shot 4
- [ ] The 8/8 EU AI Act panel flips green in Shot 5
- [ ] The `vouched: true` event fires in Shot 6
- [ ] The vouch-verify CLI exits 0 in Shot 5
- [ ] The pitch-deck slides 12, 13, 14 (Main Track 3, AI/ML API,
      Featherless) appear as B-roll in Shots A, B, C respectively
- [ ] Export at 8 Mbps H.264, 1080p, MP4
- [ ] File ≤50 MB
