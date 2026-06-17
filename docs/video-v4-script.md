# THEMIS 2.0 — Video v4 Script (5 min, 30 fps)

**Target audience:** Band of Agents Hackathon judge. **Goal:** deliver the
"THEMIS doesn't just detect fraud — it proves it" pitch in under 5 minutes.
**Updated 2026-06-17** for the THEMIS 2.0 pivot (Sprint 1-5 features
in scope: Real Band SDK, SponsorStack banner, AgentHandoff arrows,
per-agent multi-model dispatch, ISO 42001, retention, Art 73 incident
reporting, Apotheon disambiguation, public-bench, 4-buyer PDF, 31/31
dashboard).

---

## 0:00–0:30  HOOK

> "Every year, AP fraud costs enterprises $1.4 trillion. EU AI Act
> Article 12 goes live on 2 August 2026 — in 16 days. Most AI
> systems flag suspicious invoices but can't prove it. THEMIS can."

[CUT: themis.apohara.dev loading]
[CUT: SponsorStack banner: Band · AI/ML API · Featherless AI visible]

## 0:30–2:30  DEMO — Stark invoice flow with handoff arrows

[Submit a Stark invoice — InvoiceNet sample row 26 (PO-MISMATCH-*, $58K)]

Band room opens — 5 avatars appear:
  @extractor handoff @po_matcher (animated arrow)
  @po_matcher handoff @fraud_auditor (arrow)
  @fraud_auditor handoff @gaap_classifier (arrow, badge: "model: claude-sonnet-4.5")
  @gaap_classifier handoff @provenance_signer (arrow, badge: "model: Llama-3.3-70B")
[Provenance Signer emits Event::ProviderActive "model: Qwen3-Coder-30B"]

[BAAAR gate evaluates 5 conditions — risk_score = 0.95 — HALT]

[SealedPacket.rekor_entry: Some({ uuid, logIndex, bundleUrl })]
[Compliance dashboard: 31/31 fields green]
[ISO 42001 column unhidden: 5/5 clauses populated]

## 2:30–3:30  THE BAAAR HALT — Wayne invoice

[Submit a Wayne invoice — the HALT fixture]

@extractor handoff @po_matcher (arrow, "PO mismatch")
@po_matcher handoff @fraud_auditor (arrow, "no PO found")
@FraudAuditor emits FraudAssessment { risk_score: 0.92 }

[BAAAR: risk_score > 0.85, FIRED, score=0.92]

[Red modal: BAAAR HALT · WebAuthn HITL FIDO2 prompt]
[Event::IncidentReported fires — severity=high, reporting_window_hours=72]
[WebAuthn tap: APPROVE → audit_note appended to EvidencePacket]
[SealedPacket.rekor_entry: Some(...)]
[Compliance dashboard: 31/31, audit_note: "BAAAR HALT overridden via FIDO2"]

## 3:30–4:30  themis-verify OFFLINE

[CUT: terminal]

```bash
$ themis-verify sealed_packet.json
PASS
  content  [ok] artifact hash matches receipt
  hmac     [ok] hmac verified
  ed25519  [ok] ed25519 verified
  c2pa     [ok] c2pa manifest valid; payload hash bound
  rfc3161  [ok] timestamp from DigiCert (id-kp-timeStamping EKU valid)
  rekor    [ok] logIndex 4756641, inclusion proof valid
  iso_42001 [ok] risk_assessment=conducted, monitoring=BAAAR-gate, lifecycle=production
$ echo $?
0
```

[CUT: same verifier in a Python REPL on a different machine — also exit 0]

## 4:30–5:00  PUBLIC BENCH + CLOSING

[CUT: cargo test --release --features public-bench -- --nocapture]

[Output:
  TP=24 FP=0 FN=1 TN=25
  precision = 1.000
  recall    = 0.960  (target >= 0.85 ✓)
  FPR       = 0.000  (target <= 0.05 ✓)
  FP_reduction vs baseline = 100.0%  (target >= 20% ✓)
]

[CUT: black screen]

> "THEMIS doesn't just detect fraud — it proves it. Offline, in
> 30 seconds, for any auditor, any regulator, any court. BAAAR
> 10/10. 31/31 frameworks. themis-verify <30s."

[END CARD: themis.apohara.dev · github.com/SuarezPM/apohara-themis · MIT]

---

## Production notes

- 5 minutes, 30 fps → ~9000 frames. Render at 4K for the demo
  projector; upload to lablab as 1080p MP4.
- Voiceover recorded after the demo is rehearsed 3+ times;
  the judge should not see any stumbles.
- The 0:30 SponsorStack banner is the visual hook the judge
  remembers; the 3:30 themis-verify terminal is the wow
  moment (the verification is offline, real, and instant).
- No emoji in the video. Single font family. ≥14px text on
  every overlay. The "BAAAR 10/10" / "31/31" / "themis-verify <30s"
  counter cards are the visual verdict ladder.
