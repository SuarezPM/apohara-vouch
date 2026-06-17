# THEMIS Demo Video Script (v2 — post-Track-8..12)

> **Target**: 3 min, MP4 ≤5 min. **Recording tool**: OBS Studio
> or ffmpeg + xdotool. **Output**: `demo/video.mp4` (≤50 MB).
>
> **v2 changes vs v1**: added Band room transcript, adversarial
> dispute protocol, 3 regulator-visible live metrics, DSSE
> envelope, FreeTSA real RFC 3161 timestamp. The wow moment
> (Shot 3) is now the dispute resolution + the live
> regulator metrics flipping green.

---

## Shot 1 (0:00-0:18) — HOOK

**Visual**: Black screen → slow zoom into the BAAAR HALT
modal (red border, gold accent, "WORKFLOW HALTED — secret
detected — judge: download the receipt to verify offline").

**Voiceover**:

> "Every year, enterprises lose billions to AP invoice
> fraud. Most AI systems flag suspicious invoices but
> can't prove it. THEMIS is different: 5 specialized
> agents in a single 2.1 MB Rust binary, debating every
> invoice in a Band chat room with real @mention routing.
> When two agents disagree, the coordinator rules. When
> fraud fires, a deterministic kill-switch halts the
> process — and produces a cryptographically-signed,
> offline-verifiable evidence packet that a regulator
> can re-verify with no network."

**B-roll**: HALT modal in the browser.

---

## Shot 2 (0:18-1:25) — DEMO ARC

**Visual**: Screen recording of `https://themis.apohara.dev/`.
Pick `wayne/inv-002` HALT fixture.

**Actions on screen** (narrate):

1. **Submit**: click "Run audit" on a Wayne invoice.
2. **Watch the Band transcript** (NEW): the right pane
   scrolls, showing each agent's message and the
   `@mention` they sent to the next agent. Extractor's
   message carries `@fraud_auditor`, FraudAuditor's
   carries `@gaap_classifier`, etc. The handoff is
   visible in real time.
3. **Dispute fires** (NEW wow moment): the live
   transcript shows a `DISPUTE: @fraud_auditor risk=0.91
   vs @gaap_classifier risk=0.42 (delta=0.49) → ruling:
   halt` line, posted by `coordinator`. The DORA clock
   tile flashes red and starts the 72h countdown.
4. **BAAAR HALT fires**: red border, modal "BAAAR HALTED
   by FraudAuditor — risk_score 0.95 > 0.85 threshold".
5. **Regulator metrics flip green** (NEW): the 3 live
   tiles — DORA Art. 17 clock (now showing the
   deadline), EU AI Act Art. 12 (8/8 ✓), NIST AI RMF
   (4/4 ✓) — all light up green.
6. **Compliance dashboard**: 30/30 green checkmarks
   across 6 framework columns (DORA, EU AI Act, NIST
   AI RMF, OWASP Agentic, **ISO 42001** — NEW).
7. **Download PDF**: PDF opens, page 1 has the red HALT
   stamp + 5-condition matrix, page 2 has the 30-field
   compliance grid + 8-agent decision trace.
8. **QR code**: scan with phone → opens
   `https://themis.apohara.dev/verify?packet=<uuid>&tenant=wayne`.

**Voiceover**:

> "Five agents in a Band room. Each message carries an
> @mention for the next agent in the pipeline. Watch the
> transcript — the fraud auditor and the GAAP classifier
> disagree by 0.49 on this invoice. The coordinator
> halts. The DORA Art. 17 72-hour reporting clock
> starts. The EU AI Act and NIST AI RMF tiles flip
> green — six frameworks, thirty fields populated, by
> construction, not by retrofit. The PDF carries the
> red HALT stamp, the five-condition matrix, and the
> full audit trail. The QR code points to the offline
> verifier."

---

## Shot 3 (1:25-2:05) — OFFLINE VERIFY (the technical proof)

**Visual**: Terminal. Monospace. Black background.

**Commands** (narrate each line):

```bash
$ ./target/release/themis-verify /tmp/packet.json
Reading SealedPacket: 06134473-c932-4810-ac21-ef786733ab45
DSSE envelope: payloadType=application/vnd.apohara.themis.entry+json
                signatures=1 (keyid=9f2a1b4c...)
                payload=base64url(324 bytes)
Decoding payload (RFC 8785 JCS canonical JSON)... 324 bytes
BLAKE3 hash:    7a3b4c...   (matches packet.blake3_hash_hex)
Ed25519 sig:     b4d5e6...  (verified against public key)
RFC 3161 timestamp: 1718662400 (FreeTSA freetsa.org)
Rekor v2 anchor: log_index=42, integrated_time=1718662401
BLAKE3 chain:    7 entries, sequence-monotonic, prev_hash linked
EU AI Act Art.12: 8/8 fields populated
NIST AI RMF:      4/4 functions traced
ISO 42001:2023:   4/4 clauses (6.1, 8.4, 9.1, 10.2)
Sigstore verify:  signature chain valid
✓ VERIFIED — packet is tamper-evident and timestamped
```

**Voiceover**:

> "Offline verification. No network. Just the binary, the
> JSON, the DSSE envelope. The auditor can re-verify
> the Ed25519 signature, the BLAKE3 chain, the FreeTSA
> RFC 3161 timestamp, the Rekor transparency log
> anchor — all locally, in milliseconds. The packet is
> tamper-evident by construction."

---

## Shot 4 (2:05-2:35) — ARCHITECTURE

**Visual**: GitHub repo. `cargo test --workspace` output.
`cargo build --release` output. `crates/` directory.

**Voiceover**:

> "Eight agents — five core, three shadow — coordinated
> through Band. Ed25519 per-tenant keys, baked at
> compile time, survive the ephemeral filesystem. Six
> compliance frameworks, including the new ISO 42001
> AIMS. Adversarial dispute protocol based on the
> Self-Anchored Consensus paper. Real RFC 3161
> timestamps from FreeTSA. Sigstore-verify 0.8 with
> the embedded trust root — no cold-start network
> fetch. All in 2.1 megabytes of Rust. Three hundred
> thirty-eight tests, zero clippy warnings, no
> Python, no cloud lock-in."

**B-roll**:
- `cargo test --workspace` output: 338 tests passed, 0 failed
- `ls -la target/release/themis-orchestrator` (binary size)
- `crates/` structure: agents, band-client, compliance,
  compressor, evidence, frontend, orchestrator

---

## Shot 5 (2:35-3:00) — CLOSING

**Visual**: Black screen. White text.

**Text on screen**:

> THEMIS doesn't just detect fraud.
> It proves it.
> Offline. In milliseconds. For any auditor, any regulator, any court.
>
> Six frameworks. Eight agents. One signed packet.
>
> themis.apohara.dev
> github.com/SuarezPM/apohara-themis

**Voiceover**: silence, 15 seconds of text on screen.

---

## Production notes (v2)

- **Aspect ratio**: 16:9, 1920×1080 or 1280×720
- **Frame rate**: 30 fps
- **Audio**: 48 kHz mono, peak at -6 dB
- **Music**: optional, low-energy ambient
- **Export**: H.264 8-12 Mbps, MP4, ≤50 MB for 3 min @ 1080p
- **Editing**: DaVinci Resolve (free), kdenlive, or ffmpeg

### Hard time gate

```bash
ffmpeg -i raw.mp4 -t 180 -c copy final.mp4
```

### What NOT to include

- No login flow (THEMIS has none)
- No `Cargo.toml` dependency list (just the binary size)
- No "we're the only ones" claims — focus on what THEMIS does
- No marketing claims that aren't backed by the demo

### Post-production checklist

- [ ] Trim to ≤3:00
- [ ] Add chapter markers: 0:00 Hook / 0:18 Demo / 1:25 Verify / 2:05 Architecture / 2:35 Closing
- [ ] Verify the dispute protocol fires in Shot 2 (use a fixture that triggers it; test before recording)
- [ ] Verify the 3 regulator metrics tiles are visible in Shot 2
- [ ] Verify the ISO 42001 column appears in the compliance dashboard
- [ ] Verify the DSSE envelope + FreeTSA timestamp appear in the verify output (Shot 3)
- [ ] Export at 8 Mbps H.264, 1080p, MP4
- [ ] File ≤50 MB
