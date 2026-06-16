# THEMIS Demo Video Script

> 3-minute target. MP4 ≤5 min. 5 B-roll shots.
> Recording tool: OBS Studio (`apt install obs-studio` on Arch, `brew install --cask obs` on macOS, or ffmpeg + xdotol for headless).
> Output: `demo/video.mp4` (≤50 MB recommended), upload to YouTube unlisted or include as direct MP4 in lablab submission.

---

## Shot 1 (0:00-0:20) — HOOK

**Visual**: Black screen. Slow zoom into a HALT modal on a navy background with gold border.

**Voiceover** (no music, just calm voice):

> "Every year, enterprises lose billions to AP invoice fraud. Most AI systems flag suspicious invoices but can't prove it. THEMIS is different: 5 specialized agents in a single 2.1 megabyte Rust binary, debating every invoice in a Band chat room. When fraud fires, a deterministic kill-switch halts the process — and produces a cryptographically-signed, offline-verifiable evidence packet."

**B-roll**: Cut to the HALT modal firing in the browser (red border, "BAAAR HALTED — secret detected" message).

---

## Shot 2 (0:20-1:30) — DEMO ARC

**Visual**: Screen recording of `https://themis.apohara.dev/`. Pick the `wayne/inv-002` HALT fixture (or the strongest HALT fixture from the dropdown).

**Actions on screen** (narrate, don't read):

1. **Submit**: click "Run audit" on a Wayne Enterprises invoice. The dropdown should show "Wayne Enterprises · HALT · risk_score_exceeded (Globex double-spend)".
2. **Watch the debate**: scroll through the live transcript pane. Each `@mention` from the 5 agents is visible (extractor, PO matcher, fraud_auditor, GAAP classifier, provenance signer).
3. **HALT fires**: red border + modal says "BAAAR HALTED by FraudAuditor — risk_score 0.95 > 0.85 threshold".
4. **Compliance dashboard populates**: 26/26 green checkmarks across 4 framework columns.
5. **Download PDF**: click "Download Evidence". The PDF opens in a new tab. Page 1 shows a red HALT stamp + 5-condition matrix (the one that fired is checked, the other 4 are unchecked with their values). Page 2 shows the full 26-field compliance grid + the 8-agent decision trace.
6. **Scan QR code**: use a phone QR scanner on the QR code in the PDF footer. The phone opens `https://themis.apohara.dev/verify?packet=<uuid>&tenant=wayne`.

**Voiceover**:

> "Watch the 5 agents debate in the Band room. The fraud auditor raised risk_score to 0.95. The BAAAR gate fired. The 26-of-26 compliance dashboard populates. The PDF download shows a red HALT stamp with the exact 5-condition matrix — every condition evaluated, the firing one marked. Page 2 has the full field-level audit trail."

---

## Shot 3 (1:30-2:10) — OFFLINE VERIFY (the wow moment)

**Visual**: Terminal recording. Black background, monospace font. `pwd` shows a tmp directory.

**Commands** (type slowly, narrate each line):

```bash
$ ./target/release/themis-verify /tmp/evidence.json /tmp/evidence.sig
Reading packet: 06134473-c932-4810-ac21-ef786733ab45
Verifying Ed25519 signature against public key 9f2a...
Verifying BLAKE3 chain integrity... OK
Verifying Rekor v2 anchor (offline)...
  UUID: mock-uuid-1234567890abcdef
  log_index: 42
  integrated_time: 1718000000
  ✓ VERIFIED
```

**Voiceover**:

> "Offline verification. No network. Just the binary, the JSON, and the signature. The BLAKE3 chain, the Ed25519 signature, the Rekor v2 anchor — all verified locally in milliseconds. A regulator can audit this on a plane."

---

## Shot 4 (2:10-2:40) — ARCHITECTURE

**Visual**: GitHub repo screenshot. `cargo test --workspace` output. `cargo build --release` output (binary size: 2.1 MB).

**Voiceover**:

> "5 core agents plus 3 shadow agents. Ed25519 per-tenant keys baked at compile time — they survive Vercel's ephemeral filesystem. BLAKE3 chain. RFC 3161 timestamp. Rekor v2 transparency log anchor. All in 2.1 megabytes. No Python, no cloud lock-in. 298 tests pass, zero clippy warnings, zero apohara dependencies."

**B-roll to splice in**:
- `cargo test` output: `298 tests passed, 0 failed, 0 warnings`
- `ls -la target/release/themis-orchestrator` (binary size)
- Brief shot of the `crates/` directory structure
- THEMIS logo in the README

---

## Shot 5 (2:40-3:00) — CLOSING

**Visual**: Black screen with text.

**Text on screen**:

> THEMIS doesn't just detect fraud.
> It proves it.
> Offline. In milliseconds. For any auditor, any regulator, any court.
>
> themis.apohara.dev
> github.com/SuarezPM/apohara-themis

**Voiceover**: silence, just text on screen, 15 seconds.

---

## Production notes

- **Aspect ratio**: 16:9, 1920×1080 or 1280×720
- **Frame rate**: 30 fps
- **Audio**: 48 kHz mono, peak at -6 dB to avoid clipping
- **Music**: optional, low-energy ambient, fade in at 0:10, fade out at 2:40
- **Captions**: generate with YouTube auto-captions or hand-write
- **Export**: H.264, 8-12 Mbps bitrate, MP4 container
- **File size**: target 30-50 MB for 3 minutes at 1080p
- **Editing tool**: DaVinci Resolve (free), kdenlive, or ffmpeg command line

### Hard time gate

If the recording runs over 3:00, trim with:
```bash
ffmpeg -i raw.mp4 -t 180 -c copy final.mp4
```

### What NOT to include

- Don't show any login or signup flow (THEMIS has none)
- Don't show the slide deck (that's a separate artifact for the submission form)
- Don't include the `Cargo.toml` dependency list in detail (just the binary size)
- Don't promise features that aren't in the demo (Featherless, Rekor v2 live, ISO 42001)
- Don't say "we're the only ones who do X" — focus on what THEMIS does, not on competitors

### Post-production checklist

- [ ] Trim to ≤3:00
- [ ] Add THEMIS logo watermark in lower-right corner (optional)
- [ ] Add chapter markers: 0:00 Hook / 0:20 Demo / 1:30 Verify / 2:10 Architecture / 2:40 Closing
- [ ] Export at 8 Mbps H.264, 1080p, MP4
- [ ] Verify file ≤50 MB
- [ ] Upload to YouTube unlisted OR keep as MP4 for direct submission
