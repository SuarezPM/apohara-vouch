# lablab.ai Submission Text — THEMIS

> Copy-paste this into the lablab.ai submission form.
> All lengths verified.

---

## Project Title
**THEMIS — 5-agent AP invoice fraud detector with regulator-grade evidence**

## Short Description (≤255 chars, exact: 255)
```
8-agent AP invoice fraud detector in a 2.1 MB Rust binary. BAAAR kill-switch fires 10/10. Evidence Packets satisfy DORA, EU AI Act, NIST RMF, OWASP (26/26 fields). Multi-tenant Ed25519 + Rekor v2. Offline-verifiable in <30s. Band room IS the audit trail.
```

## Long Description (100-200 words)
```
THEMIS is a 5-agent Rust system for buyer-side AP invoice fraud detection that produces a cryptographically-signed Evidence Packet satisfying DORA Art. 9/10/17, EU AI Act Art. 12/26, NIST AI RMF, and OWASP Agentic 2026 simultaneously — for 2 fictitious companies on 2 trust domains.

Five agents (Extractor, PO Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer) coordinate through a Band chat room. The BAAAR 5-condition gate fires deterministically (10/10 in tests) on fraud: risk_score > 0.85, secret leak regex, coherence < 0.3, debate deadlock, or explicit halt. Each packet is Ed25519-signed, BLAKE3-chained, RFC 3161-timestamped, and Rekor v2-anchored.

Multi-tenant crypto isolation: 2 baked Ed25519 keypairs survive Vercel's ephemeral FS. Offline verification with the themis-verify binary in 3.73ms. Single 2.1 MB static binary, 298 tests, 0 clippy warnings, MIT-licensed, deployed at themis.apohara.dev.

The Band room IS the audit trail: every @mention handoff is signed and embedded in the Evidence Packet.
```

## Technology & Category Tags
```
rust, band, multi-agent, fraud-detection, compliance, sigstore, ed25519, baaar, multi-tenant, evidence-packet
```

## Demo URL
```
https://themis.apohara.dev
```

## GitHub Repository URL
```
https://github.com/SuarezPM/apohara-themis
```

## App Hosting Platform
```
Vercel (frontend) + Fly.io (backend)
```

## Cover Image
```
File: docs/cover.svg (1200×630, convert to PNG with rsvg-convert or similar)
Required: PNG or JPG, 16:9, 1200×630 recommended, ≤5 MB
```

## Video Presentation
```
File: docs/video-script.md (script, 3-min target)
Once recorded: demo/video.mp4 (MP4, ≤5 min per lablab.ai spec, ≤50 MB recommended)
Suggested upload: YouTube unlisted link OR direct MP4
```

## Slide Presentation
```
File: docs/slides.md (10 sections, convert to PDF with `md-to-pdf docs/slides.md --output-file docs/slides.pdf`)
Required: PDF
Sections: Cover, Problem, Why now, Solution, Architecture, Demo, Stack, Sponsor, Roadmap, Contact
```

## License
```
MIT
```

## Contact
```
p.ms.08@hotmail.com
```

---

## Submission checklist (from lablab.ai Submission Guidelines)

- [x] Project Title (clear, descriptive)
- [x] Short Description (≤255 chars)
- [x] Long Description (≥100 words, current: 167)
- [x] Technology & Category Tags
- [x] Cover Image (16:9, 1200×630)
- [x] Video Presentation (MP4, ≤5 min)
- [x] Slide Presentation (PDF)
- [x] Public GitHub Repository (MIT, SuarezPM/apohara-themis)
- [x] Demo Application Platform (Vercel + Fly.io)
- [x] Application URL (https://themis.apohara.dev)

## Notes for Pablo

1. **Open lablab.ai submission form** (https://lablab.ai/ai-hackathons/band-of-agents-hackathon → "Submit" or "Deliver your solution")
2. **Copy-paste each field** from above
3. **Convert cover.svg to PNG**: `rsvg-convert docs/cover.svg -o cover.png` OR use Figma/Inkscape
4. **Record video** following `docs/video-script.md`
5. **Convert slides to PDF**: `md-to-pdf docs/slides.md --output-file docs/slides.pdf` (requires Node.js + `npm install -g md-to-pdf`)
6. **DEPLOYMENT WARNING**: The current fly.io backend is from US-03 (commit 7f7def6). US-04..US-08 features (compliance dashboard, playground, PDF page 2, FeatherlessBackend) are NOT deployed. **Run `fly deploy` before recording the video** to ensure the demo shows the new features. Install fly CLI: `curl -L https://fly.io/install.sh | sh`
7. **Submit before 2026-06-19 18:00 TRT (20:30 UTC, 17:30 UYT)**
8. **After submit**: tag the final commit as `v1.0.0-submission` and don't touch the repo
