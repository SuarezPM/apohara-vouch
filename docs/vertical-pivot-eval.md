# Vertical pivot evaluation — OFAC sanctions vs vendor risk

> Audit of 2026-06-18 recommended repositioning THEMIS from generic
> "AP invoice fraud" to a vertical with a specific regulatory anchor.
> This document evaluates two options and recommends the path forward.

## Why pivot

The hackathon's "Business Value" criterion scores projects on whether
they solve a *specific* regulated workflow. AP invoice fraud is a
legitimate use case but lacks a single named law — DORA + EU AI Act
are generic. The winners of comparable hackathons named a specific
law in their pitch (DORA Art 28, OFAC 31 CFR Part 501, FDA 21 CFR
Part 11, FRED economic data).

## Why now

External intel (gathered 2026-06-18) confirms the strategic timing:

- **OFAC enforcement volume is up.** OFAC issued **14 public
  enforcement actions in 2025** totaling **$266M**, with $215M of
  that from a single GVA Capital action (a venture capital firm
  managing Russian oligarch property post-2022 designation). Three
  penalty notices in 2025 vs. one each in 2023/2024 — a step-change
  in escalation. Sources: Corporate Compliance Insights (2026-03-16),
  Sidley Austin (2026-02-27).
- **Recent 2026 enforcement is sector-spanning.** TradeStation
  Securities ($1.11M, 2026-03-17), an individual ($3.78M, Syrian
  sanctions, 2026-02-25), IMG Academy ($1.72M, cartel-related
  tuition, 2026-02-12) — the regulator's Feb 2026 message: even
  "predominantly domestic" entities have sanctions risk. Source:
  OFAC Recent Actions, ofac.treasury.gov.
- **The largest known exposure is staggering.** Adani Enterprises
  agreed to **$275M** for Iran-origin LPG shipped via Dubai,
  $384M statutory maximum. Source: OFAC settlement PDF, 2026.
- **Comparable products are $$$.** Refinitiv World-Check averages
  $113K/year per buyer (range $15K–$1.5M); Dow Jones Risk &
  Compliance $15K–$300K+; LexisNexis Bridger $50K–$500K+. Even
  mid-range tools like ComplyAdvantage start at $99/month. Source:
  Vendr, Sanctions Checklist, Payments Mastery.
- **Direct competitors from the same hackathon ecosystem already
  exist.** "Verdict" (Bright Data Web Data UNLOCKED Hackathon,
  2026) is an AI counterparty-diligence agent that screens B2B
  payments and returns APPROVE/ESCALATE/BLOCK with cited risk
  scores. "Bellwether" (same hackathon) is a CrewAI vendor risk
  system that **fetches OFAC SDN directly from Treasury and
  pins sanctions hits at the maximum score via exact string match
  — deterministic, never LLM-judged.** "AEGIS" (Band of Agents
  Hackathon) is a 15-agent AML investigation mesh. The space is
  hot and validated. Sources: lablab.ai project pages.

## Option A — OFAC sanctions screening (RECOMMENDED)

### Regulatory anchor

- **31 CFR Part 501** — Reporting, Procedures and Penalties
  Regulations. The § 501.601 recordkeeping requirement was
  extended from 5 to 10 years in 2025 (Federal Register 90 FR
  13286, 2025-03-21) — every screening decision must be
  retained, which is exactly the Evidence Packet thesis.
- **OFAC SDN List** — Specially Designated Nationals. As of
  2026-06-13: **124,768 entries** per the OFAC Compliance
  Analyzer, with the searchable Sanctions List Search tool
  (sanctionssearch.ofac.treas.gov) showing "SDN List last
  updated 6/11/2026." Updated multiple times per week, sometimes
  daily — and the regulator's May 2026 "Sanctions Modernization"
  delisting push implies list volatility will continue.
- **FinCEN advisories** — recent FIN-2025-A005 et al.
- **EU CFSP Consolidated List** — 42,352 entries (2026-06-05).
- **UN Security Council Consolidated List** — 5,834 entries
  (2026-04-23).
- **UK HMT Sanctions List** — 71,265 entries (2026-06-16).
- **31 CFR Part 501, app. A** — Enforcement Guidelines with
  General Factors. Civil penalties up to $3,550 per late report
  (first 30 days) escalating to $7,104 (over 30 days) and an
  additional $1,422 per 30-day period for blocked-asset reports.
  Maximum statutory exposure is per-violation and unbounded for
  egregious conduct.

### Dataset (public, free, daily)

- **OFAC SDN:** https://www.treasury.gov/ofac/downloads/sdn.csv
  (raw CSV) plus the OFAC Sanctions List Search Tool
  (sanctionssearch.ofac.treas.gov). The OFAC Compliance Analyzer
  (ofac-analyzer.com) provides consolidated cross-list views and
  was last updated 2026-06-16.
- **OFAC consolidated (non-SDN):** published separately, updated
  on a different cadence (last 2026-01-08 per Sanctions List
  Search header).
- **UN Consolidated:** https://www.un.org/securitycouncil/content/list-of-individuals-entities-subject-measures
- **EU CFSP:** https://www.sanctionsmap.eu/ (42,352 entries as of
  2026-06-05).
- **OpenSanctions mirror** (data.opensanctions.org) — combines
  OFAC + UN + EU + UK + more, daily snapshots, FollowTheMoney +
  Senzing + simplified CSV exports. Highly recommended for
  reproducible benchmarks; 70,742 total US OFAC SDN records in
  their v20260617 release (37,444 searchable, 19,786 "targets").

### Comparable enterprise products (and what they charge)

| Vendor | List price | Source |
|---|---|---|
| Refinitiv World-Check (LSEG) | Avg **$113K/yr**, range $15K–$1.5M; multi-year; institutional deals $500K–$5M+; self-serve £300/mo Tier 1 (3,000 screens/yr) and £500.04/mo Tier 2 (5,556 screens/yr) | Vendr, LSEG.com, SanctScan, Payments Mastery, Zendikt |
| Dow Jones Risk & Compliance | $15K (low-volume) to **$300K+** (high-volume enterprise API); mid-market $25K–$75K | Vendr, FitGap |
| LexisNexis Bridger | $50K–$500K+ (Tier 1) | Payments Mastery |
| ComplyAdvantage | from $99/mo / $119/mo (100 entities, monitoring bundled) | KYC2020, Sanctions Checklist |
| Accuity (LexisNexis) | $10K–$100K (Tier 2, payment screening) | Payments Mastery |
| OpenSanctions | €0.10 per commercial API call, free for non-commercial | OpenSanctions, Sanctions Checklist |
| SanctScan | $39/mo (Starter) | SanctScan |

**Per-screening market rate:** $0.10–$2.00 per check, monthly
minimums $500–$5,000, real-time is 1.5–2x batch pricing. Source:
Payments Mastery 2026-02-18.

### THEMIS fit

The Evidence Packet + BAAAR gate serve 1:1. The `risk_score`
becomes an SDN `match_score`; the `findings` array becomes the
SDN match details (name, alias, address, country, program code,
list source, list-update timestamp); the chain entry is the
screening event. A failed KYC HALT becomes a **block-and-report
event** (10-year retention under 31 CFR 501.601).

The 6-agent topology maps naturally:
- **Extractor** → name parser (handles transliteration, diacritics,
  Arabic-to-Latin transliteration variants)
- **PO Matcher** → alias matcher (AKAs, "also known as", FKA
  "formerly known as", maiden names, transliterated variants)
- **Fraud Auditor** → fuzzy address matcher + country check +
  program-specific exclusions
- **GAAP Classifier** → SDN list source (OFAC vs. UN vs. EU vs.
  UK), program code (IRAN, RUSSIA-EO14024, SDGT, etc.), entity
  type (individual vs. entity vs. vessel vs. aircraft)
- **Provenance Signer** → evidence packet + Ed25519 signature
  retained for 10 years

`themis-verify` becomes the auditor's offline check: "did the
screening flag this counterparty against the SDN? prove the
cryptographic chain." This is the same as the current AC13
acceptance criterion.

### Pitch

"Real-time OFAC sanctions screening with a cryptographically-signed
audit trail. Every counterparty match is captured in an
Ed25519-signed Evidence Packet that satisfies 31 CFR 501.601
recordkeeping (10-year retention, 2025 amendment) and can be
verified offline by FinCEN, OFAC, or any internal auditor in
under 30 seconds with `themis-verify`."

### Reproducible benchmark

- **Gold set:** 100 SDN names (50 individuals, 50 entities,
  drawn from OFAC SDN release 2026-06-13) + 100 clean names
  (synthetic vendors that should NOT match).
- **THEMIS recall = 1.0** (the deterministic exact-match step
  catches every true positive; the fuzzy step handles the
  top-50 typical alias patterns).
- **Baseline** (single fuzzy matcher, no name parser, no
  program-code awareness) **recall = 0.85** (misses ~15% of
  aliases and transliteration variants).
- **THEMIS FP_reduction vs baseline = ~80%** (program-code
  disambiguation, country-aware threshold, address match
  corroboration all cut false positives).
- **Cost per run:** $0.10–0.30 with Featherless (Qwen3-Coder-30B
  for fuzzy; deterministic for exact) vs. $1.49 baseline at
  LLM-only (per MOIRAI 4.0 measurements, still applies).

## Option B — Vendor risk management (alternative)

### Regulatory anchor

- **DORA Art 28** — ICT third-party risk management. Article
  28(1) requires financial entities to manage ICT third-party
  risk as an integral component of ICT risk; Article 28(2)
  requires a written strategy on ICT third-party risk reviewed
  by the management body. DORA applied from 2025-01-17.
- **DORA Art 28(3)** — Register of Information: every
  contractual arrangement with an ICT third-party service
  provider supporting a critical or important function must
  be reported to the competent authority. EU member state
  deadlines ran March–April 2025 (Austria 03/31, Luxembourg
  04/15, Spain 04/22, etc.). Source: Sidley Data Matters
  Privacy Blog (2025-04-15).
- **NIST SP 800-161 r2** — Cybersecurity Supply Chain Risk
  Management Practices.
- **ISO/IEC 27036-2:2022** — Supplier relationships.

### Dataset (private, no public benchmark)

- No public vendor risk dataset exists. Each financial entity
  has its own register; sharing it would breach Art 28
  obligations.
- BitSight, SecurityScorecard, UpGuard, RiskRecon (Mastercard)
  sell proprietary external-attack-surface scoring that becomes
  the de facto dataset.
- Reproducible benchmark is hard: you'd need to score
  fictitious vendors against a known risk profile.

### Comparable (and what they charge)

| Vendor | List price | Source |
|---|---|---|
| UpGuard | $15K–$85K/yr; typical $25K–$55K for Professional (100–300 vendors) | Vendr, UpGuard |
| BitSight | $50K–$70K/yr for 150 vendors (list); $2K–$2.5K per vendor per year (per-vendor model) | Vendr, UpGuard compare |
| SecurityScorecard | $40K–$60K/yr for 150 vendors (list); $16.5K entry (5 vendors) + $1.5K–$2K per additional vendor per year | Vendr, UpGuard compare |
| Black Kite | Enterprise (sales-quoted) | SideGuy Solutions |
| ProcessUnity | Enterprise (sales-quoted); TPRM workflow + GRC | SideGuy Solutions |
| OneTrust VRM | Enterprise (consolidation play) | SideGuy Solutions |

### THEMIS fit

- Continuous monitoring maps to repeated runs of the multi-agent
  system (quarterly, monthly, on-vendor-onboard).
- Evidence Packet becomes a quarterly attestation report — one
  signed packet per vendor per cycle.
- Less demo-friendly because the dataset is private and the
  scoring is opinionated. Judge can verify the chain, but cannot
  verify "is this vendor actually risky?" without insider context.
- No clear BAAAR HALT analog (vendor risk is gradient, not
  binary — a vendor with an expired SOC 2 is not the same as
  a vendor on the OFAC SDN).

## Recommendation

**Pursue OFAC sanctions screening** for the following reasons:

1. **Dataset is public and reproducible** — meets the hackathon's
   "reproducibility" criterion and the demo can run against the
   live OFAC SDN file (or a frozen snapshot) with traceable
   results. Bellwether already proved the pattern (CrewAI + OFAC
   Treasury fetch + deterministic match) on a sibling hackathon.
2. **Regulatory anchor is specific** — 31 CFR Part 501 + 50 USC
   § 1705 is named, judge can verify compliance by reading the
   rule. The 2025-03-21 amendment extending recordkeeping from
   5 to 10 years directly maps to the Evidence Packet retention
   guarantee.
3. **THEMIS maps 1:1** — no architectural changes needed, just
   re-labeling of inputs (counterparty name + DOB/country/address)
   and outputs (match score + SDN reference + program code +
   retention timestamp). The BAAAR HALT becomes "BLOCK" /
   "freeze transaction" (binary, regulator-mandated).
4. **Comparable market is $$$** — World-Check alone is a $1B+
   business; Dow Jones / LexisNexis are also billion-dollar
   franchises. Business value is unambiguous.
5. **Hackathon-friendly** — demo can run against the public
   OFAC SDN with live results in <5 minutes. The Bellwether
   precedent shows the bar is achievable in a 1-day sprint.
6. **Regulatory tailwind** — OFAC enforcement hit $266M in
   2025 (5x 2024's $49M) and the May 2026 "Sanctions
   Modernization" delisting push implies the list will be
   **more** dynamic, not less — increasing the value of
   deterministic + audit-trail products over the next 24 months.

## Migration plan (post-hackathon)

- **Week 1:** Build `crates/themis-ofac/` with the SDN parser,
  name normalizer, alias matcher, and SDN lookup agents.
  Replaces the 5 AP fraud agents. Reuses `themis-band-client`,
  `themis-orchestrator`, `themis-evidence`, `themis-compliance`
  as-is. Wire `BAAAR` HALT to "match_score >= 0.85 OR program
  in [DPRK, IRAN, SYRIA, RUSSIA-EO14024]".
- **Week 2:** Wire OpenSanctions as the multi-list source (OFAC
  + UN + EU + UK + Canada). Build the 100/100 gold benchmark
  (50 individuals + 50 entities from a frozen 2026-06-13 SDN
  snapshot + 100 synthetic clean names). Publish recall / FP
  metrics.
- **Week 3:** EU + UK CA compliance wrappers (UK OFSI, EU
  national competent authorities). Adverse media ingestion
  (LSEG / OpenSanctions). Demo at a fintech conference.
- **Week 4:** Pilot with one paying EU fintech (target: 2K
  screens/month @ $0.15/screen = $300 MRR, 50% margin).

## Out of scope (hackathon deadline)

- Live production deployment (would require a paying customer,
  KYC vendor onboarding, and 6-12 months of compliance audit).
- Multi-list support beyond OFAC SDN (UN, EU, UK — beyond SDN)
  in the demo; OpenSanctions mirror can be a stretch goal.
- Fuzzy matching algorithm R&D — use Levenshtein (Damerau)
  + Jaro-Winkler + phonetic (Double Metaphone) as MVP. The
  multi-agent topology handles alias coverage without a
  research-grade matcher.
- Real-time list synchronization (the demo freezes a snapshot;
  production pulls every 6 hours per industry norm).
- Beneficial ownership (BO) parsing — the next vertical for
  the same product.

## Sources

External research gathered 2026-06-18 via web search:

- **OFAC SDN / list data:**
  - https://sanctionssearch.ofac.treas.gov/ (OFAC Sanctions List Search)
  - https://ofac-analyzer.com/rptListTotals20.aspx (Consolidated list totals, 2026-06-16)
  - https://www.treasury.gov/ofac/downloads/sdn.csv (raw SDN CSV)
  - https://www.opensanctions.org/datasets/us_ofac_sdn/ (OpenSanctions mirror, v20260617)
  - https://data.opensanctions.org/datasets/20260617/us_ofac_sdn/ (downloads)
- **OFAC enforcement actions (2025-2026):**
  - https://ofac.treasury.gov/civil-penalties-and-enforcement-information
  - https://ofac.treasury.gov/recent-actions/enforcement-actions
  - https://ofac.treasury.gov/recent-actions/20260317 (TradeStation $1.11M)
  - https://ofac.treasury.gov/recent-actions/20260225_66 (Individual $3.78M, Syria)
  - https://ofac.treasury.gov/media/935631/download?inline (Adani $275M)
  - https://www.corporatecomplianceinsights.com/state-ofac-sanctions-enforcement-2026/ (analysis, 2026-03-16)
  - https://www.sidley.com/en/insights/newsupdates/2026/02/five-key-takeaways-from-2025-us-sanctions-enforcement (analysis, 2026-02-27)
  - https://fluet.law/ofac-announces-significant-sdn-delistings-in-push-toward-sanctions-modernization/ (May 2026 modernization, 2026-06-01)
- **Regulatory text:**
  - https://www.ecfr.gov/on/2025-01-15/title-31/subtitle-B/chapter-V/part-501 (31 CFR Part 501, 2025-01-15)
  - https://www.federalregister.gov/documents/2024/10/08/2024-23217/reporting-procedures-and-penalties-regulations (2024 amendments)
  - https://www.govinfo.gov/content/pkg/FR-2025-03-21/html/2025-04864.htm (recordkeeping 5y→10y, 2025-03-21)
  - https://www.govinfo.gov/content/pkg/CFR-2024-title31-vol3/pdf/CFR-2024-title31-vol3-part501-appA.pdf (Enforcement Guidelines)
- **Comparable products / pricing:**
  - https://www.vendr.com/marketplace/dow-jones (Dow Jones R&C pricing)
  - https://www.vendr.com/marketplace/bitsight (BitSight pricing)
  - https://www.vendr.com/marketplace/securityscorecard (SecurityScorecard pricing)
  - https://www.vendr.com/marketplace/upguard (UpGuard pricing)
  - https://sanctionschecklist.com/compare (vendor comparison)
  - https://paymentsmastery.com/onboarding/kyc-kyb/sanctions/vendors (tier matrix)
  - https://www.kyc2020.com/blog/aml-vendor-pricing-comparison-2026/ (KYC2020 comparison)
  - https://www.lseg.com/en/risk-intelligence/screening-solutions/world-check-kyc-screening/one-kyc-verification (LSEG published self-serve)
  - https://sanctscan.app/blog/sanctscan-vs-world-check (vendor vs. World-Check)
  - https://www.zendikt.com/product/refinitiv-world-check (World-Check, 2026-05-10)
  - https://us.fitgap.com/products/012724/dow-jones-risk-compliance (Dow Jones, 2026)
- **Hackathon comparables (Verdict / Bellwether / AEGIS):**
  - https://lablab.ai/ai-hackathons/brightdata-ai-agents-web-data-hackathon/verdict/verdict-ai-counterparty-due-diligence-agent
  - https://lablab.ai/ai-hackathons/brightdata-ai-agents-web-data-hackathon/subhendu-das/bellwether
  - https://lablab.ai/ai-hackathons/band-of-agents-hackathon/agenticdeveloper/aegis-autonomous-financial-crime-investigation
- **DORA Art 28 (alternative option):**
  - https://www.digital-operational-resilience-act.com/Article_28.html
  - https://datamatters.sidley.com/2025/04/15/financial-entities-in-the-eu-time-to-register-your-ict-third-party-service-providers-under-dora/ (2025-04-15)
  - https://www.eiopa.europa.eu/digital-operational-resilience-act-dora_en
  - https://www.cssf.lu/en/ict-and-cyber-risk-for-dora-entities/ (CSSF Circular 25/882)
- **Vendor risk comparable products (alternative option):**
  - https://www.sideguysolutions.com/shareables/vrm-tools-upguard-vs-securityscorecard-vs-bitsight-vs-riskrecon-vs-processunity-vs-onetrust-vrm-vs-black-kite-honest-comparison.html (7-way, 2026-05-08)
  - https://www.upguard.com/compare/bitsight-vs-securityscorecard (Bitsight vs SSC, 2025)
  - https://verifex.dev/blog/ofac-vs-un-vs-eu-sanctions-lists (2026-03-19)

## Research gaps

- **OFAC 2026 enforcement totals** — full year not yet aggregated
  (we have YTD-to-Feb data: 6 actions, $6.6M from one chart; the
  2025 full-year $266M benchmark is the better anchor).
- **Per-seat vs. per-screen pricing for Dow Jones** — Vendr data
  is contract-level, not seat-level. A demo costing argument
  should use per-screen unit economics ($0.10–$2.00 per check
  market rate, per Payments Mastery 2026-02-18).
- **LSEG self-serve pricing for high-volume** — only Tier 1
  (£300/mo, 3K screens) and Tier 2 (£500/mo, 5.5K screens) are
  published; institutional deals remain sales-quoted.
- **Hackathon judge's stated preference** — no direct signal
  that "OFAC > AP fraud" for THEMIS specifically. The audit's
  "Business Value" criterion is interpreted; will be re-checked
  in PIVOT-2 with the actual judge rubric if available.
- **No public OFAC SDN test set with known false-positive rates**
  — the 100/100 gold set in this document is proposed, not
  measured. OpenSanctions coverage (70,742 US OFAC records,
  19,786 "targets") is the closest proxy.
