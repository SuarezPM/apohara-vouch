# THEMIS — References

> External specs, blog posts, and ADRs that back the claims made in
> `docs/SPEC.md` and `docs/threat-model.md`. Grouped by topic.

## Architecture Decision Records (ADRs)

- [`adr/0010-rekor-v2-client.md`](adr/0010-rekor-v2-client.md) —
  Rekor v2 client: vendored `.proto` + tonic gRPC. Picks the
  `dev.sigstore.rekor.v2.Rekor` service over the deprecated v1
  HTTP path; documents the `THEMIS_REKOR_MODE` env gate and the
  graceful-degrade contract (when Rekor is unreachable, the run
  continues and `SealedPacket.rekor_entry: Option<RekorEntry>` is
  `None`).

## Sigstore / Rekor

- [Rekor v2 GA blog post](https://blog.sigstore.dev/rekor-v2-ga/) —
  the announcement of the v2 transparency-log service shape
  (`dev.sigstore.rekor.v2.Rekor`). THEMIS pins the v2 wire via the
  vendored proto at `crates/themis-evidence/proto/rekor/v2/rekor.proto`
  (a consolidated subset, not the full rekor-tiles surface).
- [`sigstore/rekor-tiles`](https://github.com/sigstore/rekor-tiles) —
  upstream source for the v2 service definitions and the canonical
  JSON-over-gRPC mapping. THEMIS mirrors the field numbers and JSON
  field names; where the upstream proto dragged in googleapis
  annotations, the vendored copy strips them (see the file header
  in `rekor.proto`).

## Regulatory frameworks

- **DORA** — EU Regulation 2022/2554, Articles 9 (ICT risk
  management), 10 (incident detection), 17 (incident reporting).
- **EU AI Act** — EU Regulation 2024/1689, Articles 12 (record-keeping
  for high-risk AI), 26 (deployer obligations). Mandatory for
  high-risk AI systems from 2 August 2026.
- **NIST AI RMF 1.0** — Govern / Map / Measure / Manage functions.
- **OWASP Agentic 2026** — 10 ASI threats (ASI01–ASI10).
- **ISO/IEC 42001:2023** — AI Management System (AIMS) standard.
  Clauses 6.1 (risk assessment), 8.4 (impact assessment), 9.1
  (monitoring), 10.2 (continual improvement).

## Naming disambiguation

Apotheon THEMIS is a separate commercial product from a different
vendor (publicly documented in a 2026 whitepaper). THEMIS 2.0
(`apohara-themis`, this repository) is the open-source
Band-of-Agents hackathon entry. They share the Greek-mythology
naming convention but are unrelated projects: different code,
different architecture, different vendor, different domain.
This repository does not derive from Apotheon's code or
whitepaper.
