# Security Policy

## Supported Versions

| Version | Supported          | EOL          |
|---------|--------------------|--------------|
| 0.1.x   | :white_check_mark: | 2026-12-31   |
| < 0.1   | :x:                | retired       |

## Reporting a Vulnerability

**Please DO NOT file a public issue.** Email `p.ms.08@hotmail.com` (the maintainer)
with:

- A clear description of the vulnerability
- Reproduction steps (proof-of-concept preferred)
- Affected component (which crate, which version)
- Whether you've disclosed it elsewhere

PGP key: not yet available; contact via email to arrange out-of-band exchange.

We commit to:

- **Acknowledge** your report within 72 hours.
- **Triage** within 7 days, with a severity rating and a timeline.
- **Fix** critical/high issues within 30 days; medium within 90 days; low
  on a best-effort basis. Disclosure timeline is coordinated with you.
- **Credit** you in the security advisory unless you request anonymity.

## Threat Model

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the in-scope / out-of-scope
analysis (the model that produced the security guarantees in the
`SECURITY.md` claims and the `ROADMAP.md` risk register).

## Cryptographic Primitives

THEMIS uses well-known primitives from the RustCrypto + official
sigstore ecosystems. **Do not** roll your own crypto.

| Use case         | Algorithm         | Library               | Rationale                |
|------------------|-------------------|-----------------------|--------------------------|
| Signatures       | Ed25519           | `ed25519-dalek` 2     | std for short PIDs       |
| Hash chain       | BLAKE3            | `blake3` 1            | faster + safer than SHA-2|
| Timestamps       | RFC 3161          | `rfc3161ng` 0.1       | standard TSA protocol    |
| Transparency log | Rekor v2          | `cosign` (shell)      | sigstore-standard       |

## Security Posture (as of June 2026)

- **OpenSSF Scorecard**: target ≥ 7.4 (in progress, see scorecard.yml)
- **Band of Agents Hackathon**: 12-19 June 2026 deadline
- **License**: MIT
- **SLSA Build Level**: target L3 (reusable attestation workflow,
  see agentguard's pattern)
- **Supply chain**: `cargo-deny` enforced (deny.toml), pre-commit
  hook installed (scripts/pre-commit.sh)

## Hall of Fame

No public reports yet. Be the first.
