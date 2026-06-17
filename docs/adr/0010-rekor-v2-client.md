# ADR 0010 — Rekor v2 client: vendored .proto + tonic gRPC

**Status**: Accepted
**Date**: 2026-06-17
**Context**: THEMIS Rekor publish path (`crates/themis-evidence/src/rekor.rs`)

## Context

THEMIS needs to publish a transparency-log entry to Rekor for every signed
Evidence Packet. Today the production binary wires `MockRekorClient` only
(`crates/themis-orchestrator/src/bin/themis-orchestrator.rs:129`). The other
two impls are dead code: `CosignRekorClient` (shell-out to the deprecated v1
HTTP API) and `SigstoreVerifyRekorClient` (its `anchor()` is a synthetic
entry by design — comment at `rekor.rs:376-380`).

The hackathon demo claims "Rekor v2" (THREAT_MODEL.md, SPEC.md, AIBOM
strings). The current code does not back the claim. This ADR picks the
client stack for closing the gap.

## Decision

Use **vendored `.proto` files compiled at build time via `tonic-build` +
`prost`**, against the public-good Rekor v2 server
(`tlog.sigstore.dev:443`, service `TransparencyLogClient`).

### Stack (crates, pinned)

| Crate | Version | Role |
|---|---|---|
| `tonic` | `0.14` | gRPC over h2/TLS |
| `tonic-build` | `0.14` | `build.rs` codegen |
| `prost` | `0.14` | Protobuf codec |
| `prost-types` | `0.14` | `Timestamp`, etc. |

Versions verified against `crates.io` on 2026-06-17 (latest stable as of
that day). The planner's A1 estimate of "0.12 / 0.13" was off — the
ecosystem has moved. Bumping now avoids a forced bump in two PRs.

`sigstore-protobuf-specs` is **not** pinned as a runtime dep. The proto
files are vendored at `crates/themis-evidence/proto/rekor/v2/{tracing,
crypto}.proto` and the vendored copy pins the `v2.0.0-beta.X` tag of
`sigstore/protobuf-specs` (concrete tag to be chosen when the first client
impl lands; open question for Pablo).

### Why not the alternatives

- **Shell to `cosign rekor create`**: technically the most reliable
  *today*, but the v1 HTTP path is deprecated and the v2 gRPC surface is
  not yet wired in stable cosign. Defeats the "pure Rust" claim.
- **Shell to `rekor-cli`**: same problem. Also adds a binary dependency
  the deploy image must ship.
- **A speculative `rekor-client` crate**: not on crates.io at time of
  writing. Inventing our own crate is out of scope for a 1-day hackathon
  sprint.
- **REST gateway at `https://tlog.sigstore.dev/api/v2/...`**: the v2
  server's gRPC surface is the canonical API; the REST gateway is a
  thin shim. Going gRPC keeps one transport layer in the codebase.

### Production behavior

- `RekorV2Client::connect("tlog.sigstore.dev:443")` builds a TLS gRPC
  channel at startup. The channel is lazy (no I/O until first call), so
  startup is unaffected.
- `anchor()` calls `CreateSignedEntry` with the BLAKE3 digest of the
  Evidence Packet as a 32-byte body, plus the tenant's Ed25519
  public key and a signature over the canonical request bytes.
- `verify()` uses the embedded `sigstore-trust-root` TUF bundle (already
  in `Cargo.toml`) to validate the inclusion proof and the signed entry
  timestamp.
- Graceful degradation: if the gRPC call fails, the orchestrator logs a
  warning and continues without a Rekor entry (the existing behavior
  in `orchestrator.rs:402-422`).
- `THEMIS_REKOR_MODE` env var selects the client (`mock|v2|cosign`),
  defaulting to `mock` to keep the demo path byte-for-byte unchanged.

## Consequences

### Positive

- Real Rekor v2 publish from CI (release workflow) becomes possible
  end-to-end.
- `themis-verify` (offline) can see the Rekor UUID + log index via the
  new `rekor_entry` field on `SealedPacket`.
- The vendored protos survive Rekor v2 schema churn between betas;
  bumping a tag is a one-commit operation.

### Negative / risks

- Rekor v2 is in `v2.0.0-beta` territory; the proto wire may change.
  Pinning a specific tag is mandatory; tracking `main` is reckless.
- `tonic` + `prost` add ~3-5 MB to the binary and ~30s to clean
  rebuilds of `themis-evidence`. This is a real cost in a 30 MB binary
  budget; mitigated by `lto = "fat"` and `strip = "symbols"` (already
  configured in the workspace).
- The orchestrator now has a runtime dep on `tlog.sigstore.dev` being
  reachable. The graceful-degradation path is mandatory and tested.
- The gRPC server's behavior under keyless OIDC (Fulcio) is a moving
  target. The CI release job will exercise this on real tags; local
  test runs use a local Rekor v2 container.

## Open questions

1. Which `sigstore/protobuf-specs` tag to pin? (Beta, RC, stable?)
2. Should the CI release job use a real `cosign attest-blob` invocation
   (which depends on `tlog.sigstore.dev` being reachable from GHA
   runners) or wrap it in a retry with a fallback that logs and ships
   the release without a Rekor UUID?
3. Should `THEMIS_REKOR_ENDPOINT` be a stable runtime knob (so users
   can point at a private Rekor v2), or is `tlog.sigstore.dev:443`
   the only supported value for v1 of this feature?
