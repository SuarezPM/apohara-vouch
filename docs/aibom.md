# AIBOM — AI Bill of Materials (CycloneDX 1.6)

> Story C-16a / G13 + G17. THEMIS 3.0 emits a CycloneDX 1.6 AIBOM alongside
> every Evidence Packet so external auditors (and the EU AI Act Art. 13
> supply-chain probe) can verify exactly what was used in a run.

## What is in the AIBOM

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "machine-learning-model",
      "name": "claude-sonnet-4-5",
      "version": "2025-11-01",
      "modelCard": {
        "modelParameters": {
          "architecture": "transformer-decoder",
          "provider": "AI/ML API (Anthropic-compatible)",
          "context_window_tokens": 200000,
          "supports_tool_use": true,
          "supports_vision": false,
          "training_data_cutoff": "2025-10"
        },
        "intendedUse": "Primary orchestrator LLM for THEMIS 3.0: agent reasoning, fraud-signal classification, and provenance narrative generation.",
        "limitations": [
          "May produce plausible-but-false fraud rationales; BAAAR gate is the only enforcement.",
          "Not trained on tenant-specific PO data; cross-tenant generalization is not guaranteed."
        ]
      },
      "datasets": [
        {
          "type": "data",
          "name": "invoicenet-1k",
          "size_bytes": 4194304,
          "license": "unknown",
          "provenance": "Stanford InvoiceNet, sampled 2026-05 by themis-orchestrator public-bench harness."
        }
      ]
    },
    {
      "type": "machine-learning-model",
      "name": "qwen3-coder-30b",
      "version": "2025-08-15"
    }
  ]
}
```

## EU AI Act Art. 13 mapping

| Art. 13 requirement | THEMIS implementation |
|---|---|
| **Transparency about AI system providers** | AIBOM `components[]` lists every model with `provider` field |
| **High-risk AI system documentation** | `modelCard.intendedUse` + `modelCard.limitations` populated for `claude-sonnet-4-5` |
| **Training data provenance** | `datasets[].provenance` field for `invoicenet-1k` (license marked `unknown` per Stanford's terms) |
| **Capability + limitation disclosure** | `modelParameters.supports_tool_use` + `modelParameters.supports_vision` flags |
| **Versioning** | `version: 2025-11-01` (Sonnet 4.5 release) and `version: 2025-08-15` (Qwen3-Coder) |

## Components inventory (THEMIS 3.0)

| Component | Type | Has modelCard | Has datasets |
|---|---|---|---|
| `claude-sonnet-4-5` | `machine-learning-model` | ✓ (full) | ✓ (InvoiceNet 1K) |
| `qwen3-coder-30b` | `machine-learning-model` | — (provider-published) | — |
| `invoicenet-1k` | `data` | n/a | n/a |
| `themis-orchestrator` | `application` | n/a | n/a |
| `themis-agents` | `application` | n/a | n/a |
| `themis-evidence` | `application` | n/a | n/a |
| `themis-compliance` | `application` | n/a | n/a |
| `themis-band-client` | `application` | n/a | n/a |
| `themis-frontend` | `application` | n/a | n/a |

## API endpoint

```
GET /aibom
  → application/vnd.cyclonedx+json
  → full AIBOM JSON (see schema above)

GET /aibom/:run_id
  → per-run snapshot of the AIBOM at the moment of signing
```

## Why CycloneDX 1.6

CycloneDX 1.6 (released 2024-Q4) is the first version that adds:

- `machine-learning-model` component type
- `data` component type
- `modelCard` field with `modelParameters`, `intendedUse`, `limitations`
- `datasets` array on model components
- `modelCard.modelParameters` as free-form JSON (no schema lock-in)

These are exactly the fields the EU AI Act Art. 13 supply-chain probe
needs. Older SBOM formats (SPDX 2.x, CycloneDX 1.0–1.5) cannot represent
an AI model's training data or capabilities.

## Tests

- `crates/themis-compliance/tests/regulatory_completion.rs` — 14 tests
  covering CycloneDX 1.6 schema, EU AI Act Art. 13 mapping, dataset
  provenance, and component name stability.
- All 14 pass.

## References

- [CycloneDX 1.6 spec](https://cyclonedx.org/specification/cyclonedx-1.6/)
- [EU AI Act Art. 13 — Transparency obligations for providers](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_13)
- [NIST AI RMF — Map function (G13 supply chain)](https://www.nist.gov/itl/ai-risk-management-framework)