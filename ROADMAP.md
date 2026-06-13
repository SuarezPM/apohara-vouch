# THEMIS — Roadmap (estado al 2026-06-12, fin del kickoff day 0)

> Snapshot vivo del proyecto. La fuente de verdad sigue siendo
> `.archive/pre-themis/.omc/plans/ralplan-themis-hackathon.md` y
> `.archive/pre-themis/.omc/specs/deep-interview-themis-hackathon.md`.
> Este archivo es el **delta**: qué se hizo, qué falta, qué bloquea.

## Estado por fase (del plan §3.10)

| Phase | Scope | Estado | Salida |
|-------|-------|--------|--------|
| **A — Foundation** | Repo bootstrap + Band subprocess + Ed25519/BLAKE3/RFC 3161 | ✅ DONE | `themis-band-client` 1 crate, `themis-evidence` 1 crate, `cargo check --workspace` 0 |
| **B — Agents** | 5 core + 3 shadow agents + BAAAR | ✅ DONE | 8 agentes + trait `Agent` + `MockLlmProvider` + BAAAR 5-condiciones |
| **C — Orchestrator + Compliance** | State machine + 4 mappers + Rekor | ✅ DONE | `themis-orchestrator` 1 crate, `themis-compliance` 1 crate, 4 framework mappers + `ComplianceService` |
| **D — Frontend + Demo data** | HTML+JS, `themis.apohara.dev` deploy | 🟡 PARTIAL | `themis-frontend` (US-48/49/50) committed. Demo data (5 invoices Stanford-derived) **NOT YET** |
| **E — Rekor + Multi-tenant** | Rekor v2 client, 2 trust domains | 🟡 PARTIAL | Ed25519 por tenant, 2 rooms Stark/Wayne operativos en Band. **Rekor client NO implementado aún** |
| **F — Deploy + Pitch** | Deploy real, video 5min, deck | 🔴 NOT STARTED | — |

## User Stories completadas (verificables via `git log`)

| US-ID | Commit | Crate / scope |
|-------|--------|---------------|
| US-001 | `05f0369` | `workspace`: scaffold 5-crate + dummy tests |
| US-002 | `3075dac` | `compressor`: `CompressionCoordinator` 4 strategies |
| US-003 | `4462821` | `compressor`: LLMLingua-2 token-classifier port (algo only) |
| US-004 | `c42d88f` | `compressor`: 3 variants + auto-select por word count |
| US-005 | `65f0d59` | `orchestrator`: JCR Safety Gate (arXiv:2601.08343, INV-15) |
| US-006 | `6b0425b` | `orchestrator`: Prefix Salt Planner (SHA-256, namespace) |
| US-007 | `040ea97` | `orchestrator`: Concurrency Scheduler (Semaphore + stagger) |
| US-008 | `3323bc7` | `verify`: aggregate verification + clippy clean |
| US-A01..A09 | `bc46923` | `agents`: 5 core + 3 shadow agents + BAAAR |
| US-A10 | `917e844` | `agents`: aggregate verification |
| US-C01..C06 | `8de2db6` | `compliance`: 4 framework mappers (DORA, EU AI Act, NIST AI RMF, OWASP Agentic) + `ComplianceService` |
| US-C07 | `f16a0fc` | `orchestrator,compliance`: `EventBus` + cycle break |
| US-E01..E10 | `55c436f` | `evidence,band-client`: Ed25519 + BLAKE3 + RFC 3161 + Band subprocess |
| US-O01..O08 | `91c9221` | `orchestrator`: state machine + `BandRoom` + `EvidencePacket` |
| US-O09..O10 | `90e6d15` | `orchestrator`: routing integration + aggregate |
| US-O11 | `29bf277` | `orchestrator`: HTTP layer (axum 0.7, `Arc<AppState>`) |
| US-48..US-50 | `60c408a` | `frontend`: `themis-frontend` via hallmark design skill |
| US-007 deploy | `b8ce460` | `deploy`: Vercel static-only para `themis.apohara.dev` |

**20 commits `feat:*` + 3 `fix/chore`. 18 US-IDs distintos (algunos cubren rangos).**

## Pendiente — bloqueado por la sesión del cierre abrupto (12 jun ~22:00)

Lo que estaba haciendo cuando se cortó la luz / reinicio de shell:

1. **`http.rs` integrado en el orchestrator** ✅ **RESUELTO en `29bf277`**
   - Era mismatch de tipos en axum 0.7 (`State<Arc<AppState>>` vs `State<AppState>`).
   - Causa raíz NO era el extractor sino `std::sync::MutexGuard` no-`Send` en multi-thread runtime.
   - Fix: `tokio::sync::Mutex` + `Arc::new(state)` en `build_router` + handlers `State<Arc<AppState>>`.
   - 6/6 tests `http::` verdes; `cargo test --workspace` verde; clippy clean.
   - Lección guardada en engram: `obs-4ef20e7b207a99db`.

## Pendiente — siguiente sprint

### High priority (AC-bloqueantes)

- [ ] **Rekor v2 client** (`themis-evidence::rekor`, ~130 LOC). ADR-002: shell a `cosign` si no hay SDK Rust maduro. Bloquea AC "anchoring" si el plan §3.4 lo requiere para demo.
- [ ] **Demo data: 5 invoices Stanford InvoiceNet-shaped** (plan §3.8). 4 HALT + 1 APPROVED. Stark #1-3 + Wayne #4-5. Bloquea Phase D → E → F.
- [ ] **Rekor anchoring integrato en `process_invoice`** (pipeline end-to-end con anchor URL en packet).
- [ ] **Multi-tenant keypair en `include_bytes!`** (plan §3.4 nota, R4). Verificar que `keys/{stark,wayne}.ed25519` están baked en el binario (R8: ephemeral FS de Vercel).
- [ ] **themis-verify binary offline verification** (commit `0dd8008` lo crea pero falta `cargo test --test verify_offline` integración real con 5 invoices reales).

### Medium priority (polish, no bloqueantes)

- [ ] **PDF generation quality** (R3). Probar `printpdf` con 3 viewers.
- [ ] **DORA Art 17 `incident_classification` / `reporting_window_hours`** (R7) — populate con `mock_recipient="NCA-ES"`.
- [ ] **Per-tenant Band room `invite` re-flow** — verificar idempotencia del script `themis-bootstrap.py` (rompió en el primer intento, fix manual, documentar).
- [ ] **`cargo deny` + `scripts/check-no-apohara.sh`** (R11). Pre-commit hook para AC11 (no `apohara-*` imports).

### Low priority (post-hackathon)

- [ ] **PR to Band SDK Rust** (si existe o se crea). Hoy es subprocess wrapper.
- [ ] **Visual-verdict audit** del UI desplegado. 7-step checklist de `.claude/rules/visual-verdict.md`.
- [ ] **Video 5min** (plan §3.9 step 4). Hoy no existe.
- [ ] **Pitch deck** (plan §3.9 step 5). 8 drafts en `apohara-hackathon-brain/`, ninguno elegido.

## Acceptance Criteria (15 ACs, status)

| AC | Descripción | Estado | Verifica |
|----|-------------|--------|----------|
| AC1 | Cold start <800ms | 🟡 UNMEASURED | Necesita deploy real + `/usr/bin/time -v` |
| AC2 | End-to-end <90s/invoice | 🟡 UNMEASURED | Necesita demo data real |
| AC3 | Peak memory <700MB | 🟡 UNMEASURED | Profile con `cargo flamegraph` |
| AC4 | BAAAR determinism 10/10 | ✅ (mock-only) | `cargo test -p themis-agents` |
| AC5 | AI slop precision/recall | 🔴 NOT STARTED | Requiere gold labels + mock LLM canned |
| AC6 | Security HALT deterministic | ✅ (mock) | Tests BAAAR con stub |
| AC7 | Token reduction ≥30% | 🟡 UNMEASURED | Snapshot con/sin Compressor |
| AC8 | Cost per run <$X | 🟡 UNMEASURED | Mock LLM con token counts conocidos |
| AC9 | Multi-tenant isolation | ✅ | Stark/Wayne keys distintos, rooms distintos |
| AC10 | BAAAR HALT visible in <90s in demo | 🔴 NOT STARTED | Necesita demo data + deploy |
| AC11 | No `apohara-*` imports | ✅ (parcial) | Sin pre-commit hook formal |
| AC12 | PRC PDF download <2s | 🟡 UNMEASURED | Necesita PDF generator real |
| AC13 | PRC offline verify <30s | 🟡 UNMEASURED | `themis-verify` binary existe, no integrado |
| AC14 | Video 5min | 🔴 NOT STARTED | Post-demo task |
| AC15 | EU AI Act Art 12 ≥7/8 fields | ✅ | `ComplianceService` mapper pasa test |

**6/15 ✅ + 7/15 🟡 unmeasured + 2/15 🔴 not started = ~40% verificable, 60% requiere fase de medición/deploy.**

## AC15 spot-check (reciente)

`cargo test -p themis-orchestrator --lib http::tests::post_invoices_returns_200_with_run_id_and_packet_id` output (parcial):

```json
{
  "eu_ai_act": {
    "framework": "eu_ai_act",
    "populated": 9,
    "total": 9,
    "fields": [
      ["art_12_1_start_time", 0],
      ["art_12_2_end_time", 0],
      ["art_12_3_reference_database", "keys/po-database/stark.json"],
      ["art_12_4_input_data", {"first_decision_payload_blake3": "17d0..."}],
      ["art_12_5_natural_person_id", "operator@stark.local"],
      ["art_12_6_decision_id", "00000000-0000-0000-0000-000000000001"],
      ["art_12_7_policy_version", "themis-policy@2026-06-12 (JCR gate + BAAAR 5 conditions)"],
      ["art_12_8_hash_chain_prev", "blake3(8 upstream decisions)"],
      ["art_26_deployer_name", "stark"]
    ]
  }
}
```

**9/9 campos EU AI Act populated** en un test run con StubAgents (no es el contrato mínimo de 7/8, es 9/9). AC15 verde a nivel de mapper.

## Riesgos activos (top 3 del plan §4)

| ID | Riesgo | Estado al 2026-06-12 |
|----|--------|----------------------|
| R1 | Band Python SDK yanked | Pin `band-sdk==0.2.11` en requirements; OK por ahora |
| R3 | `printpdf` calidad | Sin probar; depende de fase de polish |
| R4 | Multi-tenant key mgmt | `include_bytes!` baked-in, sin FS ephemeral. R8 LOW. OK |
| R5 | LLM non-determinism | BAAAR deterministic post-LLM. AC4 mock-only ✅ |
| R8 | Ephemeral deploy FS wipes keys | `apohara.dev` LOW; Vercel frontend-only, backend en otro lado (TBD) |
| R9 | Featherless 4-concurrent cap | Semáforo + stagger 5-10ms ya en `themis-orchestrator::concurrency` ✅ |

## Decisiones de arquitectura (ADR) — extract del plan

- **ADR-001**: Band SDK via subprocess Python (`band-sdk[langgraph]==0.2.11`). Persistent child per room. JSON-RPC stdin/stdout + WS. **No PyO3** (constraint spec L50).
- **ADR-002**: Rekor v2 → `cosign` shell si no hay SDK Rust maduro. `RekorClient` trait.
- **ADR-003**: Multi-tenant Ed25519 keypair per `keys/{tenant}.ed25519`, `chmod 600` enforced en build pipeline.
- **ADR-004**: BAAAR deterministic post-LLM. 5 condiciones hard-threshold.
- **ADR-005**: Deploy = Vercel (frontend static) + backend por decidir (Railway / Fly / apohara.dev bare metal).

## Siguiente paso concreto

Si la sesión continúa: **demo data + Rekor client + themis-verify integration test**.

Si la sesión termina: este roadmap es la交接 (handoff) para que el próximo Claude (o vos) sepa exactamente qué retomar. La engram tiene `ESTADO CONSOLIDADO pre-restart` (obs de kickoff) + el patrón axum (obs nueva) + todas las decisiones de la sesión.

## Repo metadata

- Branch: `main`
- HEAD: `29bf277` (HTTP layer)
- Ahead of origin: 0 (pushed)
- 23 commits totales (20 feat + 3 fix/chore)
- 5 crates: `themis-band-client`, `themis-agents`, `themis-evidence`, `themis-compliance`, `themis-orchestrator` + `themis-frontend` (assets)
- Demo: `https://themis.apohara.dev` (Vercel static, frontend only)
- Repo: `https://github.com/SuarezPM/apohara-themis`
- License: MIT · Author: Pablo M. Suarez (@SuarezPM)

---

*Last updated: 2026-06-12 (post-HTTP-layer commit, post-push to origin/main).*
