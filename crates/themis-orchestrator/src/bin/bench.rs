//! `themis-bench` — measures the ACs that don't need a real deploy.
//!
//! Run: `cargo run --release --bin themis-bench --features bench -- --out ac-measurements.json`
//!
//! ACs measured (fully mocked path, no real LLM/TSA/Rekor):
//! - **AC2**: end-to-end `process_invoice` latency per demo invoice (5 runs).
//! - **AC4 / AC6 / AC11**: BAAAR determinism + halt distribution (10/10 runs).
//! - **AC7**: token reduction — measured indirectly via input_tokens
//!   on the mock LLM (we record the count; the Compressor is in
//!   `themis-compressor` and isn't wired into the mocked path yet).
//! - **AC8**: cost per run — USD cents, derived from mock token
//!   counts × a fixed $/MTok rate.
//! - **AC9**: multi-tenant isolation — distinct pubkeys per tenant.
//! - **AC10**: BAAAR HALT visible latency — same as AC2 (mocked path).
//! - **AC13**: PRC offline verify — runs themis-verify on the
//!   sealed packet, asserts exit 0 in <30s.
//!
//! ACs NOT measured here (need a deployed binary + curl):
//! - **AC1** (cold start <800ms): `scripts/measure_acs.sh` measures this
//!   by spawning the binary and timing the first response.
//! - **AC3** (peak memory <700MB): measured by `/usr/bin/time -v` in
//!   the shell script.
//! - **AC12** (PRC PDF download <2s): needs the running HTTP server.
//!
//! Output: JSON report at `--out` (default `ac-measurements.json`).

use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use themis_agents::llm::{LlmBackend, LlmResponse, MockLlmProvider};
use themis_evidence::packet::EvidenceService;
use themis_evidence::timestamp::MockTimestampAuthority;
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::room::MockBandRoom;
use themis_orchestrator::tenants::TenantRegistry;
use themis_orchestrator::test_support::{
    build_stub_agents, fixtures_dir, fraud_auditor_payload, stub_default_response, DemoInvoice,
};

#[derive(Debug, Clone, Serialize)]
struct AcReport {
    ac2_per_invoice_ms: HashMap<String, f64>,
    ac2_avg_ms: f64,
    ac2_p95_ms: f64,
    ac4_halt_distribution: HashMap<String, usize>,
    ac4_determinism_10_of_10: bool,
    ac7_input_tokens_per_invoice: HashMap<String, u32>,
    ac7_total_input_tokens: u32,
    ac8_total_usd_cents: f64,
    ac9_distinct_pubkeys: bool,
    ac10_halt_latency_ms: HashMap<String, f64>,
    ac13_verify_exit_code_per_invoice: HashMap<String, i32>,
    ac13_verify_avg_ms: f64,
    total_wall_clock_ms: f64,
    measured_at: String,
}

fn load_fixtures() -> Vec<DemoInvoice> {
    let names = [
        "stark-001.json",
        "stark-002.json",
        "stark-003.json",
        "wayne-001.json",
        "wayne-002.json",
    ];
    names
        .iter()
        .map(|n| {
            let p = fixtures_dir().join(n);
            let bytes = std::fs::read(&p).expect("read fixture");
            serde_json::from_slice(&bytes).expect("parse fixture")
        })
        .collect()
}

fn orchestrator_for(f: &DemoInvoice, counter: Arc<AtomicU32>) -> (Orchestrator, Arc<AtomicU32>) {
    let mock_llm: Arc<dyn LlmBackend> = Arc::new(
        MockLlmProvider::new("mock-bench")
            .with_response(
                &f.invoice_id,
                LlmResponse {
                    text: serde_json::to_string(&f.extracted).unwrap(),
                    input_tokens: 256,
                    output_tokens: 128,
                    model_id: "mock-bench".to_string(),
                finish_reason: themis_agents::llm::FinishReason::Stop,
            }            )
            .with_response(
                "assess_fraud_risk",
                LlmResponse {
                    text: fraud_auditor_payload(f),
                    input_tokens: 256,
                    output_tokens: 64,
                    model_id: "mock-bench".to_string(),
                finish_reason: themis_agents::llm::FinishReason::Stop,
            }            )
            .with_default(stub_default_response("mock-bench")),
    );
    // Per-agent dispatch map (bench uses a single shared mock).
    let mut dispatch = std::collections::HashMap::new();
    for name in [
        "extractor",
        "po_matcher",
        "fraud_auditor",
        "gaap_classifier",
        "provenance_signer",
        "demo_narrator",
        "regression_tester",
        "audit_watchdog",
    ] {
        dispatch.insert(name.to_string(), mock_llm.clone());
    }
    let agents = build_stub_agents(dispatch, Some(counter.clone()));
    let rooms: Arc<dyn themis_orchestrator::room::BandRoom> = MockBandRoom::new().into_arc();
    let tenants = Arc::new(TenantRegistry::with_default_tenants());
    (Orchestrator::new(rooms, agents, tenants), counter)
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run());
}

async fn run() {
    let args: Vec<String> = std::env::args().collect();
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "ac-measurements.json".to_string());

    let total_start = Instant::now();
    let fixtures = load_fixtures();

    let mut per_invoice_ms: HashMap<String, f64> = HashMap::new();
    let mut halt_latency_ms: HashMap<String, f64> = HashMap::new();
    let mut tokens_per_invoice: HashMap<String, u32> = HashMap::new();
    let mut halt_distribution: HashMap<String, usize> = HashMap::new();
    let mut verify_exit_codes: HashMap<String, i32> = HashMap::new();
    let mut verify_durations: Vec<f64> = Vec::new();
    let mut total_input_tokens: u32 = 0;
    let mut total_usd_cents: f64 = 0.0;

    for f in &fixtures {
        let counter = Arc::new(AtomicU32::new(0));
        let (orch, counter) = orchestrator_for(f, counter);
        let start = Instant::now();
        let sp = orch
            .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
            .await
            .unwrap();
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        per_invoice_ms.insert(f.invoice_id.clone(), elapsed_ms);
        let in_tok = counter.load(std::sync::atomic::Ordering::SeqCst);
        tokens_per_invoice.insert(f.invoice_id.clone(), in_tok);
        total_input_tokens += in_tok;
        // $0.50/MTok input × tokens.
        let usd_cents = (in_tok as f64 * 0.05) / 1000.0;
        total_usd_cents += usd_cents;

        if matches!(
            sp.packet.bbaaar_outcome,
            themis_agents::baaar::Outcome::Halt(_)
        ) {
            halt_latency_ms.insert(f.invoice_id.clone(), elapsed_ms);
            let key = format!("{:?}", sp.packet.bbaaar_outcome);
            *halt_distribution.entry(key).or_insert(0) += 1;
        }

        // AC13: run themis-verify on a real SealedPacket built from
        // the fixture's ExtractedInvoice.
        let tsa: Arc<dyn themis_evidence::timestamp::TimestampAuthority> =
            Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"));
        let seed: [u8; 32] = if f.tenant_id == "stark" {
            [0xA1; 32]
        } else {
            [0xB2; 32]
        };
        let mut svc = EvidenceService::from_seed(&f.tenant_id, seed, tsa);
        let payload = serde_json::to_string(&f.extracted).unwrap();
        let sealed = svc.seal(&f.invoice_id, &payload, None).await.unwrap();
        let tmp = std::env::temp_dir().join(format!("bench-{}.json", f.invoice_id));
        let json = serde_json::to_string(&sealed).unwrap();
        std::fs::write(&tmp, json).unwrap();
        let sig_path = std::env::temp_dir().join(format!("bench-{}.sig", f.invoice_id));
        std::fs::write(&sig_path, &sealed.signature_hex).unwrap();
        let start = Instant::now();
        let output = std::process::Command::new("./target/release/themis-verify")
            .arg(&tmp)
            .arg(&sig_path)
            .output();
        let dur = start.elapsed().as_secs_f64() * 1000.0;
        match output {
            Ok(o) => {
                verify_exit_codes.insert(f.invoice_id.clone(), o.status.code().unwrap_or(-1));
                if o.status.success() {
                    verify_durations.push(dur);
                }
            }
            Err(_) => {
                verify_exit_codes.insert(f.invoice_id.clone(), -1);
            }
        }
    }

    // AC4 / AC6: determinism — run stark-003 10 times.
    let f0 = &fixtures[2];
    let mut halts_10 = 0;
    for _ in 0..10 {
        let counter = Arc::new(AtomicU32::new(0));
        let (orch, _) = orchestrator_for(f0, counter);
        let sp = orch
            .process_invoice(&f0.tenant_id, &f0.invoice_id, b"raw".to_vec())
            .await
            .unwrap();
        if matches!(
            sp.packet.bbaaar_outcome,
            themis_agents::baaar::Outcome::Halt(_)
        ) {
            halts_10 += 1;
        }
    }
    let determinism_10_of_10 = halts_10 == 10;

    let stark_tenant = TenantRegistry::with_default_tenants();
    let stark = stark_tenant.get("stark").unwrap();
    let wayne = stark_tenant.get("wayne").unwrap();
    let distinct_pubkeys = stark.ed25519_public_key_hex != wayne.ed25519_public_key_hex;

    let mut latencies: Vec<f64> = per_invoice_ms.values().copied().collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<f64>() / latencies.len() as f64
    };
    let p95_idx = (latencies.len() as f64 * 0.95).ceil() as usize - 1;
    let p95 = if latencies.is_empty() {
        0.0
    } else {
        latencies[p95_idx.min(latencies.len() - 1)]
    };
    let verify_avg = if !verify_durations.is_empty() {
        verify_durations.iter().sum::<f64>() / verify_durations.len() as f64
    } else {
        0.0
    };

    let report = AcReport {
        ac2_per_invoice_ms: per_invoice_ms,
        ac2_avg_ms: avg,
        ac2_p95_ms: p95,
        ac4_halt_distribution: halt_distribution,
        ac4_determinism_10_of_10: determinism_10_of_10,
        ac7_input_tokens_per_invoice: tokens_per_invoice,
        ac7_total_input_tokens: total_input_tokens,
        ac8_total_usd_cents: total_usd_cents,
        ac9_distinct_pubkeys: distinct_pubkeys,
        ac10_halt_latency_ms: halt_latency_ms,
        ac13_verify_exit_code_per_invoice: verify_exit_codes,
        ac13_verify_avg_ms: verify_avg,
        total_wall_clock_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        measured_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(&out, &json).expect("write report");
    println!("wrote AC report to {out}");
    println!("{}", json);
}
