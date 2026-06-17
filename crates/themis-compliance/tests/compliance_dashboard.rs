//! Integration test for the 26/26 compliance dashboard data shape.
//!
//! US-04 of the THEMIS 3-Day Sprint plan adds a frontend dashboard that
//! renders one row per populated field, grouped by framework, with a
//! green checkmark. This test validates the data contract that the
//! dashboard consumes: an APPROVED Evidence Packet must produce a
//! `ComplianceReport` with 31 populated fields across the 5 mappers
//! (DORA 3 + EU AI Act 9 + NIST AI RMF 4 + OWASP 10 + ISO 42001 5 = 31). The
//! frontend ACS column adds 4 more derived fields (tenant_id,
//! ed25519 pubkey, blake3 hash, chain length) to reach 35/35 in the
//! visual layout, but those are derived client-side from the
//! SealedPacket — not part of `ComplianceReport` itself.

use themis_agents::baaar::Outcome;
use themis_agents::decision::{AgentDecision, DecisionType};
use themis_compliance::framework::EvidencePacket;
use themis_compliance::service::ComplianceService;

fn dec(tenant: &str, dt: DecisionType, payload: serde_json::Value) -> AgentDecision {
    AgentDecision {
        agent_id: "x".to_string(),
        tenant_id: tenant.to_string(),
        invoice_id: "inv-001".to_string(),
        decision_type: dt,
        confidence: 0.92,
        reasoning: "ok".to_string(),
        timestamp_ms: 1_700_000_000_000,
        payload,
    }
}

fn approved_packet() -> EvidencePacket {
    // The "APPROVED" path that the frontend dashboard is built around:
    //  - Extractor     -> Extracted
    //  - PO Matcher    -> PoMatched
    //  - Fraud Auditor -> FraudAssessed
    //  - Audit Watchdog-> WatchdogAlert (populates DORA Art 10)
    //  - Provenance    -> ProvenanceSigned (populates NIST Manage)
    //  - Regression    -> RegressionResult (populates NIST Manage)
    EvidencePacket::new(
        "stark",
        "inv-clean-001",
        vec![
            dec("stark", DecisionType::Extracted, serde_json::json!({})),
            dec("stark", DecisionType::PoMatched, serde_json::json!({})),
            dec(
                "stark",
                DecisionType::FraudAssessed,
                serde_json::json!({"outcome": "approve", "risk_score": 0.18}),
            ),
            dec(
                "stark",
                DecisionType::WatchdogAlert,
                serde_json::json!({"coherence_score": 0.92, "reasoning": "ok"}),
            ),
            dec(
                "stark",
                DecisionType::ProvenanceSigned,
                serde_json::json!({}),
            ),
            dec(
                "stark",
                DecisionType::RegressionResult,
                serde_json::json!({}),
            ),
        ],
        Outcome::Approve,
    )
}

#[test]
fn approved_packet_surfaces_31_populated_fields() {
    let svc = ComplianceService::new();
    let report = svc.report(&approved_packet());

    // The 31 regulator fields: DORA 3 + EU AI Act 9 + NIST 4 + OWASP 10 + ISO 42001 5.
    // US-05 added the 5th ISO 42001 field (Annex A.6 lifecycle stage);
    // the total grew from 30 to 31.
    assert_eq!(
        report.total_populated, 31,
        "APPROVED packet must populate all 31 fields (DORA 3 + EU AI Act 9 + NIST 4 + OWASP 10 + ISO 42001 5), got {}",
        report.total_populated
    );
    assert_eq!(report.total_fields, 31);
    assert!((report.coverage_pct - 1.0).abs() < 1e-5);
    assert!(report.ac8_pass, "AC8 must pass on APPROVED packet");
    assert!(
        report.ac15_pass,
        "AC15 must pass on APPROVED packet (Art 12 8/8)"
    );
}

#[test]
fn approved_packet_field_breakdown_matches_dashboard_columns() {
    let svc = ComplianceService::new();
    let report = svc.report(&approved_packet());

    // Index fields by framework to assert each dashboard column has
    // the expected count.
    let mut by_fw: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for map in &report.frameworks {
        let names: Vec<String> = map.fields.iter().map(|(n, _)| (*n).to_string()).collect();
        by_fw.insert(map.framework.as_str().to_string(), names);
    }

    let dora = by_fw.get("dora").expect("DORA column must be present");
    assert_eq!(dora.len(), 3, "DORA must have 3 fields, got {:?}", dora);
    assert!(dora.iter().any(|n| n == "art_9_ict_risk_management"));
    assert!(dora.iter().any(|n| n == "art_10_incident_detection"));
    assert!(dora.iter().any(|n| n == "art_17_incident_reporting"));

    let euaiact = by_fw
        .get("eu_ai_act")
        .expect("EU AI Act column must be present");
    assert_eq!(
        euaiact.len(),
        9,
        "EU AI Act must have 9 fields (8 Art 12 + 1 Art 26), got {:?}",
        euaiact
    );
    let art12_count = euaiact.iter().filter(|n| n.starts_with("art_12_")).count();
    assert_eq!(art12_count, 8, "EU AI Act Art 12 must be 8/8");
    assert!(euaiact.iter().any(|n| n == "art_26_deployer_name"));

    let nist = by_fw
        .get("nist_ai_rmf")
        .expect("NIST column must be present");
    assert_eq!(nist.len(), 4, "NIST must have 4 functions, got {:?}", nist);
    assert!(nist.contains(&"govern".to_string()));
    assert!(nist.contains(&"map".to_string()));
    assert!(nist.contains(&"measure".to_string()));
    assert!(nist.contains(&"manage".to_string()));

    let owasp = by_fw
        .get("owasp_agentic")
        .expect("OWASP column must be present");
    assert_eq!(
        owasp.len(),
        10,
        "OWASP must have 10 ASI fields, got {:?}",
        owasp
    );
    for asi in &[
        "ASI01_prompt_injection",
        "ASI02_sensitive_data_exposure",
        "ASI03_supply_chain",
        "ASI04_data_and_model_poisoning",
        "ASI05_improper_output_handling",
        "ASI06_excessive_agency",
        "ASI07_system_prompt_leakage",
        "ASI08_vector_and_embedding_weaknesses",
        "ASI09_misinformation",
        "ASI10_rogue_agents",
    ] {
        assert!(owasp.iter().any(|n| n == asi), "missing ASI field: {asi}");
    }

    let iso = by_fw
        .get("iso_42001")
        .expect("ISO 42001 column must be present");
    assert_eq!(iso.len(), 5, "ISO 42001 must have 5 clauses, got {:?}", iso);
    for clause in &[
        "clause_6_1_risk_assessment",
        "clause_8_4_impact_assessment",
        "clause_9_1_monitoring_measurement",
        "clause_10_2_continual_improvement",
        "annex_a_6_lifecycle_stage",
    ] {
        assert!(
            iso.iter().any(|n| n == clause),
            "missing ISO 42001 clause: {clause}"
        );
    }
}

#[test]
fn compliance_report_serializes_with_field_level_detail_for_dashboard() {
    // The dashboard's renderComplianceDashboard walks the
    // `frameworks[i].fields` array. This test pins the JSON shape:
    // each framework entry has a `fields` array of (name, value)
    // tuples. If a future refactor renames or restructures the field
    // list, the frontend will silently render 0 rows — this test
    // catches that.
    let svc = ComplianceService::new();
    let report = svc.report(&approved_packet());
    let json = serde_json::to_value(&report).expect("serialize ComplianceReport");

    let frameworks = json
        .get("frameworks")
        .and_then(|v| v.as_array())
        .expect("frameworks must be an array");
    assert_eq!(frameworks.len(), 5, "5 framework entries expected");

    let mut total_field_rows = 0usize;
    for fw in frameworks {
        let fields = fw
            .get("fields")
            .and_then(|v| v.as_array())
            .expect("each framework must have a fields array");
        for row in fields {
            // Each row is serialized as a 2-element array: [name, value]
            let arr = row.as_array().expect("each field row must be a JSON array");
            assert_eq!(arr.len(), 2, "field row must be [name, value]");
            assert!(arr[0].is_string(), "field name must be a string");
            total_field_rows += 1;
        }
    }
    assert_eq!(
        total_field_rows, 31,
        "JSON must expose all 30 populated field rows (frontend renders one row per entry)"
    );
}

#[test]
fn halted_packet_still_populates_art_17_with_incident_metadata() {
    // On HALT, DORA Art 17 carries 3 regulator-ready sub-fields
    // (incident_classification, reporting_window_hours=72,
    // mock_recipient=NCA-ES). The dashboard surfaces these in the
    // Art 17 row's tooltip.
    let svc = ComplianceService::new();
    let report = svc.report(&EvidencePacket::new(
        "wayne",
        "inv-halt-001",
        vec![dec(
            "wayne",
            DecisionType::FraudAssessed,
            serde_json::json!({"outcome": "halt", "risk_score": 0.93}),
        )],
        Outcome::Halt(themis_agents::baaar::BaaarReason::RiskScoreExceeded),
    ));
    let dora = report
        .frameworks
        .iter()
        .find(|m| m.framework.as_str() == "dora")
        .expect("DORA must be present");
    let art_17 = dora
        .fields
        .iter()
        .find(|(n, _)| *n == "art_17_incident_reporting")
        .expect("Art 17 must be populated on HALT");
    let val = &art_17.1;
    assert_eq!(val["outcome"], "halt");
    assert_eq!(val["incident_classification"], "fraud_suspected");
    assert_eq!(val["reporting_window_hours"], 72);
    assert_eq!(val["mock_recipient"], "NCA-ES");
}
