//! vouch-orchestrator POST /seal JSON Schema validation.
//!
//! AC-3.5: round-trip JSON Schema validation — every field
//! in SealRequest and SealResponse deserializes back to the
//! original after `serde_json` round-trip.

use serde_json::json;
use vouch_orchestrator::http::{AgentOutputHttp, SealRequest, SealResponse};

fn sample_request() -> SealRequest {
    SealRequest {
        case_id: "case-001".into(),
        tenant_id: "stark".into(),
        agent_outputs: vec![AgentOutputHttp {
            agent_id: "fraud-auditor".into(),
            verdict: "halt".into(),
            summary: "secret detected".into(),
            risk_score: Some(0.92),
        }],
        hash_chain_link: Some("0".repeat(64)),
        reference_database: "stanford-invoicenet-50".into(),
        policy_version: "apohara-vouch-1".into(),
        natural_person_id: Some("operator@apohara.dev".into()),
    }
}

#[test]
fn seal_request_round_trips_json() {
    let req = sample_request();
    let s = serde_json::to_string(&req).unwrap();
    let back: SealRequest = serde_json::from_str(&s).unwrap();
    assert_eq!(back, req);
}

#[test]
fn seal_request_deserializes_from_canonical_json() {
    let raw = json!({
        "case_id": "case-002",
        "tenant_id": "wayne",
        "agent_outputs": [
            {
                "agent_id": "extractor",
                "verdict": "approve",
                "summary": "extraction ok",
                "risk_score": 0.05
            }
        ],
        "hash_chain_link": null,
        "reference_database": "stanford-invoicenet-50",
        "policy_version": "apohara-vouch-1"
    });
    let req: SealRequest = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(req.case_id, "case-002");
    assert_eq!(req.tenant_id, "wayne");
    assert_eq!(req.agent_outputs.len(), 1);
    assert_eq!(req.agent_outputs[0].agent_id, "extractor");
    assert_eq!(req.agent_outputs[0].risk_score, Some(0.05));
    assert!(req.natural_person_id.is_none()); // omitted in JSON
}

#[test]
fn seal_response_round_trips_json() {
    let resp = SealResponse {
        hash: "a".repeat(64),
        signature_hex: "b".repeat(128),
        public_key_hex: "c".repeat(64),
        decision_id: "00000000-0000-0000-0000-000000000001".into(),
        c2pa_manifest: vouch_receipt::C2paManifest::build(
            "vouch-orchestrator",
            "b".repeat(128).as_str(),
            None,
        ),
        sealed_at: "2026-06-18T12:00:00Z".into(),
        chain_root: "d".repeat(64),
    };
    let s = serde_json::to_string(&resp).unwrap();
    let back: SealResponse = serde_json::from_str(&s).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn seal_request_omits_optional_fields_with_serde_default() {
    // hash_chain_link and natural_person_id are optional. The
    // canonical JSON for an empty case_id is rejected at the
    // handler layer; here we just check the deserializer.
    let raw = json!({
        "case_id": "case-003",
        "tenant_id": "stark",
        "agent_outputs": [
            {
                "agent_id": "fraud-auditor",
                "verdict": "approve",
                "summary": "ok"
            }
        ]
    });
    let req: SealRequest = serde_json::from_value(raw).unwrap();
    assert!(req.hash_chain_link.is_none());
    assert!(req.natural_person_id.is_none());
    assert_eq!(req.reference_database, "stanford-invoicenet-50");
    assert_eq!(req.policy_version, "apohara-vouch-1");
}
