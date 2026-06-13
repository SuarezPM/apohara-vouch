//! Tenant isolation tests (AC9).
//!
//! Verifies that two tenants' signed packets differ in the
//! tenant-specific fields (tenant_id, public_key_hex, signature_hex)
//! even when the upstream decisions are identical. Also verifies
//! that a tenant cannot read another tenant's Band room.

#[cfg(test)]
mod tests {
    use crate::orchestrator::Orchestrator;
    use crate::room::{BandRoom, MockBandRoom};
    use crate::router::LlmBackendRouter;
    use crate::tenants::TenantRegistry;
    use std::collections::HashMap;
    use std::sync::Arc;
    use themis_agents::decision::{AgentDecision, DecisionType};
    use themis_agents::traits::{Agent, AgentContext};

    /// Stub agent that returns the same canned decision regardless
    /// of the calling tenant. Used to prove that the *tenant*
    /// differentiates the packets, not the agent's output.
    struct StubAgent(&'static str, DecisionType);
    #[async_trait::async_trait]
    impl Agent for StubAgent {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn process(
            &self,
            ctx: AgentContext,
        ) -> Result<AgentDecision, themis_agents::decision::AgentError> {
            Ok(AgentDecision {
                agent_id: self.0.to_string(),
                tenant_id: ctx.tenant_id.clone(),
                invoice_id: ctx.invoice_id.clone(),
                decision_type: self.1,
                confidence: 0.9,
                reasoning: "ok".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({"outcome": "approve"}),
            })
        }
    }

    fn build_orch() -> Orchestrator {
        let rooms: Arc<dyn BandRoom> = MockBandRoom::new().into_arc();
        let tenants = Arc::new(TenantRegistry::with_default_tenants());
        let mut agents: HashMap<String, Arc<dyn Agent>> = HashMap::new();
        let mapping: &[(&str, DecisionType)] = &[
            ("extractor", DecisionType::Extracted),
            ("po_matcher", DecisionType::PoMatched),
            ("fraud_auditor", DecisionType::FraudAssessed),
            ("gaap_classifier", DecisionType::GaapClassified),
            ("provenance_signer", DecisionType::ProvenanceSigned),
            ("demo_narrator", DecisionType::Narrated),
            ("regression_tester", DecisionType::RegressionResult),
            ("audit_watchdog", DecisionType::WatchdogAlert),
        ];
        for (n, dt) in mapping {
            agents.insert(n.to_string(), Arc::new(StubAgent(n, *dt)));
        }
        let router = LlmBackendRouter::with_default_routing(HashMap::new());
        Orchestrator::new(rooms, agents, router, tenants)
    }

    #[tokio::test]
    async fn stark_vs_wayne_packets_differ_in_tenant_specific_fields() {
        let orch = build_orch();
        let stark = orch
            .process_invoice("stark", "inv-001", b"raw".to_vec())
            .await
            .unwrap();
        let wayne = orch
            .process_invoice("wayne", "inv-001", b"raw".to_vec())
            .await
            .unwrap();

        // tenant_id differs.
        assert_eq!(stark.packet.tenant_id, "stark");
        assert_eq!(wayne.packet.tenant_id, "wayne");
        assert_ne!(stark.packet.tenant_id, wayne.packet.tenant_id);

        // public_key_hex differs (tenants have distinct keys).
        assert_ne!(stark.public_key_hex, wayne.public_key_hex);
        // Both are 64 hex chars.
        assert_eq!(stark.public_key_hex.len(), 64);
        assert_eq!(wayne.public_key_hex.len(), 64);

        // blake3_hash_hex differs (canonical JSON includes tenant_id).
        assert_ne!(stark.blake3_hash_hex, wayne.blake3_hash_hex);

        // Stark has the stark key; wayne has the wayne key.
        assert_eq!(stark.public_key_hex, "11".repeat(32));
        assert_eq!(wayne.public_key_hex, "22".repeat(32));
    }

    #[tokio::test]
    async fn wayne_cannot_read_stark_room() {
        // The orchestrator doesn't expose a "read another tenant's
        // room" method — but the BandRoom trait + TenantRegistry
        // guarantee it. Verify at the registry level.
        let registry = TenantRegistry::with_default_tenants();
        registry.open_room("stark", "inv-001").unwrap();
        let err = registry.get_room("wayne", "stark", "inv-001").unwrap_err();
        assert!(matches!(
            err,
            crate::tenants::TenantError::CrossTenantAccess { .. }
        ));
    }

    #[tokio::test]
    async fn stark_and_wayne_packets_have_distinct_decision_chains() {
        // Even though the agents return the same payload per call,
        // each AgentDecision records the `tenant_id` from the
        // context, so the chain differs.
        let orch = build_orch();
        let stark = orch
            .process_invoice("stark", "inv-001", b"raw".to_vec())
            .await
            .unwrap();
        let wayne = orch
            .process_invoice("wayne", "inv-001", b"raw".to_vec())
            .await
            .unwrap();
        // Same number of decisions (8).
        assert_eq!(
            stark.packet.agent_decisions.len(),
            wayne.packet.agent_decisions.len()
        );
        // But the per-decision tenant_id differs.
        for (s, w) in stark
            .packet
            .agent_decisions
            .iter()
            .zip(wayne.packet.agent_decisions.iter())
        {
            assert_eq!(s.tenant_id, "stark");
            assert_eq!(w.tenant_id, "wayne");
        }
    }
}
