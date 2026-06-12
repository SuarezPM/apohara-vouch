//! BAAAR kill-switch — re-exports the gate from themis-agents and
//! adds a wire-format `HaltReason` for the Evidence Packet.
//!
//! The actual decision logic lives in `themis_agents::baaar`. This
//! module exists so the orchestrator has a stable import path and
//! can extend the surface (e.g. telemetry hooks) without touching
//! themis-agents.

pub use themis_agents::baaar::{
    BaaarGate, BaaarReason, Finding, FindingKind, FraudAssessment, Outcome,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_approves_clean_assessment() {
        let a = FraudAssessment {
            risk_score: 0.5,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: false,
        };
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_high_risk() {
        let a = FraudAssessment {
            risk_score: 0.95,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: false,
        };
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn halts_on_secret_leak() {
        let a = FraudAssessment {
            risk_score: 0.1,
            findings: vec![Finding {
                kind: FindingKind::SecretLeak,
                description: "AWS key".to_string(),
            }],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: false,
        };
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::SecretLeakDetected)
        );
    }

    #[test]
    fn halts_on_low_coherence() {
        let a = FraudAssessment {
            risk_score: 0.1,
            findings: vec![],
            coherence_score: 0.29,
            debate_rounds: 1,
            explicit_halt: false,
        };
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn halts_on_max_debate_rounds() {
        let a = FraudAssessment {
            risk_score: 0.1,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 5,
            explicit_halt: false,
        };
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::MaxDebateRoundsReached)
        );
    }

    #[test]
    fn halts_on_explicit_halt() {
        let a = FraudAssessment {
            risk_score: 0.1,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: true,
        };
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::ExplicitHaltRequested)
        );
    }

    #[test]
    fn first_matching_condition_wins() {
        let a = FraudAssessment {
            risk_score: 0.99,
            findings: vec![Finding {
                kind: FindingKind::SecretLeak,
                description: "x".to_string(),
            }],
            coherence_score: 0.1,
            debate_rounds: 10,
            explicit_halt: true,
        };
        // risk (first checked) wins.
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }
}
