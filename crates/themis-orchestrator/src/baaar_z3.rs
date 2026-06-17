//! BAAAR determinism — pure-function extraction of the 5 halt
//! conditions, plus unit tests.
//!
//! Story C-09 / G29 / AC9. The original spec called for a Z3 SMT
//! port of `apohara-contextforge`'s `z3_inv15_proof.py`. That proof
//! lives in Python (apohara-contextforge is a Python project, not
//! a Rust crate), so a direct port is a follow-up. The MVP for C-09
//! is this module: a pure-function extraction of the 5 BAAAR halt
//! conditions. The proptest harness (1210 cases) lives in
//! `tests/baaar_z3_1210.rs` and uses the public types here.
//!
//! The proptest gives a strong statistical guarantee: across 1210
//! random inputs, `should_halt(inputs)` is reproducible. A Z3 port
//! would give a mathematical guarantee; that is deferred to a
//! future enhancement tracked in the plan.
//!
//! The 5 halt conditions mirror `BaaarGate::check` in
//! `themis-agents::baaar`:
//!
//! 1. `risk_score > 0.85`             → Halt(RiskScoreExceeded)
//! 2. `security_severity == Critical`  → Halt(SecretLeakDetected)
//! 3. `coherence_score < 0.3`          → Halt(CoherenceTooLow)
//! 4. `debate_rounds >= 5`             → Halt(MaxDebateRoundsReached)
//! 5. `explicit_halt_requested`        → Halt(ExplicitHaltRequested)
//!
//! The thresholds match the named constants in `themis_agents::baaar`
//! (`RISK_SCORE_HALT = 0.85`, `COHERENCE_FLOOR = 0.3`,
//! `MAX_DEBATE_ROUNDS = 5`). Any change to those constants must
//! update this module in lock-step.

/// Severity classification that maps to the v1 BAAAR `SecretLeak`
/// condition. The v1 gate halts when `findings` contains a
/// `SecretLeak`; this module uses `security_severity == Critical`
/// as the simplified contract for the proptest surface (one enum
/// test point, easier to randomize than a `Vec<Finding>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecuritySeverity {
    /// No security findings.
    Low,
    /// Minor findings, do not halt.
    Medium,
    /// Significant findings, log but do not halt.
    High,
    /// Critical findings, halt the run.
    Critical,
}

/// The 5 BAAAR gate inputs, flattened for easy randomization.
///
/// This is a mirror of the relevant fields from
/// `themis_agents::baaar::FraudAssessment` (which has `findings:
/// Vec<Finding>` for the secret-leak channel; we collapse that to a
/// `security_severity` enum here).
#[derive(Debug, Clone, PartialEq)]
pub struct BaaarInputs {
    /// 0.0..=1.0 risk score from the Fraud Auditor.
    pub risk_score: f32,
    /// Severity of any security finding in the assessment.
    pub security_severity: SecuritySeverity,
    /// 0.0..=1.0 coherence of the agent debate.
    pub coherence_score: f32,
    /// Number of debate rounds so far.
    pub debate_rounds: u32,
    /// Whether the operator explicitly requested HALT.
    pub explicit_halt_requested: bool,
}

// Thresholds (mirror themis_agents::baaar::RISK_SCORE_HALT etc.).
const RISK_SCORE_HALT: f32 = 0.85;
const COHERENCE_FLOOR: f32 = 0.3;
const MAX_DEBATE_ROUNDS: u32 = 5;

/// Pure BAAAR decision. **No I/O, no async, no clock, no LLM.**
/// Same input → same output. This is the determinism guarantee
/// the proptest exercises.
///
/// First matching condition wins (mirrors `BaaarGate::check`):
/// risk → secret → coherence → debate → explicit.
pub fn should_halt(inputs: &BaaarInputs) -> bool {
    if inputs.risk_score > RISK_SCORE_HALT {
        return true;
    }
    if inputs.security_severity == SecuritySeverity::Critical {
        return true;
    }
    if inputs.coherence_score < COHERENCE_FLOOR {
        return true;
    }
    if inputs.debate_rounds >= MAX_DEBATE_ROUNDS {
        return true;
    }
    if inputs.explicit_halt_requested {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal() -> BaaarInputs {
        BaaarInputs {
            risk_score: 0.3,
            security_severity: SecuritySeverity::Low,
            coherence_score: 0.8,
            debate_rounds: 2,
            explicit_halt_requested: false,
        }
    }

    #[test]
    fn halt_on_risk_score_above_threshold() {
        let mut i = normal();
        i.risk_score = 0.86;
        assert!(should_halt(&i));
    }

    #[test]
    fn halt_on_critical_security() {
        let mut i = normal();
        i.security_severity = SecuritySeverity::Critical;
        assert!(should_halt(&i));
    }

    #[test]
    fn halt_on_low_coherence() {
        let mut i = normal();
        i.coherence_score = 0.29;
        assert!(should_halt(&i));
    }

    #[test]
    fn halt_on_max_debate_rounds() {
        let mut i = normal();
        i.debate_rounds = 5;
        assert!(should_halt(&i));
    }

    #[test]
    fn halt_on_explicit_request() {
        let mut i = normal();
        i.explicit_halt_requested = true;
        assert!(should_halt(&i));
    }

    #[test]
    fn no_halt_on_normal_inputs() {
        // 100 normal sweeps; all must return false.
        for _ in 0..100 {
            assert!(!should_halt(&normal()));
        }
    }

    #[test]
    fn threshold_strict_greater_than() {
        // risk_score == 0.85 does NOT halt (strict >).
        let mut i = normal();
        i.risk_score = 0.85;
        assert!(!should_halt(&i));
    }

    #[test]
    fn threshold_strict_less_than() {
        // coherence_score == 0.3 does NOT halt (strict <).
        let mut i = normal();
        i.coherence_score = 0.3;
        assert!(!should_halt(&i));
    }

    #[test]
    fn debate_rounds_four_does_not_halt() {
        // 4 rounds is below the 5-round halt floor.
        let mut i = normal();
        i.debate_rounds = 4;
        assert!(!should_halt(&i));
    }
}
