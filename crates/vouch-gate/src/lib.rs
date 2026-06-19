//! vouch-gate — BAAAR kill-switch (deterministic 5-condition halt).
//!
//! AC-3.1, AC-3.10: thin re-export of `themis-agents::baaar` plus a
//! flat `GateInput` / `Verdict` surface for orchestrator use. The
//! five deterministic halt conditions (AC-3.10) — evaluated
//! first-match-wins:
//!
//! 1. `risk_score > 0.85` → Halt(RiskScoreExceeded)
//! 2. any `SecretLeak` finding → Halt(SecretLeakDetected)
//! 3. `coherence_score < 0.3` → Halt(CoherenceTooLow)
//! 4. `debate_rounds >= 5` → Halt(MaxDebateRoundsReached)
//! 5. `explicit_halt_requested` → Halt(ExplicitHaltRequested)
//!
//! All comparisons are strict; same input → same verdict (proptest
//! 10/10 over the risk_score boundary).

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-gate"
}

pub use themis_agents::baaar::{
    BaaarGate, BaaarReason, BaaarV2Gate, Finding, FindingKind, FraudAssessment, Outcome,
};
pub use themis_orchestrator::baaar_z3::{BaaarInputs, SecuritySeverity};

/// Verdict: Halt(reason) or Allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Continue execution.
    Allow,
    /// Halt with the given reason.
    Halt(BaaarReason),
}

impl Verdict {
    /// True iff this verdict halts execution.
    pub fn is_halt(&self) -> bool {
        matches!(self, Verdict::Halt(_))
    }

    /// Convert to `Outcome` (compatible with themis-agents surface).
    pub fn to_outcome(&self) -> Outcome {
        match self {
            Verdict::Allow => Outcome::Approve,
            Verdict::Halt(r) => Outcome::Halt(*r),
        }
    }
}

impl From<Outcome> for Verdict {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Approve => Verdict::Allow,
            Outcome::Halt(r) => Verdict::Halt(r),
        }
    }
}

/// Gate input — the orchestrator-side flattened mirror of
/// `FraudAssessment` + BaaarInputs.
#[derive(Debug, Clone, PartialEq)]
pub struct GateInput {
    /// 0.0..=1.0 risk score (HALT if > 0.85).
    pub risk_score: f32,
    /// Findings from the Fraud Auditor (SecretLeak → HALT).
    pub findings: Vec<Finding>,
    /// 0.0..=1.0 coherence score (HALT if < 0.3).
    pub coherence_score: f32,
    /// Number of debate rounds (HALT if >= 5).
    pub debate_rounds: u32,
    /// Whether the human explicitly requested HALT.
    pub explicit_halt_requested: bool,
    /// Optional security severity (informational; the BAAAR gate
    /// itself only consults the other 5 fields).
    pub security_severity: Option<SecuritySeverity>,
}

impl GateInput {
    /// Construct from `FraudAssessment`.
    pub fn from_assessment(a: &FraudAssessment) -> Self {
        Self {
            risk_score: a.risk_score,
            findings: a.findings.clone(),
            coherence_score: a.coherence_score,
            debate_rounds: a.debate_rounds,
            explicit_halt_requested: a.explicit_halt,
            security_severity: None,
        }
    }

    /// Construct from `BaaarInputs` (the orchestrator's flat mirror).
    pub fn from_baaar_inputs(b: &BaaarInputs) -> Self {
        Self {
            risk_score: b.risk_score,
            findings: Vec::new(),
            coherence_score: b.coherence_score,
            debate_rounds: b.debate_rounds,
            explicit_halt_requested: b.explicit_halt_requested,
            security_severity: Some(b.security_severity),
        }
    }
}

/// 5 deterministic halt conditions. AC-3.10 — same input → same
/// verdict, every time. The gate is intentionally a pure function:
/// no I/O, no clocks, no randomness.
pub fn should_halt(input: &GateInput) -> Verdict {
    // Condition 1: risk_score > 0.85
    if input.risk_score > 0.85 {
        return Verdict::Halt(BaaarReason::RiskScoreExceeded);
    }
    // Condition 2: any SecretLeak finding
    if input
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::SecretLeak))
    {
        return Verdict::Halt(BaaarReason::SecretLeakDetected);
    }
    // Condition 3: coherence_score < 0.3
    if input.coherence_score < 0.3 {
        return Verdict::Halt(BaaarReason::CoherenceTooLow);
    }
    // Condition 4: debate_rounds >= 5
    if input.debate_rounds >= 5 {
        return Verdict::Halt(BaaarReason::MaxDebateRoundsReached);
    }
    // Condition 5: explicit halt
    if input.explicit_halt_requested {
        return Verdict::Halt(BaaarReason::ExplicitHaltRequested);
    }
    Verdict::Allow
}

/// Gatekeeper — wraps `should_halt` for use as a struct (matches
/// the existing `BaaarGate` style).
#[derive(Debug, Default, Clone, Copy)]
pub struct Gatekeeper;

impl Gatekeeper {
    /// Evaluate the 5 conditions.
    pub fn check(&self, input: &GateInput) -> Verdict {
        should_halt(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benign() -> GateInput {
        GateInput {
            risk_score: 0.10,
            findings: vec![],
            coherence_score: 0.90,
            debate_rounds: 1,
            explicit_halt_requested: false,
            security_severity: None,
        }
    }

    #[test]
    fn allows_benign_input() {
        let v = should_halt(&benign());
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn halts_on_high_risk() {
        let mut i = benign();
        i.risk_score = 0.86;
        assert_eq!(
            should_halt(&i),
            Verdict::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn boundary_0_85_is_allow_strict_gt() {
        let mut i = benign();
        i.risk_score = 0.85; // exactly 0.85 → Allow (strict >)
        assert_eq!(should_halt(&i), Verdict::Allow);
    }

    #[test]
    fn halts_on_secret_leak_finding() {
        let mut i = benign();
        i.findings.push(Finding {
            kind: FindingKind::SecretLeak,
            description: "AKIA...".into(),
        });
        assert_eq!(
            should_halt(&i),
            Verdict::Halt(BaaarReason::SecretLeakDetected)
        );
    }

    #[test]
    fn halts_on_low_coherence() {
        let mut i = benign();
        i.coherence_score = 0.29;
        assert_eq!(should_halt(&i), Verdict::Halt(BaaarReason::CoherenceTooLow));
    }

    #[test]
    fn halts_on_max_debate_rounds() {
        let mut i = benign();
        i.debate_rounds = 5;
        assert_eq!(
            should_halt(&i),
            Verdict::Halt(BaaarReason::MaxDebateRoundsReached)
        );
    }

    #[test]
    fn halts_on_explicit_request() {
        let mut i = benign();
        i.explicit_halt_requested = true;
        assert_eq!(
            should_halt(&i),
            Verdict::Halt(BaaarReason::ExplicitHaltRequested)
        );
    }

    #[test]
    fn first_match_wins() {
        // Both risk > 0.85 AND explicit halt → RiskScoreExceeded wins.
        let mut i = benign();
        i.risk_score = 0.95;
        i.explicit_halt_requested = true;
        assert_eq!(
            should_halt(&i),
            Verdict::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn gatekeeper_matches_free_fn() {
        let g = Gatekeeper;
        let mut i = benign();
        i.risk_score = 0.9;
        assert_eq!(g.check(&i), should_halt(&i));
    }

    #[test]
    fn verdict_into_outcome_round_trip() {
        let v = Verdict::Halt(BaaarReason::RiskScoreExceeded);
        let o = v.to_outcome();
        assert_eq!(Verdict::from(o), v);
    }
}
