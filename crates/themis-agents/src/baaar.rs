//! BAAAR kill-switch — the wow moment of the demo.
//!
//! Five conditions, all of which trigger HALT when present. The LLM
//! is the *producer* of `risk_score` and `findings`; the gate is the
//! *judge* (deterministic). This split is the entire reason AC4
//! (BAAAR 10/10 deterministic) holds.

use serde::{Deserialize, Serialize};

/// A single finding from the Fraud Auditor's LLM call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// What kind of finding this is.
    pub kind: FindingKind,
    /// Human-readable description (goes into the Evidence Packet).
    pub description: String,
}

/// The 6 kinds of fraud findings. Serialized as a flat string so the
/// LLM contract stays simple: the LLM produces a JSON object with a
/// `kind` string field. The `Other` variant carries the custom tag
/// as its serialized form (so a custom kind `"chargeback_dispute"`
/// round-trips cleanly).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// Secret pattern (AWS, OpenAI, etc.) detected in the invoice.
    SecretLeak,
    /// Price anomaly (3x PO, etc.).
    PriceAnomaly,
    /// Vendor doesn't exist in the PO database.
    PhantomVendor,
    /// Line items don't sum to the total.
    MathFraud,
    /// Same vendor+amount+date as a recent invoice.
    Duplicate,
    /// Anything else (custom string tag).
    Other(String),
}

impl FindingKind {
    /// Wire-format string. Stable identifiers used in the Evidence
    /// Packet + telemetry.
    pub fn as_str(&self) -> &str {
        match self {
            FindingKind::SecretLeak => "secret_leak",
            FindingKind::PriceAnomaly => "price_anomaly",
            FindingKind::PhantomVendor => "phantom_vendor",
            FindingKind::MathFraud => "math_fraud",
            FindingKind::Duplicate => "duplicate",
            FindingKind::Other(s) => s.as_str(),
        }
    }
}

impl serde::Serialize for FindingKind {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for FindingKind {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Ok(match s.as_str() {
            "secret_leak" => FindingKind::SecretLeak,
            "price_anomaly" => FindingKind::PriceAnomaly,
            "phantom_vendor" => FindingKind::PhantomVendor,
            "math_fraud" => FindingKind::MathFraud,
            "duplicate" => FindingKind::Duplicate,
            other => FindingKind::Other(other.to_string()),
        })
    }
}

/// The full assessment the LLM produces, before the BAAAR gate
/// evaluates it. All fields are required (the gate checks each one).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudAssessment {
    /// 0.0..=1.0 risk score from the LLM.
    pub risk_score: f32,
    /// All findings the LLM identified.
    pub findings: Vec<Finding>,
    /// 0.0..=1.0 coherence of the agent debate (the LLM rates how
    /// internally consistent the debate was).
    pub coherence_score: f32,
    /// Number of debate rounds so far.
    pub debate_rounds: u32,
    /// Whether the operator explicitly requested HALT.
    pub explicit_halt: bool,
}

/// The gate's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No HALT condition triggered; proceed.
    Approve,
    /// At least one HALT condition triggered.
    Halt(BaaarReason),
}

/// Why the gate halted. Each variant maps to exactly one BAAAR
/// condition (so the Evidence Packet can surface "halted on
/// SecretLeak" precisely).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaaarReason {
    /// `risk_score > 0.85`.
    RiskScoreExceeded,
    /// `findings` contained a `SecretLeak`.
    SecretLeakDetected,
    /// `coherence_score < 0.3`.
    CoherenceTooLow,
    /// `debate_rounds >= 5`.
    MaxDebateRoundsReached,
    /// `explicit_halt == true`.
    ExplicitHaltRequested,
}

// Thresholds (named constants for evidence-packet audit).
const RISK_SCORE_HALT: f32 = 0.85;
const COHERENCE_FLOOR: f32 = 0.3;
const MAX_DEBATE_ROUNDS: u32 = 5;

/// The kill-switch. `check` is pure: same input → same output, no
/// I/O, no clock. That's what makes AC4 (10/10 deterministic) work.
#[derive(Debug, Default, Clone, Copy)]
pub struct BaaarGate;

impl BaaarGate {
    /// New gate (no state; const-fn construction is fine).
    pub fn new() -> Self {
        Self
    }

    /// Evaluate the assessment. Returns `Halt(reason)` if any of the
    /// 5 conditions is met, otherwise `Approve`. The first matching
    /// reason wins (so the Evidence Packet shows a single, precise
    /// halt cause).
    pub fn check(&self, a: &FraudAssessment) -> Outcome {
        if a.risk_score > RISK_SCORE_HALT {
            return Outcome::Halt(BaaarReason::RiskScoreExceeded);
        }
        if a.findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::SecretLeak))
        {
            return Outcome::Halt(BaaarReason::SecretLeakDetected);
        }
        if a.coherence_score < COHERENCE_FLOOR {
            return Outcome::Halt(BaaarReason::CoherenceTooLow);
        }
        if a.debate_rounds >= MAX_DEBATE_ROUNDS {
            return Outcome::Halt(BaaarReason::MaxDebateRoundsReached);
        }
        if a.explicit_halt {
            return Outcome::Halt(BaaarReason::ExplicitHaltRequested);
        }
        Outcome::Approve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FraudAssessment {
        FraudAssessment {
            risk_score: 0.5,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: false,
        }
    }

    #[test]
    fn approves_when_no_conditions_triggered() {
        assert_eq!(BaaarGate::new().check(&base()), Outcome::Approve);
    }

    #[test]
    fn halts_on_risk_score_above_threshold() {
        let mut a = base();
        a.risk_score = 0.86;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn risk_score_threshold_is_strict() {
        // Exactly 0.85 does NOT trigger (strict >).
        let mut a = base();
        a.risk_score = 0.85;
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_secret_leak_finding() {
        let mut a = base();
        a.findings.push(Finding {
            kind: FindingKind::SecretLeak,
            description: "AWS key in line item notes".to_string(),
        });
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::SecretLeakDetected)
        );
    }

    #[test]
    fn price_anomaly_alone_does_not_halt() {
        // PriceAnomaly is logged but does NOT trigger HALT by itself
        // (no threshold). The LLM also raises risk_score for price
        // anomalies, which DOES halt.
        let mut a = base();
        a.findings.push(Finding {
            kind: FindingKind::PriceAnomaly,
            description: "3x PO expected".to_string(),
        });
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_coherence_below_floor() {
        let mut a = base();
        a.coherence_score = 0.29;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn coherence_floor_is_strict() {
        // Exactly 0.3 does NOT trigger.
        let mut a = base();
        a.coherence_score = 0.3;
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_max_debate_rounds() {
        let mut a = base();
        a.debate_rounds = 5;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::MaxDebateRoundsReached)
        );
    }

    #[test]
    fn halts_on_explicit_halt_request() {
        let mut a = base();
        a.explicit_halt = true;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::ExplicitHaltRequested)
        );
    }

    #[test]
    fn first_matching_condition_wins() {
        // Both risk and secret leak present — risk wins (checked first).
        let mut a = base();
        a.risk_score = 0.99;
        a.findings.push(Finding {
            kind: FindingKind::SecretLeak,
            description: "key".to_string(),
        });
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn finding_kind_serializes_as_flat_string() {
        // Plain string per FindingKind: "secret_leak", "price_anomaly", etc.
        let f = Finding {
            kind: FindingKind::SecretLeak,
            description: "x".to_string(),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["kind"], "secret_leak");

        let f2 = Finding {
            kind: FindingKind::Other("custom".to_string()),
            description: "y".to_string(),
        };
        let v2 = serde_json::to_value(&f2).unwrap();
        assert_eq!(v2["kind"], "custom");
    }
}
