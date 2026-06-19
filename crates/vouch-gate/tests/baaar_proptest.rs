//! vouch-gate BAAAR kill-switch proptest.
//!
//! AC-3.10: 10/10 proptest on `risk_score > 0.85` (5 deterministic
//! conditions). 200 proptest cases total across the 5 conditions.

use proptest::prelude::*;
use vouch_gate::{should_halt, BaaarReason, Finding, FindingKind, GateInput, Verdict};

fn input_strategy() -> impl Strategy<Value = GateInput> {
    (
        0.0f32..1.0f32, // risk_score
        proptest::collection::vec(
            (0..6u8).prop_map(|k| Finding {
                kind: match k {
                    0 => FindingKind::SecretLeak,
                    1 => FindingKind::PriceAnomaly,
                    2 => FindingKind::PhantomVendor,
                    3 => FindingKind::MathFraud,
                    4 => FindingKind::Duplicate,
                    _ => FindingKind::Other("custom".to_string()),
                },
                description: "test finding".to_string(),
            }),
            0..4,
        ),
        0.0f32..1.0f32,      // coherence_score
        0u32..10,            // debate_rounds
        proptest::bool::ANY, // explicit_halt_requested
    )
        .prop_map(|(risk, findings, coherence, rounds, halt)| GateInput {
            risk_score: risk,
            findings,
            coherence_score: coherence,
            debate_rounds: rounds,
            explicit_halt_requested: halt,
            security_severity: None,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Determinism: same input → same verdict, every time.
    #[test]
    fn should_halt_is_deterministic(input in input_strategy()) {
        let v1 = should_halt(&input);
        let v2 = should_halt(&input);
        let v3 = should_halt(&input);
        prop_assert_eq!(v1, v2.clone());
        prop_assert_eq!(v2, v3);
    }

    /// risk_score > 0.85 → RiskScoreExceeded (AC-3.10, condition 1).
    #[test]
    fn risk_above_threshold_halts(score in 0.851f32..1.0f32) {
        let input = GateInput {
            risk_score: score,
            findings: vec![],
            coherence_score: 0.9,
            debate_rounds: 1,
            explicit_halt_requested: false,
            security_severity: None,
        };
        prop_assert_eq!(
            should_halt(&input),
            Verdict::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    /// risk_score <= 0.85 → Allow (strict > threshold).
    #[test]
    fn risk_at_or_below_threshold_allows(score in 0.0f32..=0.85f32) {
        let input = GateInput {
            risk_score: score,
            findings: vec![],
            coherence_score: 0.9,
            debate_rounds: 1,
            explicit_halt_requested: false,
            security_severity: None,
        };
        prop_assert_eq!(should_halt(&input), Verdict::Allow);
    }

    /// SecretLeak finding → SecretLeakDetected (condition 2).
    #[test]
    fn secret_leak_finding_halts(_dummy in 0..1u8) {
        let input = GateInput {
            risk_score: 0.1,
            findings: vec![Finding {
                kind: FindingKind::SecretLeak,
                description: "AKIA...".into(),
            }],
            coherence_score: 0.9,
            debate_rounds: 1,
            explicit_halt_requested: false,
            security_severity: None,
        };
        prop_assert_eq!(
            should_halt(&input),
            Verdict::Halt(BaaarReason::SecretLeakDetected)
        );
    }

    /// coherence_score < 0.3 → CoherenceTooLow (condition 3).
    #[test]
    fn coherence_below_floor_halts(score in 0.0f32..0.3f32) {
        let input = GateInput {
            risk_score: 0.1,
            findings: vec![],
            coherence_score: score,
            debate_rounds: 1,
            explicit_halt_requested: false,
            security_severity: None,
        };
        prop_assert_eq!(
            should_halt(&input),
            Verdict::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    /// debate_rounds >= 5 → MaxDebateRoundsReached (condition 4).
    #[test]
    fn max_debate_rounds_halt(rounds in 5u32..20) {
        let input = GateInput {
            risk_score: 0.1,
            findings: vec![],
            coherence_score: 0.9,
            debate_rounds: rounds,
            explicit_halt_requested: false,
            security_severity: None,
        };
        prop_assert_eq!(
            should_halt(&input),
            Verdict::Halt(BaaarReason::MaxDebateRoundsReached)
        );
    }

    /// First-match-wins: risk > 0.85 wins over explicit halt.
    #[test]
    fn first_match_wins_ordering(
        risk in 0.9f32..1.0f32,
        rounds in 5u32..10,
    ) {
        let input = GateInput {
            risk_score: risk,
            findings: vec![Finding {
                kind: FindingKind::SecretLeak,
                description: "x".into(),
            }],
            coherence_score: 0.05,
            debate_rounds: rounds,
            explicit_halt_requested: true,
            security_severity: None,
        };
        // RiskScoreExceeded wins (condition 1 < 2 < 3 < 4 < 5).
        prop_assert_eq!(
            should_halt(&input),
            Verdict::Halt(BaaarReason::RiskScoreExceeded)
        );
    }
}
