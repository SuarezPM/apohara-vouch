//! BAAAR determinism proptest (Story C-09 / G29 / AC9).
//!
//! Runs 1210 randomized `BaaarInputs` through `should_halt` and
//! asserts the function is deterministic (same input → same
//! boolean) on each case. Plus a 360-case manual sweep over the
//! threshold boundaries to confirm the strict-comparison semantics.
//!
//! The "Z3" in the story title is aspirational: the Z3 port of
//! `apohara-contextforge/z3_inv15_proof.py` is deferred (that
//! proof is Python; a Rust Z3 port is a follow-up). This proptest
//! gives a strong statistical signal — 1210 cases is enough to
//! catch any non-determinism (a hidden clock, an LLM call, a hash
//! of memory addresses, etc.) with very high probability.
//!
//! Run:
//! ```
//! cargo test -p themis-orchestrator --test baaar_z3_1210 --release
//! ```

use proptest::prelude::*;
use themis_orchestrator::baaar_z3::{self, BaaarInputs, SecuritySeverity};

// 1210 generated cases. This is the headline number from the
// story spec; it exceeds 1000 (a round number for "lots of cases")
// by enough to comfortably detect any flaky non-determinism.
const GENERATED_CASES: u32 = 1210;

// 360 manual boundary cases covering the strict-comparison
// thresholds: risk_score {0.849, 0.850, 0.851, 0.90, 0.99},
// coherence_score {0.299, 0.300, 0.301}, debate_rounds {4, 5, 6},
// severity {Low, Medium, High, Critical}, explicit {false, true}.
// 5 * 3 * 3 * 4 * 2 = 360. The story spec says "100-case manual
// sweep"; this is a superset (every combination of boundary
// values), giving stronger coverage. We assert count >= 100.
const MANUAL_CASES_MIN: usize = 100;

/// proptest strategy for `BaaarInputs` with realistic value ranges.
///
/// `risk_score` and `coherence_score` are drawn from `0.0..=1.0`.
/// `debate_rounds` is drawn from `0..=10` (well past the 5-round
/// halt threshold). `security_severity` is uniformly chosen.
/// `explicit_halt_requested` is a 50/50 boolean.
fn inputs_strategy() -> BoxedStrategy<BaaarInputs> {
    (
        0.0_f32..=1.0,
        prop_oneof![
            Just(SecuritySeverity::Low),
            Just(SecuritySeverity::Medium),
            Just(SecuritySeverity::High),
            Just(SecuritySeverity::Critical),
        ],
        0.0_f32..=1.0,
        0_u32..=10,
        any::<bool>(),
    )
        .prop_map(
            |(risk_score, security_severity, coherence_score, debate_rounds, explicit_halt_requested)| {
                BaaarInputs {
                    risk_score,
                    security_severity,
                    coherence_score,
                    debate_rounds,
                    explicit_halt_requested,
                }
            },
        )
        .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GENERATED_CASES))]

    /// Determinism: `should_halt(inputs) == should_halt(inputs)`
    /// for any random input. This is the core AC9 guarantee.
    #[test]
    fn baaar_should_halt_is_deterministic(inputs in inputs_strategy()) {
        let first = baaar_z3::should_halt(&inputs);
        let second = baaar_z3::should_halt(&inputs);
        let third = baaar_z3::should_halt(&inputs);
        prop_assert_eq!(first, second, "first != second on same input");
        prop_assert_eq!(second, third, "second != third on same input");
    }

    /// Determinism with a mutated copy: same logical input, same
    /// decision. Proves the function doesn't depend on identity
    /// (e.g. pointer hashing) — only on field values.
    #[test]
    fn baaar_determinism_independent_of_identity(
        inputs in inputs_strategy()
    ) {
        let copy = inputs.clone();
        prop_assert_eq!(
            baaar_z3::should_halt(&inputs),
            baaar_z3::should_halt(&copy),
        );
    }
}

#[test]
fn baaar_manual_threshold_sweep() {
    // Boundary values from the story spec. These are the precise
    // thresholds that could trip up a sloppy implementation
    // (off-by-one, non-strict comparisons, etc.).
    let risk_scores = [0.849_f32, 0.850, 0.851, 0.90, 0.99];
    let coherence_scores = [0.299_f32, 0.300, 0.301];
    let debate_rounds = [4_u32, 5, 6];
    let severities = [
        SecuritySeverity::Low,
        SecuritySeverity::Medium,
        SecuritySeverity::High,
        SecuritySeverity::Critical,
    ];
    let explicit = [false, true];

    let mut count = 0_usize;
    for &risk in &risk_scores {
        for &coherence in &coherence_scores {
            for &rounds in &debate_rounds {
                for &severity in &severities {
                    for &halt in &explicit {
                        let inputs = BaaarInputs {
                            risk_score: risk,
                            security_severity: severity,
                            coherence_score: coherence,
                            debate_rounds: rounds,
                            explicit_halt_requested: halt,
                        };
                        // Determinism: 3 calls, all equal.
                        let a = baaar_z3::should_halt(&inputs);
                        let b = baaar_z3::should_halt(&inputs);
                        let c = baaar_z3::should_halt(&inputs);
                        assert_eq!(a, b, "a != b at boundary case #{count}");
                        assert_eq!(b, c, "b != c at boundary case #{count}");

                        // Cross-check the expected boolean against the
                        // hand-computed truth table for each case.
                        let expected = risk > 0.85
                            || severity == SecuritySeverity::Critical
                            || coherence < 0.3
                            || rounds >= 5
                            || halt;
                        assert_eq!(
                            a, expected,
                            "expected halt={expected} got halt={a} \
                             for risk={risk} sev={severity:?} coh={coherence} \
                             rounds={rounds} explicit={halt} (case #{count})"
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    // Sanity: the loop must run the expected number of cases.
    // 5 * 3 * 3 * 4 * 2 = 360. The story spec asks for ≥100.
    assert_eq!(count, 360, "manual sweep should produce 360 cases, got {count}");
    assert!(count >= MANUAL_CASES_MIN, "manual sweep produced {count} < {MANUAL_CASES_MIN} cases");
}
