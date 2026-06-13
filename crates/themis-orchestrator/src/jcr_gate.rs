//! JCR Safety Gate — protects judge-type agents from KV-reuse drift.
//!
//! Ported from Apohara Context Forge's `safety/jcr_gate.py`. Based on
//! the paper "When KV Cache Reuse Fails in Multi-Agent Systems"
//! (arXiv:2601.08343, January 2026). The paper shows that aggressive
//! KV-cache reuse can silently degrade the Judge Consistency Rate
//! (JCR) of judge-type agents even when raw accuracy looks unchanged.
//! In THEMIS, the **judge-type agents** are the **Fraud Auditor** (the
//! one that decides whether to HALT) and the **Provenance Signer**
//! (the one that seals the Evidence Packet verdict).
//!
//! ## INV-15
//!
//! Any judge-class agent MUST use dense prefill — bypassing the shared
//! KV cache — whenever the JCR risk score exceeds the threshold
//! (default 0.7). The orchestrator enforces this by setting
//! `use_dense = true` on the `JcrDecision` and routing the request
//! through the **Prefix Salt Planner** (see `crate::prefix_salt`)
//! with an **isolated** salt that forces vLLM-equivalent backends
//! to allocate fresh blocks for the judge.

/// Agents considered "judge-type" in THEMIS — the protected callers
/// per INV-15. Both the Fraud Auditor and the Provenance Signer get
/// dense prefill when risky.
pub const JUDGE_ROLES: &[&str] = &["fraud_auditor", "provenance_signer"];

/// Default risk threshold above which dense prefill is mandated.
pub const DEFAULT_JCR_THRESHOLD: f32 = 0.7;

// Risk-model constants (from arXiv:2601.08343 Sec. 4 table 2).
const BASE_RISK_JUDGE: f32 = 0.6;
const BASE_RISK_OTHER: f32 = 0.1;
const RISK_PER_EXTRA_CANDIDATE: f32 = 0.10; // +0.1 per candidate beyond 2
const RISK_LAYOUT_SHUFFLED: f32 = 0.20; // +0.2 if order changed since last round
const RISK_HIGH_REUSE: f32 = 0.15; // +0.15 if reuse_rate > 0.8
const HIGH_REUSE_THRESHOLD: f32 = 0.8;
const EXTRA_CANDIDATE_BASE: usize = 2;
const RISK_CAP: f32 = 1.0;

/// Inputs the gate needs to compute a JCR risk score.
#[derive(Debug, Clone, PartialEq)]
pub struct JcrInput {
    /// The agent's role (e.g. "fraud_auditor", "extractor").
    pub agent_role: String,
    /// Number of candidates the agent will compare (e.g. 2 invoices,
    /// 3 line items). Beyond 2, each one adds risk.
    pub candidate_count: usize,
    /// Fraction of the request that will reuse cached KV blocks
    /// (0.0 = none, 1.0 = all).
    pub reuse_rate: f32,
    /// Whether the layout / order of the inputs changed since the
    /// last round (true ⇒ previous KV blocks are stale).
    pub layout_shuffled: bool,
}

impl JcrInput {
    /// Quick constructor.
    pub fn new(agent_role: impl Into<String>, candidate_count: usize) -> Self {
        Self {
            agent_role: agent_role.into(),
            candidate_count,
            reuse_rate: 0.0,
            layout_shuffled: false,
        }
    }

    /// Set the reuse rate (builder-style).
    pub fn with_reuse_rate(mut self, rate: f32) -> Self {
        self.reuse_rate = rate;
        self
    }

    /// Mark the layout as shuffled (builder-style).
    pub fn with_layout_shuffled(mut self, shuffled: bool) -> Self {
        self.layout_shuffled = shuffled;
        self
    }
}

/// The decision the gate makes for one request.
#[derive(Debug, Clone, PartialEq)]
pub struct JcrDecision {
    /// The computed JCR risk score in `[0.0, 1.0]`.
    pub risk_score: f32,
    /// Whether the orchestrator should force dense prefill (bypass
    /// the shared KV cache) for this request.
    pub use_dense: bool,
    /// Human-readable explanation (mirrors the Python `reason` field).
    pub reason: String,
}

/// Return `true` if `role` is a judge-type role per INV-15.
pub fn is_judge_role(role: &str) -> bool {
    JUDGE_ROLES.contains(&role)
}

/// Compute the JCR risk score for the given inputs.
///
/// The formula (from the paper):
/// ```text
/// base      = 0.6 if judge else 0.1
/// candidate = 0.10 * max(0, candidate_count - 2)
/// shuffle   = 0.20 if layout_shuffled else 0.0
/// reuse     = 0.15 if reuse_rate > 0.8 else 0.0
/// risk      = min(1.0, base + candidate + shuffle + reuse)
/// ```
pub fn compute_risk(input: &JcrInput) -> f32 {
    let base = if is_judge_role(&input.agent_role) {
        BASE_RISK_JUDGE
    } else {
        BASE_RISK_OTHER
    };
    let extra_candidates = input.candidate_count.saturating_sub(EXTRA_CANDIDATE_BASE);
    let candidate = RISK_PER_EXTRA_CANDIDATE * extra_candidates as f32;
    let shuffle = if input.layout_shuffled {
        RISK_LAYOUT_SHUFFLED
    } else {
        0.0
    };
    let reuse = if input.reuse_rate > HIGH_REUSE_THRESHOLD {
        RISK_HIGH_REUSE
    } else {
        0.0
    };
    (base + candidate + shuffle + reuse).min(RISK_CAP)
}

/// Decide whether the given request must use dense prefill.
///
/// `use_dense = true` when:
/// 1. The agent role is a judge-type role (INV-15 protected), AND
/// 2. The computed risk score exceeds the threshold.
///
/// Non-judge agents are never forced to dense prefill (their reuse
/// is safe per the paper's analysis).
pub fn decide(input: &JcrInput, threshold: f32) -> JcrDecision {
    let risk = compute_risk(input);
    let judge = is_judge_role(&input.agent_role);
    let use_dense = judge && risk > threshold;
    let reason = if use_dense {
        format!(
            "judge={} risk={:.3} > threshold={:.3} — dense prefill (INV-15)",
            input.agent_role, risk, threshold
        )
    } else if !judge {
        format!(
            "non-judge role={} (INV-15 only protects judges) — reuse allowed (risk={:.3})",
            input.agent_role, risk
        )
    } else {
        format!(
            "judge={} risk={:.3} ≤ threshold={:.3} — reuse allowed",
            input.agent_role, risk, threshold
        )
    };
    JcrDecision {
        risk_score: risk,
        use_dense,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn judge_input() -> JcrInput {
        // fraud_auditor with 2 candidates, no shuffle, no reuse.
        JcrInput::new("fraud_auditor", 2)
    }

    #[test]
    fn judge_with_high_risk_uses_dense() {
        // 5 candidates, layout shuffled, high reuse — risk = 0.6 + 0.3 + 0.2 + 0.15 = 1.25 → cap 1.0
        let input = judge_input()
            .with_reuse_rate(0.9)
            .with_layout_shuffled(true);
        let input = JcrInput {
            candidate_count: 5,
            ..input
        };
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        assert!(d.use_dense);
        assert!(
            (d.risk_score - 1.0).abs() < 0.01,
            "expected cap 1.0, got {}",
            d.risk_score
        );
    }

    #[test]
    fn non_judge_with_same_risk_does_not_use_dense() {
        // Same risk inputs, but role is not a judge.
        let input = JcrInput {
            agent_role: "extractor".to_string(),
            candidate_count: 5,
            reuse_rate: 0.9,
            layout_shuffled: true,
        };
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        assert!(
            !d.use_dense,
            "non-judge must never be forced to dense (INV-15 only protects judges)"
        );
        // Risk is 0.1 + 0.3 + 0.2 + 0.15 = 0.75 — but use_dense is false because not a judge.
        assert!((d.risk_score - 0.75).abs() < 0.01);
    }

    #[test]
    fn low_risk_uses_reuse() {
        // 2 candidates, no shuffle, no reuse → risk = 0.6, ≤ 0.7.
        let d = decide(&judge_input(), DEFAULT_JCR_THRESHOLD);
        assert!(!d.use_dense);
        assert!((d.risk_score - 0.6).abs() < 0.01);
    }

    #[test]
    fn baseline_non_judge_zero_candidates() {
        // 0 candidates, no shuffle, no reuse → base 0.1, no extras.
        let d = decide(&JcrInput::new("extractor", 0), DEFAULT_JCR_THRESHOLD);
        assert_eq!(d.risk_score, 0.1);
        assert!(!d.use_dense);
    }

    #[test]
    fn risk_caps_at_one_with_all_factors_maxed() {
        // 100 candidates, shuffled, high reuse — every factor maxed.
        let input = JcrInput {
            agent_role: "provenance_signer".to_string(),
            candidate_count: 100,
            reuse_rate: 1.0,
            layout_shuffled: true,
        };
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        assert_eq!(d.risk_score, 1.0);
        assert!(d.use_dense);
    }

    #[test]
    fn is_judge_role_recognises_both_judges() {
        assert!(is_judge_role("fraud_auditor"));
        assert!(is_judge_role("provenance_signer"));
    }

    #[test]
    fn is_judge_role_rejects_non_judges() {
        assert!(!is_judge_role("extractor"));
        assert!(!is_judge_role("po_matcher"));
        assert!(!is_judge_role("gaap_classifier"));
    }

    #[test]
    fn candidate_count_two_does_not_add_risk() {
        // Base 0.6 + 0 candidates (== 2 - 2) = 0.6.
        let d = decide(&judge_input(), DEFAULT_JCR_THRESHOLD);
        assert!((d.risk_score - 0.6).abs() < 0.01);
    }

    #[test]
    fn candidate_count_three_adds_one_tenth() {
        let input = JcrInput {
            candidate_count: 3,
            ..judge_input()
        };
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        // 0.6 + 0.10 = 0.70 > 0.7 → dense (strict >).
        assert!((d.risk_score - 0.70).abs() < 0.01);
        assert!(d.use_dense);
    }

    #[test]
    fn candidate_count_four_crosses_threshold() {
        let input = JcrInput {
            candidate_count: 4,
            ..judge_input()
        };
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        // 0.6 + 0.20 = 0.80 > 0.7 → dense.
        assert!((d.risk_score - 0.80).abs() < 0.01);
        assert!(d.use_dense);
    }

    #[test]
    fn high_reuse_threshold_is_strict() {
        // Exactly 0.8 reuse is NOT > 0.8 → no reuse bump.
        let input = judge_input().with_reuse_rate(0.8);
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        assert!((d.risk_score - 0.6).abs() < 0.01);
    }

    #[test]
    fn high_reuse_above_threshold_bumps_risk() {
        let input = judge_input().with_reuse_rate(0.81);
        let d = decide(&input, DEFAULT_JCR_THRESHOLD);
        // 0.6 + 0.15 = 0.75 > 0.7 → dense.
        assert!((d.risk_score - 0.75).abs() < 0.01);
        assert!(d.use_dense);
    }

    #[test]
    fn reason_field_explains_decision() {
        let d = decide(&judge_input(), DEFAULT_JCR_THRESHOLD);
        assert!(d.reason.contains("risk="));
        assert!(d.reason.contains("judge=fraud_auditor"));
    }
}
