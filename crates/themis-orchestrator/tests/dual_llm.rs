//! Integration tests for Story C-07 — Dual-LLM split (ASI01 3rd
//! defense / G14 / AC7).
//!
//! Pattern from Microsoft Zero Trust SFI 2026: a privileged LLM
//! (sees user data) and a quarantined LLM (sees only sanitized
//! data) are strictly isolated. Cross-taint is detected and
//! blocked. C-07 is the 3rd defense layer after C-03 INV-15
//! verification and C-02 AgentGuard regex input firewall.

use std::sync::{Arc, Mutex};

use themis_orchestrator::dual_llm::{DualLlm, DualLlmError, LlmBackend, RedactionPolicy};

/// Mock LLM that records every prompt it was sent, and returns a
/// canned response. The probe is wrapped in `Arc` so the test can
/// inspect `last_prompt()` after the value is moved into the
/// `Box<dyn LlmBackend>` that `DualLlm` owns.
struct ProbeLlm {
    last_prompt: Mutex<String>,
    response: String,
}

impl ProbeLlm {
    fn new(response: impl Into<String>) -> Self {
        Self {
            last_prompt: Mutex::new(String::new()),
            response: response.into(),
        }
    }

    fn last_prompt(&self) -> String {
        self.last_prompt.lock().expect("probe poisoned").clone()
    }
}

impl LlmBackend for ProbeLlm {
    fn complete(&self, prompt: &str) -> Result<String, DualLlmError> {
        *self.last_prompt.lock().expect("probe poisoned") = prompt.to_string();
        Ok(self.response.clone())
    }
}

/// Newtype adapter: lets a test put an `Arc<ProbeLlm>` behind
/// `Box<dyn LlmBackend>` and still inspect the probe afterwards.
struct SharedProbe(Arc<ProbeLlm>);

impl LlmBackend for SharedProbe {
    fn complete(&self, prompt: &str) -> Result<String, DualLlmError> {
        self.0.as_ref().complete(prompt)
    }
}

/// End-to-end flow: privileged LLM returns PII, run_quarantined
/// sanitizes before forwarding. Verify the quarantined LLM
/// receives the sanitized version (no email, no phone).
#[test]
fn test_full_split_flow() {
    let priv_llm = Arc::new(ProbeLlm::new("priv-response"));
    let quar_llm = Arc::new(ProbeLlm::new("quar-response"));
    let dual = DualLlm::new(
        Box::new(SharedProbe(Arc::clone(&priv_llm))),
        Box::new(SharedProbe(Arc::clone(&quar_llm))),
    );

    // Privileged step.
    let priv_out = dual
        .run_privileged("send invoice to alice@example.com 555-1234")
        .expect("privileged ok");
    assert_eq!(priv_out, "priv-response");
    assert_eq!(
        priv_llm.last_prompt(),
        "send invoice to alice@example.com 555-1234",
        "privileged LLM must see the raw prompt"
    );

    // Quarantined step: feeds the privileged output through
    // redaction before calling the quarantined LLM.
    let quar_out = dual
        .run_quarantined("Send to alice@example.com 555-123-4567")
        .expect("quarantined ok");
    assert_eq!(quar_out, "quar-response");

    // The quarantined LLM MUST have seen the sanitized prompt —
    // no raw email, no raw phone, the [REDACTED] marker is present.
    let received = quar_llm.last_prompt();
    assert!(
        !received.contains("alice@example.com"),
        "quarantined LLM saw raw email: {received}"
    );
    assert!(
        !received.contains("555-123-4567"),
        "quarantined LLM saw raw phone: {received}"
    );
    assert!(received.contains("[REDACTED]"));
}

/// Cross-taint detection: a privileged leak that survives
/// sanitization is blocked.
#[test]
fn test_cross_taint_detection() {
    let priv_llm = Arc::new(ProbeLlm::new("p"));
    let quar_llm = Arc::new(ProbeLlm::new("q"));
    let dual = DualLlm::new(
        Box::new(SharedProbe(Arc::clone(&priv_llm))),
        Box::new(SharedProbe(Arc::clone(&quar_llm))),
    );

    // Privileged text has NO email. The quarantined prompt HAS an
    // email — it could not have come from sanitization of the
    // privileged text, so it is a cross-taint.
    let privileged = "no pii here, just prose";
    let quarantined = "leaked alice@example.com into quarantined";
    let result = dual.check_cross_taint(quarantined, privileged);
    assert!(
        matches!(result, Err(DualLlmError::CrossTaint)),
        "expected CrossTaint, got {result:?}"
    );

    // Clean sanitized text: the privileged text HAS the email,
    // the quarantined prompt does not match any pattern.
    let privileged_ok = "Send to alice@example.com and 555-123-4567";
    let quarantined_ok = "Send to [REDACTED] and [REDACTED]";
    let result_ok = dual.check_cross_taint(quarantined_ok, privileged_ok);
    assert!(
        result_ok.is_ok(),
        "clean sanitized text must pass: {result_ok:?}"
    );
}

/// Custom redaction patterns: caller supplies a policy with
/// patterns of their own. Verify the policy is honored.
#[test]
fn test_redaction_policy_custom() {
    // Custom policy: redact employee IDs (E-NNNN) and account
    // numbers (ACC-NNNNNNNN).
    let employee = regex::Regex::new(r"\bE-\d{4}\b").expect("employee regex");
    let account = regex::Regex::new(r"\bACC-\d{8}\b").expect("account regex");
    let policy = RedactionPolicy::new(vec![employee, account]);

    let priv_llm = Arc::new(ProbeLlm::new("p"));
    let quar_llm = Arc::new(ProbeLlm::new("q"));
    let dual = DualLlm::with_policy(
        Box::new(SharedProbe(Arc::clone(&priv_llm))),
        Box::new(SharedProbe(Arc::clone(&quar_llm))),
        policy,
    );

    // Default email pattern is NOT in the custom policy; email
    // must leak through.
    let out = dual.sanitize("E-1234 alice@example.com ACC-12345678");
    assert!(!out.contains("E-1234"), "employee id leaked: {out}");
    assert!(!out.contains("ACC-12345678"), "account leaked: {out}");
    assert!(
        out.contains("alice@example.com"),
        "email (not in custom policy) should not be redacted: {out}"
    );
    assert!(out.contains("[REDACTED]"));
}
