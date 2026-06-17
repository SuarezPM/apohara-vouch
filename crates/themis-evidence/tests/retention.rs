//! US-06: configurable retention per tenant per jurisdiction.
//!
//! Asserts:
//!   - Default retention is 6 months (EU AI Act Art 12).
//!   - A 7-month-old chain entry fails the next append.
//!   - Per-tenant override (wayne = 24 months) succeeds.
//!   - `for_tenant_with_retention` honors the policy.

use std::collections::HashMap;
use std::sync::Arc;

use themis_evidence::chain::RetentionPolicy;
use themis_evidence::packet::EvidenceService;
use themis_evidence::timestamp::MockTimestampAuthority;

fn tsa() -> Arc<dyn themis_evidence::timestamp::TimestampAuthority> {
    Arc::new(MockTimestampAuthority::new("https://mock.tsa"))
}

#[tokio::test]
async fn default_retention_is_six_months() {
    let p = RetentionPolicy::default();
    assert_eq!(p.default_months, 6, "EU AI Act Art 12 = 6 months");
    assert_eq!(p.effective_months("stark", "EU"), 6);
    assert_eq!(p.effective_months("wayne", "EU"), 6);
}

#[tokio::test]
async fn per_tenant_override_takes_precedence() {
    let mut per_tenant = HashMap::new();
    per_tenant.insert("wayne".to_string(), 24);
    let p = RetentionPolicy {
        default_months: 6,
        per_tenant_overrides: per_tenant,
        per_jurisdiction_overrides: HashMap::new(),
    };
    assert_eq!(p.effective_months("wayne", "EU"), 24);
    assert_eq!(p.effective_months("stark", "EU"), 6, "other tenants use default");
}

#[tokio::test]
async fn per_jurisdiction_override_takes_precedence_over_default() {
    let mut per_jur = HashMap::new();
    per_jur.insert("US".to_string(), 12);
    let p = RetentionPolicy {
        default_months: 6,
        per_tenant_overrides: HashMap::new(),
        per_jurisdiction_overrides: per_jur,
    };
    assert_eq!(p.effective_months("stark", "US"), 12);
    assert_eq!(p.effective_months("stark", "EU"), 6);
}

#[tokio::test]
async fn seal_succeeds_within_retention_window() {
    let mut svc = EvidenceService::for_tenant("stark", tsa()).expect("baked stark");
    let p1 = svc.seal("inv-r-1", "{\"a\":1}", None).await.expect("first");
    // Same instant — second seal should still pass (window not exceeded).
    let p2 = svc.seal("inv-r-2", "{\"a\":2}", None).await.expect("second");
    assert!(p1.chain_length < p2.chain_length);
}

#[tokio::test]
async fn seal_succeeds_for_wayne_with_24_month_retention() {
    let mut per_tenant = HashMap::new();
    per_tenant.insert("wayne".to_string(), 24);
    let policy = RetentionPolicy {
        default_months: 6,
        per_tenant_overrides: per_tenant,
        per_jurisdiction_overrides: HashMap::new(),
    };
    let mut svc = EvidenceService::for_tenant_with_retention("wayne", tsa(), policy)
        .expect("baked wayne");
    let _ = svc.seal("inv-r-w-1", "{\"w\":1}", None).await.expect("seal");
    // 24 months later would still pass for wayne (US-06 test).
    // We can't fast-forward the clock on the live service, but the
    // policy resolution is verified above.
}

#[tokio::test]
async fn chain_enforce_retention_rejects_aged_entry() {
    // Drive the chain directly with explicit timestamps
    // (the live `seal` always uses `Utc::now()`, so we
    // exercise the enforcement path via `HashChain`).
    use themis_evidence::chain::{ChainError, HashChain};
    let mut chain = HashChain::new();
    // Append a fresh entry — passes retention (empty → OK).
    chain.append_with_timestamp("first", 1_000_000).expect("append 1");
    // Same instant — 0ms age, well within any window.
    let policy = RetentionPolicy::default();
    chain
        .enforce_retention(&policy, 1_000_000, "stark", "EU")
        .expect("same instant must pass");
    // 7 months later — exceeds 6-month default.
    let seven_months_ms: i64 = 7 * 30 * 86_400 * 1000;
    let res = chain.enforce_retention(
        &policy,
        1_000_000 + seven_months_ms,
        "stark",
        "EU",
    );
    assert!(
        matches!(res, Err(ChainError::RetentionExceeded { window_months: 6 })),
        "expected RetentionExceeded {{ window_months: 6 }}, got {res:?}"
    );
}
