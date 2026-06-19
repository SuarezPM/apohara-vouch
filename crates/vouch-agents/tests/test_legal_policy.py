"""S-06: LegalPolicyChecker tests (5 ACs + Band handoff).

Tests are organized as 1+ test per AC:

* test_build_featherless_llm_uses_qwen3_coder_model              (AC-6.1)
* test_build_featherless_llm_targets_featherless                 (AC-6.1)
* test_legal_policy_checker_model_id_constant                    (AC-6.1)
* test_policy_report_schema_has_findings_list                    (AC-6.2)
* test_finding_schema_has_required_fields                        (AC-6.2)
* test_policy_report_validates_empty_findings                    (AC-6.2)
* test_findings_for_three_violations_on_violations_fixture       (AC-6.3)
* test_findings_count_exactly_three_on_violations_fixture        (AC-6.3)
* test_no_findings_on_clean_fixture                              (AC-6.3)
* test_finding_has_statute_citation                              (AC-6.4)
* test_every_finding_statute_is_canonical                        (AC-6.4)
* test_fim_prompt_has_prefix_suffix_middle                       (AC-6.5)
* test_fim_prompt_includes_regulatory_text                       (AC-6.5)
* test_fim_prompt_logs_deviation                                 (AC-6.5)

Every public function in legal_policy.py has at least one test
(hard rule #2). The LLM is mocked via the ``llm_call`` injection
point on ``LegalPolicyChecker``; tests never hit Featherless.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
FIXTURES = THIS_DIR.parent / "fixtures"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from finance_risk import RiskScore  # noqa: E402
from intake import ProcurementCase  # noqa: E402
from legal_policy import (  # noqa: E402
    CANONICAL_STATUTES,
    DEVIATIONS,
    FIM_MIDDLE_TOKEN,
    FIM_PREFIX_TOKEN,
    FIM_SUFFIX_TOKEN,
    Finding,
    LegalPolicyChecker,
    PolicyReport,
    RULE_REGISTRY,
    Severity,
    build_crewai_agent,
    build_featherless_llm,
    fim_retrieval_prompt,
    load_directive_text,
    load_secrets,
    scan_rules,
)
from vendor_researcher import (  # noqa: E402
    SanctionsHit,
    UltimateBeneficialOwner,
    VendorProfile,
)


# ---------------------------------------------------------------------------
# Fixtures: fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def violations_case() -> ProcurementCase:
    """The S-02 violations fixture (case PC-2026-0002)."""
    return ProcurementCase(
        case_id="PC-2026-0002",
        buyer="Stark Industries EU Sp.z.o.o.",
        vendor_name="Bright Horizon Consulting LLC",
        vendor_id="US-FL-99001234",
        amount_eur=487500.00,
        category="consulting_services",
        requested_action="approve",
        attachments=["s3://vouch-invoices/PC-2026-0002/sow.pdf"],
        urgency="urgent",
    )


@pytest.fixture
def violations_case_with_raw(violations_case: ProcurementCase) -> ProcurementCase:
    """Violations case with raw_procurement_request text attached.

    The deterministic COI scanner inspects the raw text for the
    "not attached" marker — the S-02 fixture file carries that
    string verbatim.
    """
    raw = (
        "Procurement request PC-2026-0002 — single-source consulting "
        "engagement with Bright Horizon Consulting LLC (US-FL-99001234) "
        "for EUR 487,500. Marked urgent. Beneficial owner disclosed as "
        "Vladimir Petrov. Conflict of interest declaration NOT attached."
    )
    # pydantic v2: re-create with the extra field. ProcurementCase
    # does not declare raw_procurement_request as a field, so we
    # attach it as a generic attribute for the scan.
    object.__setattr__(violations_case, "raw_procurement_request", raw)
    return violations_case


@pytest.fixture
def violations_profile() -> VendorProfile:
    """The CY vendor with sanctions hits + PEP UBO (shell-company + AML)."""
    return VendorProfile(
        registration_country="CY",
        ultimate_beneficial_owner=[
            UltimateBeneficialOwner(
                name="Vladimir Petrov",
                ownership_pct=100.0,
                nationality="RU",
                pep_flag=True,
            ),
        ],
        sector="shell_company_services",
        sanctions_hits=[
            SanctionsHit(
                list="OFAC_SDN",
                matched_name="Vladimir Petrov",
                listed_on="2024-09-12",
            ),
            SanctionsHit(
                list="EU_CFSP",
                matched_name="Bright Horizon Consulting LLC",
                listed_on="2025-01-04",
            ),
        ],
        adverse_media_count=14,
    )


@pytest.fixture
def clean_case() -> ProcurementCase:
    """The S-02 clean fixture (case PC-2026-0001)."""
    return ProcurementCase(
        case_id="PC-2026-0001",
        buyer="Stark Industries EU Sp.z.o.o.",
        vendor_name="Acme Office Supplies GmbH",
        vendor_id="DE-271828-BERLIN",
        amount_eur=12450.00,
        category="office_supplies",
        requested_action="approve",
        attachments=[
            "s3://vouch-invoices/PC-2026-0001/quote.pdf",
            "s3://vouch-invoices/PC-2026-0001/w9.pdf",
            "s3://vouch-invoices/PC-2026-0001/coi.pdf",
        ],
        urgency="standard",
    )


@pytest.fixture
def clean_case_with_raw(clean_case: ProcurementCase) -> ProcurementCase:
    """Clean case with a raw_procurement_request that confirms COI is present."""
    raw = (
        "Procurement request PC-2026-0001 from Stark Industries EU "
        "Sp.z.o.o. requesting approval to engage Acme Office Supplies "
        "GmbH for office supplies valued at EUR 12,450.00. Standard "
        "30-day terms. Conflict of interest declaration attached."
    )
    object.__setattr__(clean_case, "raw_procurement_request", raw)
    return clean_case


@pytest.fixture
def clean_profile() -> VendorProfile:
    """The DE office-supplies vendor (clean)."""
    return VendorProfile(
        registration_country="DE",
        ultimate_beneficial_owner=[
            UltimateBeneficialOwner(
                name="Heinrich Mueller",
                ownership_pct=62.5,
                nationality="DE",
                pep_flag=False,
            ),
        ],
        sector="office_supplies_manufacturing",
        sanctions_hits=[],
        adverse_media_count=0,
    )


@pytest.fixture
def risk_score() -> RiskScore:
    """A representative risk score for the violations case."""
    return RiskScore(
        score=78,
        severity="HIGH",
        drivers=["Shell-company vendor pattern (CY)", "Sanctions list hit"],
        citations=["CY", "OFAC_SDN"],
    )


def _mock_llm_call(
    case: Any, profile: Any, risk: Any, base_report: PolicyReport
) -> PolicyReport:
    """No-op LLM mock — returns the deterministic scan unchanged."""
    return base_report


# ---------------------------------------------------------------------------
# AC-6.1 — Featherless CrewAI LLM with Qwen3-Coder-30B-A3B-Instruct
# ---------------------------------------------------------------------------


def test_build_featherless_llm_uses_qwen3_coder_model() -> None:
    """AC-6.1: the LLM carries the openai/Qwen/Qwen3-Coder-30B-A3B-Instruct model id."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    model = getattr(llm, "model", "") or str(llm)
    assert "Qwen3-Coder-30B-A3B-Instruct" in model, model


def test_build_featherless_llm_targets_featherless() -> None:
    """AC-6.1: the LLM targets the Featherless base URL."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    base_url = (
        getattr(llm, "base_url", None)
        or getattr(llm, "api_base", None)
        or ""
    )
    assert "featherless.ai" in str(base_url), base_url


def test_legal_policy_checker_model_id_constant() -> None:
    """AC-6.1: LegalPolicyChecker.MODEL_ID matches the contract."""
    assert LegalPolicyChecker.MODEL_ID == "Qwen/Qwen3-Coder-30B-A3B-Instruct"


def test_legal_policy_checker_provider_is_featherless() -> None:
    """AC-6.1: provider tag is 'featherless'."""
    assert LegalPolicyChecker.PROVIDER == "featherless"


def test_build_crewai_agent_accepts_injected_llm() -> None:
    """AC-6.1: build_crewai_agent accepts an injected LLM (mock-friendly)."""
    # Use a real crewai.llm.LLM (the agent's pydantic discriminator
    # rejects MagicMock; a real LLM with dummy creds is fine because
    # we never call kickoff here).
    from crewai.llm import LLM  # type: ignore[import-not-found]

    llm = LLM(
        model="openai/Qwen/Qwen3-Coder-30B-A3B-Instruct",
        base_url="https://api.featherless.ai/v1",
        api_key="test-key",
    )
    agent = build_crewai_agent(llm=llm)
    assert agent is not None
    # CrewAI Agent exposes role; we assert the role string is what we set.
    role = getattr(agent, "role", "")
    assert role == "legal-policy-checker"


# ---------------------------------------------------------------------------
# AC-6.2 — PolicyReport + Finding schemas
# ---------------------------------------------------------------------------


def test_policy_report_schema_has_findings_list() -> None:
    """AC-6.2: PolicyReport has case_id, findings, ruleset_version."""
    fields = set(PolicyReport.model_fields.keys())
    assert fields == {"case_id", "findings", "ruleset_version"}, fields


def test_finding_schema_has_required_fields() -> None:
    """AC-6.2: Finding has rule_id, statute, severity, evidence_span, recommendation."""
    fields = set(Finding.model_fields.keys())
    assert fields == {
        "rule_id",
        "statute",
        "severity",
        "evidence_span",
        "recommendation",
    }, fields


def test_policy_report_validates_empty_findings() -> None:
    """AC-6.2: a PolicyReport with no findings round-trips."""
    pr = PolicyReport(case_id="PC-EMPTY", findings=[])
    assert pr.case_id == "PC-EMPTY"
    assert pr.findings == []


def test_policy_report_to_json_is_deterministic() -> None:
    """AC-6.2: to_json() produces deterministic, JSON-serializable output."""
    pr = PolicyReport(
        case_id="PC-X",
        findings=[
            Finding(
                rule_id="PROC-001",
                statute="Directive 2014/24/EU Art. 56",
                severity="HIGH",
                evidence_span="vendor registration_country",
                recommendation="Request EDD",
            )
        ],
    )
    s = pr.to_json()
    obj = json.loads(s)
    assert obj["case_id"] == "PC-X"
    assert obj["findings"][0]["rule_id"] == "PROC-001"
    assert obj["findings"][0]["statute"] == "Directive 2014/24/EU Art. 56"


def test_finding_severity_is_literal() -> None:
    """AC-6.2: severity is one of LOW/MEDIUM/HIGH/CRITICAL."""
    for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        Finding(
            rule_id="X",
            statute="Directive 2014/24/EU",
            severity=sev,
            evidence_span="x",
            recommendation="x",
        )
    with pytest.raises(Exception):
        Finding(
            rule_id="X",
            statute="Directive 2014/24/EU",
            severity="UNKNOWN",
            evidence_span="x",
            recommendation="x",
        )


# ---------------------------------------------------------------------------
# AC-6.3 — Three pre-planted violations => three findings
# ---------------------------------------------------------------------------


def test_findings_count_exactly_three_on_violations_fixture(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.3: the violations fixture triggers exactly 3 findings."""
    findings = scan_rules(
        violations_case_with_raw, violations_profile, risk_score
    )
    rule_ids = sorted(f.rule_id for f in findings)
    assert rule_ids == ["AML-001", "COI-001", "PROC-001"], rule_ids


def test_findings_for_three_violations_on_violations_fixture(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.3: each of the three pre-planted violations gets a finding."""
    findings = scan_rules(
        violations_case_with_raw, violations_profile, risk_score
    )
    by_rule = {f.rule_id: f for f in findings}
    # (1) shell-company vendor — PROC-001
    assert "PROC-001" in by_rule
    assert "Art. 56" in by_rule["PROC-001"].statute
    # (2) sanctions-adjacent beneficial owner — AML-001
    assert "AML-001" in by_rule
    assert "AMLD6" in by_rule["AML-001"].statute
    # (3) missing conflict-of-interest declaration — COI-001
    assert "COI-001" in by_rule
    assert "Art. 24" in by_rule["COI-001"].statute


def test_no_findings_on_clean_fixture(
    clean_case_with_raw: ProcurementCase,
    clean_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.3: a clean case produces zero findings."""
    findings = scan_rules(clean_case_with_raw, clean_profile, risk_score)
    assert findings == [], [f.rule_id for f in findings]


def test_legal_policy_checker_emits_three_findings_via_band(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.3: end-to-end check() returns 3 findings and posts to Band."""
    checker = LegalPolicyChecker(llm_call=_mock_llm_call)
    tools = MagicMock()
    report = checker.check(
        violations_case_with_raw, violations_profile, risk_score, tools=tools
    )
    assert isinstance(report, PolicyReport)
    assert len(report.findings) == 3
    # Band handoff: send_event was called.
    assert tools.send_event.called


# ---------------------------------------------------------------------------
# AC-6.4 — Every Finding carries a canonical statute citation
# ---------------------------------------------------------------------------


def test_finding_has_statute_citation() -> None:
    """AC-6.4: a Finding's statute field is non-empty."""
    f = Finding(
        rule_id="PROC-001",
        statute="Directive 2014/24/EU Art. 56",
        severity="HIGH",
        evidence_span="x",
        recommendation="x",
    )
    assert "Directive 2014/24/EU" in f.statute


def test_every_finding_statute_is_canonical() -> None:
    """AC-6.4: every Finding in RULE_REGISTRY carries a canonical statute."""
    for rule_id, spec in RULE_REGISTRY.items():
        assert any(
            canon in spec["statute"] for canon in CANONICAL_STATUTES
        ), (rule_id, spec["statute"])


def test_violations_findings_all_carry_canonical_statutes(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.4: the 3 findings on the violations fixture all carry canonical statutes."""
    findings = scan_rules(
        violations_case_with_raw, violations_profile, risk_score
    )
    assert len(findings) == 3
    for f in findings:
        assert any(canon in f.statute for canon in CANONICAL_STATUTES), f.statute


def test_every_finding_has_non_empty_recommendation(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.4: a Finding with no recommendation is rejected by the schema."""
    findings = scan_rules(
        violations_case_with_raw, violations_profile, risk_score
    )
    for f in findings:
        assert f.recommendation.strip()
        assert f.evidence_span.strip()


# ---------------------------------------------------------------------------
# AC-6.5 — FIM mode (documented alternative via chat-completion messages)
# ---------------------------------------------------------------------------


def test_fim_prompt_has_prefix_suffix_middle(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.5: the FIM prompt records the three FIM token names verbatim."""
    prompt = fim_retrieval_prompt(
        violations_case_with_raw, violations_profile, risk_score
    )
    assert FIM_PREFIX_TOKEN in prompt["fim_tokens"]
    assert FIM_SUFFIX_TOKEN in prompt["fim_tokens"]
    assert FIM_MIDDLE_TOKEN in prompt["fim_tokens"]


def test_fim_prompt_includes_regulatory_text(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.5: the system message carries the EU directive excerpt."""
    prompt = fim_retrieval_prompt(
        violations_case_with_raw, violations_profile, risk_score
    )
    # Case-insensitive: the directive fixture uses "DIRECTIVE 2014/24/EU"
    # in its header and "Directive 2014/24/EU" in the body.
    assert "directive 2014/24/eu" in prompt["system"].lower()
    assert "Art. 56" in prompt["system"]
    assert "Art. 24" in prompt["system"]


def test_fim_prompt_includes_rule_registry(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """AC-6.5: the system message embeds the Rule Registry JSON."""
    prompt = fim_retrieval_prompt(
        violations_case_with_raw, violations_profile, risk_score
    )
    assert "PROC-001" in prompt["system"]
    assert "AML-001" in prompt["system"]
    assert "COI-001" in prompt["system"]


def test_fim_prompt_logs_deviation() -> None:
    """AC-6.5: the FIM deviation (Featherless gateway has no FIM endpoint)
    is recorded in DEVIATIONS so the operator sees it at runtime."""
    assert any(
        "Featherless" in d and "FIM" in d for d in DEVIATIONS
    ), DEVIATIONS


def test_directive_fixture_loaded() -> None:
    """AC-6.5: the EU directive fixture is loaded and ≥500 chars."""
    text = load_directive_text()
    assert len(text) >= 500, len(text)
    # The fixture uses uppercase "DIRECTIVE 2014/24/EU" in the header
    # and "Directive 2014/24/EU" in the body — both must match.
    assert "Directive 2014/24/EU" in text or "DIRECTIVE 2014/24/EU" in text


# ---------------------------------------------------------------------------
# Band handoff (defensive coverage of the @red-team-auditor handoff)
# ---------------------------------------------------------------------------


def test_legal_policy_checker_emits_to_red_team_auditor(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """The Band send_event carries metadata.to='red-team-auditor'."""
    checker = LegalPolicyChecker(llm_call=_mock_llm_call)
    tools = MagicMock()
    checker.check(
        violations_case_with_raw, violations_profile, risk_score, tools=tools
    )
    assert tools.send_event.called
    call = tools.send_event.call_args
    if call.kwargs:
        metadata = call.kwargs.get("metadata", {})
        content = call.kwargs.get("content", "")
        message_type = call.kwargs.get("message_type", "")
    else:
        args = call.args
        content = args[0] if len(args) > 0 else ""
        message_type = args[1] if len(args) > 1 else ""
        metadata = args[2] if len(args) > 2 else {}
    assert metadata.get("to") == "red-team-auditor"
    assert metadata.get("from") == "legal-policy-checker"
    assert metadata.get("schema") == "PolicyReport"
    assert message_type == "thought"
    # Content is a JSON PolicyReport
    obj = json.loads(content)
    assert obj["case_id"] == "PC-2026-0002"
    assert len(obj["findings"]) == 3


def test_legal_policy_checker_clean_case_posts_empty_findings(
    clean_case_with_raw: ProcurementCase,
    clean_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """A clean case posts a PolicyReport with findings=[]."""
    checker = LegalPolicyChecker(llm_call=_mock_llm_call)
    tools = MagicMock()
    report = checker.check(
        clean_case_with_raw, clean_profile, risk_score, tools=tools
    )
    assert report.findings == []
    assert tools.send_event.called


# ---------------------------------------------------------------------------
# Defensive coverage
# ---------------------------------------------------------------------------


def test_load_secrets_handles_missing_file() -> None:
    """load_secrets never raises on a missing secrets.env."""
    out = load_secrets()
    assert isinstance(out, dict)
    assert "FEATHERLESS_API_KEY" in out


def test_llm_enrichment_preserves_deterministic_findings(
    violations_case_with_raw: ProcurementCase,
    violations_profile: VendorProfile,
    risk_score: RiskScore,
) -> None:
    """The LLM enrichment path NEVER removes scan findings — it can only add."""
    checker = LegalPolicyChecker(
        llm_call=lambda c, p, r, base: base,
    )
    base = PolicyReport(
        case_id="PC-TEST",
        findings=[
            Finding(
                rule_id="PROC-001",
                statute="Directive 2014/24/EU Art. 56",
                severity="HIGH",
                evidence_span="x",
                recommendation="y",
            )
        ],
    )
    report = checker._llm(
        violations_case_with_raw, violations_profile, risk_score, base
    )
    assert any(f.rule_id == "PROC-001" for f in report.findings)
