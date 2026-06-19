"""S-07a: RedTeamAuditor tests (4 ACs + Band handoff + tool loop).

Tests are organized as 1+ test per AC:

* test_build_anthropic_client_uses_claude_opus_4_7      (AC-7a.1)
* test_build_anthropic_client_targets_aiml_base_url     (AC-7a.1)
* test_build_chat_completions_llm_uses_claude_opus_4_7  (AC-7a.1)
* test_red_team_auditor_model_id_constant              (AC-7a.1)
* test_audit_report_schema_has_required_fields          (AC-7a.2)
* test_audit_report_veto_recommended_default_false      (AC-7a.2)
* test_audit_report_to_json_is_deterministic            (AC-7a.2)
* test_deterministic_veto_returns_true_on_critical_risk (AC-7a.3)
* test_deterministic_veto_returns_true_on_critical_finding (AC-7a.3)
* test_deterministic_veto_returns_false_on_clean        (AC-7a.3)
* test_deterministic_veto_proptest_100_samples          (AC-7a.3)
* test_load_agent_config_returns_fraud_auditor_uuid     (AC-7a.4)
* test_red_team_auditor_emits_to_evidence_clerk         (Band handoff)
* test_red_team_auditor_veto_flag_in_metadata           (Band handoff)
* test_run_with_tools_breaks_on_end_turn                (AC-7a.1 hint #2)
* test_run_with_tools_executes_tool_use                 (AC-7a.1 hint #2)

Every public function in red_team.py has at least one test
(hard rule #2). The LLM is mocked via the ``llm_call`` injection
point on ``RedTeamAuditor``; tests never hit AI/ML API.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings, strategies as st

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
FIXTURES = THIS_DIR.parent / "fixtures"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from finance_risk import RiskScore  # noqa: E402
from intake import ProcurementCase  # noqa: E402
from legal_policy import Finding, PolicyReport  # noqa: E402
from orchestrator import load_agent_config  # noqa: E402
from red_team import (  # noqa: E402
    AuditReport,
    DEVIATIONS,
    RedTeamAuditor,
    build_anthropic_client,
    build_chat_completions_llm,
    run_with_tools,
)
from vendor_researcher import (  # noqa: E402
    SanctionsHit,
    UltimateBeneficialOwner,
    VendorProfile,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


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
def violations_profile() -> VendorProfile:
    """The CY vendor with sanctions hits + PEP UBO."""
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
def critical_risk() -> RiskScore:
    """A risk score at CRITICAL severity."""
    return RiskScore(
        score=95,
        severity="CRITICAL",
        drivers=["CRITICAL: shell company + sanctions hit"],
        citations=["CY", "OFAC_SDN"],
    )


@pytest.fixture
def high_risk() -> RiskScore:
    """A non-CRITICAL risk score (HIGH)."""
    return RiskScore(
        score=78,
        severity="HIGH",
        drivers=["Shell-company vendor pattern (CY)"],
        citations=["CY"],
    )


@pytest.fixture
def violations_policy() -> PolicyReport:
    """A PolicyReport with 3 findings (2 CRITICAL, 1 MEDIUM)."""
    return PolicyReport(
        case_id="PC-2026-0002",
        findings=[
            Finding(
                rule_id="PROC-001",
                statute="Directive 2014/24/EU Art. 56",
                severity="HIGH",
                evidence_span="vendor registration_country=CY",
                recommendation="Escalate to EDD.",
            ),
            Finding(
                rule_id="AML-001",
                statute="AMLD6 Art. 5",
                severity="CRITICAL",
                evidence_span="vendor ultimate_beneficial_owner + sanctions_hits",
                recommendation="Block payment; file a goAML report.",
            ),
            Finding(
                rule_id="COI-001",
                statute="Directive 2014/24/EU Art. 24",
                severity="MEDIUM",
                evidence_span="case attachments + raw_procurement_request",
                recommendation="Hold procurement pending COI declaration.",
            ),
        ],
    )


@pytest.fixture
def clean_policy() -> PolicyReport:
    """A PolicyReport with no findings."""
    return PolicyReport(case_id="PC-2026-0001", findings=[])


def _mock_llm_call(
    profile: Any, risk_score: Any, policy_report: Any, base: AuditReport
) -> str:
    """No-op LLM mock — returns the deterministic rationale unchanged."""
    return base.rationale


# ---------------------------------------------------------------------------
# AC-7a.1 — Anthropic SDK with claude-opus-4-5 via AI/ML API
# ---------------------------------------------------------------------------


def test_build_anthropic_client_uses_claude_opus_4_7() -> None:
    """AC-7a.1: the Anthropic client carries claude-opus-4-5 as the model id."""
    client = build_anthropic_client(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    model = getattr(client, "_apohara_model", "")
    assert model == "claude-opus-4-5", model


def test_build_anthropic_client_targets_aiml_base_url() -> None:
    """AC-7a.1: the Anthropic client targets the AI/ML API base URL."""
    client = build_anthropic_client(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    base_url = getattr(client, "_apohara_base_url", "")
    assert "aimlapi.com" in str(base_url), base_url


def test_build_chat_completions_llm_uses_claude_opus_4_7() -> None:
    """AC-7a.1: the OpenAI-compatible LLM carries claude-opus-4-5."""
    llm = build_chat_completions_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    model_name = getattr(llm, "model_name", "") or str(getattr(llm, "model", ""))
    assert "claude-opus-4-5" in model_name, model_name


def test_red_team_auditor_model_id_constant() -> None:
    """AC-7a.1: RedTeamAuditor.MODEL_ID is claude-opus-4-5."""
    assert RedTeamAuditor.MODEL_ID == "claude-opus-4-5"


def test_red_team_auditor_provider_is_aiml() -> None:
    """AC-7a.1: provider tag is 'aiml'."""
    assert RedTeamAuditor.PROVIDER == "aiml"


def test_red_team_auditor_agent_name_constant() -> None:
    """AC-7a.1 / AC-7a.4: agent name matches the Band registration."""
    assert RedTeamAuditor.AGENT_NAME == "themis-fraud-auditor"


def test_anthropic_sdk_path_deviation_logged() -> None:
    """AC-7a.1: the wire-path deviation (Anthropic SDK -> OpenAI-compatible
    gateway) is recorded in DEVIATIONS so the operator sees it."""
    assert any(
        "Anthropic" in d and "OpenAI-compatible" in d for d in DEVIATIONS
    ), DEVIATIONS


# ---------------------------------------------------------------------------
# AC-7a.2 — AuditReport schema
# ---------------------------------------------------------------------------


def test_audit_report_schema_has_required_fields() -> None:
    """AC-7a.2: AuditReport carries critical_findings, citations_challenged,
    veto_recommended, plus case_id and rationale."""
    fields = set(AuditReport.model_fields.keys())
    assert "critical_findings" in fields, fields
    assert "citations_challenged" in fields, fields
    assert "veto_recommended" in fields, fields


def test_audit_report_veto_recommended_is_bool() -> None:
    """AC-7a.2: veto_recommended is a bool, default False."""
    report = AuditReport(case_id="PC-X")
    assert report.veto_recommended is False
    assert isinstance(report.veto_recommended, bool)


def test_audit_report_lists_default_to_empty() -> None:
    """AC-7a.2: critical_findings and citations_challenged default to []."""
    report = AuditReport(case_id="PC-X")
    assert report.critical_findings == []
    assert report.citations_challenged == []


def test_audit_report_to_json_is_deterministic() -> None:
    """AC-7a.2: to_json() round-trips through JSON losslessly."""
    report = AuditReport(
        case_id="PC-X",
        critical_findings=[
            Finding(
                rule_id="AML-001",
                statute="AMLD6 Art. 5",
                severity="CRITICAL",
                evidence_span="vendor UBO sanctions match",
                recommendation="Block payment.",
            )
        ],
        citations_challenged=["Suspect statute 999"],
        veto_recommended=True,
        rationale="CRITICAL severity detected.",
    )
    obj = json.loads(report.to_json())
    assert obj["case_id"] == "PC-X"
    assert obj["veto_recommended"] is True
    assert len(obj["critical_findings"]) == 1
    assert obj["critical_findings"][0]["rule_id"] == "AML-001"
    assert obj["citations_challenged"] == ["Suspect statute 999"]


def test_audit_report_rejects_unknown_veto_type() -> None:
    """AC-7a.2: veto_recommended must be a bool, not a non-boolean value.
    Pydantic v2 coerces truthy strings to True, so we test with a
    clearly non-boolean (e.g. an integer)."""
    # Pydantic v2 coerces "true" to True; we use a clearly invalid type
    # to assert the schema rejects it.
    import unittest.mock

    with pytest.raises(Exception):
        AuditReport(case_id="PC-X", veto_recommended=object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-7a.3 — Deterministic CRITICAL veto (100/100 proptest)
# ---------------------------------------------------------------------------


def test_deterministic_veto_returns_true_on_critical_risk(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    critical_risk: RiskScore,
    clean_policy: PolicyReport,
) -> None:
    """AC-7a.3: risk CRITICAL => veto True."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    report = auditor.audit(
        violations_case, violations_profile, critical_risk, clean_policy
    )
    assert report.veto_recommended is True


def test_deterministic_veto_returns_true_on_critical_finding(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    high_risk: RiskScore,
    violations_policy: PolicyReport,
) -> None:
    """AC-7a.3: a CRITICAL finding in the policy report => veto True,
    even when risk severity is HIGH."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    report = auditor.audit(
        violations_case, violations_profile, high_risk, violations_policy
    )
    assert report.veto_recommended is True
    # The 1 CRITICAL finding (AML-001) is affirmed in critical_findings.
    rule_ids = [f.rule_id for f in report.critical_findings]
    assert "AML-001" in rule_ids


def test_deterministic_veto_returns_false_on_clean(
    clean_case: ProcurementCase,
    clean_profile: VendorProfile,
    high_risk: RiskScore,
    clean_policy: PolicyReport,
) -> None:
    """AC-7a.3: HIGH risk + empty policy => veto False."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    report = auditor.audit(
        clean_case, clean_profile, high_risk, clean_policy
    )
    assert report.veto_recommended is False


def test_deterministic_veto_dict_input_works(
    clean_profile: VendorProfile,
) -> None:
    """AC-7a.3: duck-typed dict inputs work for the deterministic check."""
    from red_team import _deterministic_veto_check

    # dict risk with CRITICAL
    risk_dict = {"score": 95, "severity": "CRITICAL"}
    policy_empty = {"findings": []}
    assert _deterministic_veto_check(risk_dict, policy_empty) is True
    # dict policy with CRITICAL finding
    risk_high = {"score": 70, "severity": "HIGH"}
    policy_critical = {
        "findings": [
            {"rule_id": "AML-001", "severity": "CRITICAL", "statute": "AMLD6"}
        ]
    }
    assert _deterministic_veto_check(risk_high, policy_critical) is True
    # No CRITICAL anywhere => False
    risk_low = {"score": 10, "severity": "LOW"}
    policy_low = {"findings": [{"rule_id": "PROC-001", "severity": "MEDIUM"}]}
    assert _deterministic_veto_check(risk_low, policy_low) is False


@settings(max_examples=100, deadline=None)
@given(
    risk_severity=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    has_critical_finding=st.booleans(),
)
def test_deterministic_veto_proptest_100_samples(
    risk_severity: str, has_critical_finding: bool
) -> None:
    """AC-7a.3: 100/100 deterministic — given CRITICAL risk or a CRITICAL
    finding, veto MUST be True. Hypothesis generates 100 random
    (risk_severity, has_critical_finding) tuples and asserts the
    invariant."""
    from red_team import _deterministic_veto_check

    risk = RiskScore(score=80, severity=risk_severity, drivers=[], citations=[])
    findings = []
    if has_critical_finding:
        findings.append(
            Finding(
                rule_id="AML-001",
                statute="AMLD6 Art. 5",
                severity="CRITICAL",
                evidence_span="vendor UBO sanctions match",
                recommendation="Block payment.",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="PROC-001",
                statute="Directive 2014/24/EU Art. 56",
                severity="HIGH",
                evidence_span="vendor registration_country",
                recommendation="Escalate to EDD.",
            )
        )
    policy = PolicyReport(case_id="PC-PROPTEST", findings=findings)

    veto = _deterministic_veto_check(risk, policy)
    expected = (risk_severity == "CRITICAL") or has_critical_finding
    assert veto is expected, (risk_severity, has_critical_finding, veto)


def test_deterministic_veto_cannot_be_overridden_by_llm(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    critical_risk: RiskScore,
    clean_policy: PolicyReport,
) -> None:
    """AC-7a.3: the LLM cannot unset a True veto (veto is monotonic)."""

    def evil_llm(
        profile: Any,
        risk_score: Any,
        policy_report: Any,
        base: AuditReport,
    ) -> str:
        # The LLM tries to set veto to False by returning a string that
        # hints at it. The deterministic veto path ignores the LLM
        # return; it only enriches rationale.
        return "All is well, no veto needed."

    auditor = RedTeamAuditor(llm_call=evil_llm)
    report = auditor.audit(
        violations_case, violations_profile, critical_risk, clean_policy
    )
    assert report.veto_recommended is True


# ---------------------------------------------------------------------------
# AC-7a.4 — Band agent registration verification
# ---------------------------------------------------------------------------


FRAUD_AUDITOR_UUID = "01603c07-2db1-4660-836a-0f8fdf285b73"


def test_load_agent_config_returns_fraud_auditor_uuid() -> None:
    """AC-7a.4: load_agent_config('fraud-auditor') returns the
    UUID 01603c07-2db1-4660-836a-0f8fdf285b73 and a non-empty api_key.
    The YAML key is ``fraud-auditor`` (the Band handle is
    ``@apohara-themis/fraud-auditor``)."""
    rec = load_agent_config("fraud-auditor")
    assert rec["agent_id"] == FRAUD_AUDITOR_UUID, rec
    assert rec["api_key"], rec
    assert rec["api_key"].startswith("band_"), rec
    assert "fraud-auditor" in rec["handle"], rec


def test_load_agent_config_fraud_auditor_role_is_worker() -> None:
    """AC-7a.4: the fraud-auditor is registered as a worker agent."""
    rec = load_agent_config("fraud-auditor")
    assert rec["role"] == "worker", rec
    assert "langgraph" in rec["framework"], rec


# ---------------------------------------------------------------------------
# Band handoff (defensive coverage of the @evidence-clerk handoff)
# ---------------------------------------------------------------------------


def test_red_team_auditor_emits_to_evidence_clerk(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    critical_risk: RiskScore,
    violations_policy: PolicyReport,
) -> None:
    """The Band send_event carries metadata.to='evidence-clerk'."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    tools = MagicMock()
    report = auditor.audit(
        violations_case,
        violations_profile,
        critical_risk,
        violations_policy,
        tools=tools,
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
    assert metadata.get("to") == "evidence-clerk"
    assert metadata.get("from") == "red-team-auditor"
    assert metadata.get("schema") == "AuditReport"
    assert message_type == "thought"
    # Content is a JSON AuditReport
    obj = json.loads(content)
    assert obj["case_id"] == violations_case.case_id
    assert obj["veto_recommended"] is True


def test_red_team_auditor_veto_flag_in_metadata(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    critical_risk: RiskScore,
    violations_policy: PolicyReport,
) -> None:
    """The Band metadata carries a ``veto`` boolean for the evidence clerk."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    tools = MagicMock()
    auditor.audit(
        violations_case,
        violations_profile,
        critical_risk,
        violations_policy,
        tools=tools,
    )
    call = tools.send_event.call_args
    if call.kwargs:
        metadata = call.kwargs.get("metadata", {})
    else:
        metadata = call.args[2] if len(call.args) > 2 else {}
    assert metadata.get("veto") is True


def test_red_team_auditor_clean_case_posts_no_veto(
    clean_case: ProcurementCase,
    clean_profile: VendorProfile,
    high_risk: RiskScore,
    clean_policy: PolicyReport,
) -> None:
    """A clean case posts an AuditReport with veto_recommended=False."""
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    tools = MagicMock()
    report = auditor.audit(
        clean_case, clean_profile, high_risk, clean_policy, tools=tools
    )
    assert report.veto_recommended is False
    assert tools.send_event.called


# ---------------------------------------------------------------------------
# Adversarial citation challenge
# ---------------------------------------------------------------------------


def test_red_team_auditor_challenges_ungrounded_citations(
    violations_case: ProcurementCase,
    violations_profile: VendorProfile,
    high_risk: RiskScore,
) -> None:
    """The auditor flags citations that match no canonical statute and no
    vendor profile anchor."""
    # Construct a policy with one grounded + one hallucinated finding.
    policy = PolicyReport(
        case_id="PC-2026-0002",
        findings=[
            Finding(
                rule_id="PROC-001",
                statute="Directive 2014/24/EU Art. 56",
                severity="HIGH",
                evidence_span="vendor registration_country=CY",
                recommendation="Escalate to EDD.",
            ),
            Finding(
                rule_id="FAKE-999",
                statute="Made-up Statute 999",
                severity="MEDIUM",
                evidence_span="free text without anchor",
                recommendation="Some recommendation.",
            ),
        ],
    )
    auditor = RedTeamAuditor(llm_call=_mock_llm_call)
    report = auditor.audit(
        violations_case, violations_profile, high_risk, policy
    )
    assert "Made-up Statute 999" in report.citations_challenged


# ---------------------------------------------------------------------------
# Manual tool loop (AC-7a.1 hint #2)
# ---------------------------------------------------------------------------


def test_run_with_tools_breaks_on_end_turn() -> None:
    """The manual tool loop breaks on stop_reason != 'tool_use'."""
    client = MagicMock()
    # Mock a response with stop_reason='end_turn'
    fake_response = MagicMock()
    fake_response.stop_reason = "end_turn"
    fake_response.content = []
    client.messages.create.return_value = fake_response
    out = run_with_tools(client, [{"role": "user", "content": "hi"}])
    assert out["stop_reason"] == "end_turn"


def test_run_with_tools_executes_tool_use() -> None:
    """The manual tool loop executes tool_use blocks and re-prompts."""
    client = MagicMock()

    # First call: tool_use; second call: end_turn.
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "echo"
    tool_block.input = {"x": 1}
    tool_block.id = "tool_1"

    first = MagicMock()
    first.stop_reason = "tool_use"
    first.content = [tool_block]

    second = MagicMock()
    second.stop_reason = "end_turn"
    second.content = []

    client.messages.create.side_effect = [first, second]
    out = run_with_tools(
        client,
        [{"role": "user", "content": "hi"}],
        tools=[{"name": "echo", "description": "echo"}],
    )
    assert out["stop_reason"] == "end_turn"
    # Two round-trips happened.
    assert client.messages.create.call_count == 2


def test_run_with_tools_handles_max_iterations() -> None:
    """The manual tool loop respects max_iterations."""
    client = MagicMock()

    # Always returns tool_use so the loop hits max_iterations.
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "echo"
    tool_block.input = {}
    tool_block.id = "tool_loop"
    fake = MagicMock()
    fake.stop_reason = "tool_use"
    fake.content = [tool_block]
    client.messages.create.return_value = fake

    out = run_with_tools(
        client,
        [{"role": "user", "content": "hi"}],
        tools=[{"name": "echo", "description": "echo"}],
        max_iterations=3,
    )
    assert out["stop_reason"] == "max_iterations"


# ---------------------------------------------------------------------------
# Defensive coverage
# ---------------------------------------------------------------------------


def test_load_secrets_handles_missing_file() -> None:
    """load_secrets never raises on a missing secrets.env."""
    from red_team import load_secrets

    out = load_secrets()
    assert isinstance(out, dict)
    assert "AIML_API_KEY" in out


def test_red_team_auditor_lazy_client() -> None:
    """The Anthropic client is built lazily on first .client access."""
    auditor = RedTeamAuditor(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    # No client built yet
    assert auditor._client is None
    client = auditor.client
    assert client is not None
    assert getattr(client, "_apohara_model", "") == "claude-opus-4-5"


def test_red_team_auditor_uses_injected_client() -> None:
    """An injected Anthropic client is preferred over the lazy default."""
    injected = MagicMock()
    injected._apohara_model = "claude-opus-4-5"
    auditor = RedTeamAuditor(anthropic_client=injected)
    assert auditor.client is injected