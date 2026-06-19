"""S-04: VendorResearcher agent tests (5 ACs total).

Tests are organized as 1+ test per AC:

* test_build_featherless_llm_targets_featherless        (AC-4.1)
* test_build_featherless_llm_uses_default_model         (AC-4.1)
* test_vendor_profile_schema_has_five_required_fields   (AC-4.2)
* test_vendor_profile_validates_clean_fixture           (AC-4.2)
* test_vendor_profile_validates_alt_fixture_sanctions   (AC-4.2)
* test_vendor_lookup_resolves_known_vendor              (AC-4.3)
* test_vendor_lookup_returns_partial_for_unknown        (AC-4.3)
* test_vendor_lookup_partial_profile_is_valid_schema    (AC-4.3)
* test_run_emits_vendor_profile_with_to_finance         (AC-4.4)
* test_run_emits_vendor_profile_with_correct_metadata   (AC-4.4)
* test_featherless_llm_base_url_contains_featherless_ai (AC-4.5)
* test_vendor_lookup_tool_is_bound_to_adapter           (AC-4.1 + AC-4.3)

Every public function in vendor_researcher.py has at least one test
(hard rule #2). The LLM is mocked (we never hit Featherless in tests);
the Band ``send_event`` is mocked via ``unittest.mock.MagicMock``.
"""

from __future__ import annotations

import asyncio
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

from vendor_researcher import (  # noqa: E402
    SanctionsHit,
    UltimateBeneficialOwner,
    VendorProfile,
    VendorResearcher,
    VendorResearcherState,
    build_featherless_llm,
    build_state_graph,
    compile_state_machine,
    load_secrets,
    make_graph_factory,
    vendor_lookup,
)
from intake import ProcurementCase  # noqa: E402


# ---------------------------------------------------------------------------
# AC-4.1 — ChatOpenAI built against Featherless base_url
# ---------------------------------------------------------------------------


def test_build_featherless_llm_targets_featherless() -> None:
    """AC-4.1: ChatOpenAI is built with base_url=FEATHERLESS_API_BASE_URL
    and model=meta-llama/Llama-3.3-70B-Instruct."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    # ChatOpenAI stores the base on `openai_api_base`.
    assert "meta-llama/Llama-3.3-70B-Instruct" in llm.model_name
    assert "featherless.ai" in str(llm.openai_api_base), llm.openai_api_base


def test_build_featherless_llm_uses_default_model() -> None:
    """AC-4.1: default model id is meta-llama/Llama-3.3-70B-Instruct."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    assert llm.model_name == "meta-llama/Llama-3.3-70B-Instruct"


# ---------------------------------------------------------------------------
# AC-4.2 — VendorProfile schema has 5 required fields
# ---------------------------------------------------------------------------


def test_vendor_profile_schema_has_five_required_fields() -> None:
    """AC-4.2: VendorProfile has registration_country,
    ultimate_beneficial_owner, sector, sanctions_hits,
    adverse_media_count."""
    fields = set(VendorProfile.model_fields.keys())
    required = {
        "registration_country",
        "ultimate_beneficial_owner",
        "sector",
        "sanctions_hits",
        "adverse_media_count",
    }
    assert required.issubset(fields), f"missing: {required - fields}"


def test_vendor_profile_validates_clean_fixture() -> None:
    """AC-4.2: clean fixture's profile parses against VendorProfile."""
    data = json.loads((FIXTURES / "vendor_profile.json").read_text())
    profile = VendorProfile.model_validate(data["profile"])
    assert profile.registration_country == "DE"
    assert profile.sector == "office_supplies_manufacturing"
    assert profile.sanctions_hits == []
    assert profile.adverse_media_count == 0
    assert len(profile.ultimate_beneficial_owner) == 2


def test_vendor_profile_validates_alt_fixture_sanctions() -> None:
    """AC-4.2: alt fixture (shell company with sanctions hits) parses
    and exposes 2 sanctions list matches."""
    data = json.loads((FIXTURES / "vendor_profile_alt.json").read_text())
    profile = VendorProfile.model_validate(data["profile"])
    assert profile.registration_country == "CY"
    assert profile.sector == "shell_company_trading"
    assert len(profile.sanctions_hits) == 2
    assert profile.sanctions_hits[0].list == "OFAC_SDN"
    assert profile.adverse_media_count == 14
    # UBO is a single PEP with 100% ownership.
    assert len(profile.ultimate_beneficial_owner) == 1
    assert profile.ultimate_beneficial_owner[0].pep_flag is True


def test_vendor_profile_to_json_is_deterministic() -> None:
    """AC-4.2: to_json() produces a stable, sorted-key serialization
    so downstream agents can hash it for the BLAKE3 chain."""
    p = VendorProfile(
        registration_country="DE",
        sector="manufacturing",
    )
    j = p.to_json()
    obj = json.loads(j)
    # Sort order: keys appear alphabetically in the serialized output.
    assert list(obj.keys()) == sorted(obj.keys())


# ---------------------------------------------------------------------------
# AC-4.3 — vendor_lookup tool resolves a known vendor_name to a fixture
# ---------------------------------------------------------------------------


def test_vendor_lookup_resolves_known_vendor() -> None:
    """AC-4.3: vendor_lookup returns the profile dict for a known vendor."""
    res = vendor_lookup.invoke({"vendor_name": "Acme Office Supplies GmbH"})
    assert res["vendor_name"] == "Acme Office Supplies GmbH"
    assert "profile" in res
    assert res["profile"]["registration_country"] == "DE"
    assert res["profile"]["sector"] == "office_supplies_manufacturing"


def test_vendor_lookup_resolves_alt_fixture() -> None:
    """AC-4.3: vendor_lookup resolves the shell-company alt fixture too."""
    res = vendor_lookup.invoke({"vendor_name": "Northbridge Trading Ltd"})
    assert res["profile"]["registration_country"] == "CY"
    assert len(res["profile"]["sanctions_hits"]) == 2


def test_vendor_lookup_returns_partial_for_unknown() -> None:
    """AC-4.3: unknown vendor_name returns a partial profile so the
    agent can reason about incompleteness (registration_country only)."""
    res = vendor_lookup.invoke({"vendor_name": "Nonexistent Vendor Co"})
    assert "profile" in res
    # Partial profile carries the unknown marker.
    assert res["profile"]["registration_country"] == "XX"
    assert res["profile"]["sector"] == "unknown"
    assert res["profile"]["ultimate_beneficial_owner"] == []
    assert res["profile"]["sanctions_hits"] == []
    assert res["profile"]["adverse_media_count"] == 0
    assert "warning" in res


def test_vendor_lookup_partial_profile_is_valid_schema() -> None:
    """AC-4.3: the partial profile is still a valid VendorProfile."""
    res = vendor_lookup.invoke({"vendor_name": "Some Unknown Vendor"})
    profile = VendorProfile.model_validate(res["profile"])
    assert profile.registration_country == "XX"
    assert profile.adverse_media_count == 0


# ---------------------------------------------------------------------------
# AC-4.4 — Band send_event metadata.to == 'finance-risk-analyst'
# ---------------------------------------------------------------------------


def _run_async(coro: Any) -> Any:
    """Run a coroutine in a fresh event loop (pytest-asyncio not required)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_case(vendor_name: str = "Acme Office Supplies GmbH") -> ProcurementCase:
    return ProcurementCase(
        case_id="PC-2026-0001",
        buyer="Stark Industries EU Sp.z.o.o.",
        vendor_name=vendor_name,
        vendor_id="DE-271828-BERLIN",
        amount_eur=12450.0,
        category="office_supplies",
        requested_action="approve",
        attachments=[],
        urgency="standard",
    )


def test_run_emits_vendor_profile_with_to_finance() -> None:
    """AC-4.4: run() calls send_event with metadata.to='finance-risk-analyst'."""
    tools = MagicMock()
    agent = VendorResearcher(
        secrets={
            "FEATHERLESS_API_KEY": "test",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    case = _make_case()
    profile = _run_async(agent.run(case, tools=tools))
    # AC-4.2 contract: profile is a valid VendorProfile.
    assert isinstance(profile, VendorProfile)
    assert profile.registration_country == "DE"
    # AC-4.4 contract: send_event was called with metadata.to == finance.
    assert tools.send_event.called
    call_kwargs = tools.send_event.call_args.kwargs
    assert call_kwargs.get("metadata", {}).get("to") == "finance-risk-analyst"
    assert call_kwargs.get("message_type") == "thought"


def test_run_emits_vendor_profile_with_correct_metadata() -> None:
    """AC-4.4: full metadata envelope (from, to, schema, case_id)."""
    tools = MagicMock()
    agent = VendorResearcher(
        secrets={
            "FEATHERLESS_API_KEY": "test",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    case = _make_case(vendor_name="Northbridge Trading Ltd")
    profile = _run_async(agent.run(case, tools=tools))
    # Alt fixture = shell company with sanctions hits.
    assert profile.registration_country == "CY"
    assert len(profile.sanctions_hits) == 2
    call_kwargs = tools.send_event.call_args.kwargs
    md = call_kwargs.get("metadata", {})
    assert md["from"] == "vendor-researcher"
    assert md["to"] == "finance-risk-analyst"
    assert md["schema"] == "VendorProfile"
    assert md["case_id"] == "PC-2026-0001"
    # Content is the structured profile JSON.
    content = call_kwargs.get("content", "")
    parsed = json.loads(content)
    assert parsed["registration_country"] == "CY"
    assert len(parsed["sanctions_hits"]) == 2


def test_run_partial_profile_for_unknown_vendor() -> None:
    """AC-4.4 + AC-4.3: unknown vendor still emits a partial profile
    with metadata.to set correctly so the finance agent can flag it."""
    tools = MagicMock()
    agent = VendorResearcher(
        secrets={
            "FEATHERLESS_API_KEY": "test",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    case = _make_case(vendor_name="Ghost Vendor Ltd")
    profile = _run_async(agent.run(case, tools=tools))
    assert profile.registration_country == "XX"
    call_kwargs = tools.send_event.call_args.kwargs
    assert call_kwargs["metadata"]["to"] == "finance-risk-analyst"


# ---------------------------------------------------------------------------
# AC-4.5 — Featherless is the actual backend (integration check)
# ---------------------------------------------------------------------------


def test_featherless_llm_base_url_contains_featherless_ai() -> None:
    """AC-4.5: integration-level assertion that the LLM base URL
    points at featherless.ai (NOT openai.com / aimlapi.com)."""
    # 1. Direct construction with the configured secrets.
    llm = build_featherless_llm()
    assert "featherless.ai" in str(llm.openai_api_base), llm.openai_api_base
    # 2. Cross-check via load_secrets() to prove no env override
    #    silently redirected the LLM to a different provider.
    secrets = load_secrets()
    assert "featherless.ai" in secrets.get(
        "FEATHERLESS_API_BASE_URL", ""
    ), secrets
    # 3. The graph factory uses the same LLM builder (no override).
    factory = make_graph_factory(secrets=secrets)
    assert callable(factory)


def test_vendor_lookup_tool_is_bound_to_adapter() -> None:
    """AC-4.1 + AC-4.3: VendorResearcher.build_adapter() wires the
    vendor_lookup tool into the LangGraphAdapter additional_tools."""
    agent = VendorResearcher(
        secrets={
            "FEATHERLESS_API_KEY": "test",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    adapter = agent.build_adapter()
    # The adapter exposes additional_tools; vendor_lookup must be there.
    extra = getattr(adapter, "additional_tools", None)
    assert extra is not None, "LangGraphAdapter missing additional_tools"
    tool_names = {getattr(t, "name", "") for t in extra}
    assert "vendor_lookup" in tool_names, tool_names


# ---------------------------------------------------------------------------
# Direct state-machine sanity (no Band tools attached)
# ---------------------------------------------------------------------------


def test_state_machine_compiles_and_runs_without_tools() -> None:
    """The graph compiles and finishes (state=DONE) without Band tools
    attached — the EMIT node logs a warning and the run still returns
    a valid VendorProfile."""
    agent = VendorResearcher(
        secrets={
            "FEATHERLESS_API_KEY": "test",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    case = _make_case()
    profile = _run_async(agent.run(case, tools=None))
    assert profile.registration_country == "DE"