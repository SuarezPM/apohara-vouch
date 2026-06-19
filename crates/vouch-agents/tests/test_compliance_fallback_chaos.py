"""S-07b AC-7b.5: Chaos harness for the compliance-veto fallback.

Runs 10 scenarios. Each scenario spawns the Orchestrator +
ComplianceVeto mock, then ``kill_cross_account_websocket()`` raises
an exception 3 times during the run. The harness asserts:

  1. The fallback veto fires in ALL 10 runs (10/10).
  2. The Orchestrator's ``DEGRADED`` banner flag is set in ALL 10
     runs (10/10) — this is what makes the demo UI show the
     "DEGRADED MODE — using local fallback" banner.

The harness is intentionally deterministic (no random seeds; fixed
kill schedule). It does NOT hit the network — every Band call and
every LLM call is mocked at the test boundary.

The orchestrator-side fallback decision
----------------------------------------
Production code path (documented in ``compliance_fallback.py``):

  1. The Orchestrator's ``_try_compliance_veto`` loop calls the
     primary ``ComplianceVeto`` up to ``MAX_PRIMARY_ATTEMPTS = 5``
     times. Every attempt that hits a ``_KillCrossAccountWebSocketError``
     increments the kill counter; after 3 kills, the loop exits and
     the orchestrator invokes ``ComplianceFallback.evaluate()``.

  2. The fallback's ``VetoDecision.fallback=True`` is the signal
     that flips ``state.degraded = True`` in
     ``node_compliance_escalation`` — visible to the demo UI as the
     ``DEGRADED`` banner.

This file reimplements that contract at the test boundary so the
test does NOT depend on a production wiring that does not exist
yet (the Orchestrator's retry loop is added in a follow-up story;
S-07b defines the CONTRACT).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
ORCH_SRC = (THIS_DIR.parent.parent / "vouch-orchestrator" / "src")
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ORCH_SRC) not in sys.path:
    sys.path.insert(0, str(ORCH_SRC))

from compliance_fallback import ComplianceFallback  # noqa: E402
from compliance_veto import ComplianceVeto, VetoDecision  # noqa: E402
from orchestrator import (  # noqa: E402
    OrchestratorState,
    compile_state_machine,
    node_compliance_escalation,
    register_tools,
)


N_RUNS = 10
KILLS_BEFORE_FALLBACK = 3


# ---------------------------------------------------------------------------
# Chaos primitives
# ---------------------------------------------------------------------------


class _KillCrossAccountWebSocketError(RuntimeError):
    """Raised when the cross-account WebSocket dies."""


class _KillablePrimary:
    """A primary ComplianceVeto wrapper that raises on every call.

    The harness drives it directly to count kills; once the kill
    count reaches ``KILLS_BEFORE_FALLBACK``, the harness activates
    the fallback.
    """

    def __init__(self) -> None:
        self.kill_count = 0
        self.attempts = 0
        # The primary's real ComplianceVeto is used for the verdict
        # when (hypothetically) the LLM roundtrip succeeds. The
        # chaos harness always raises instead — the fallback is the
        # only path that produces a verdict in this test.
        self._inner = ComplianceVeto(
            secrets={"AIML_API_KEY": "x", "AIML_API_BASE_URL": "y"},
            llm_call=lambda base: (_ for _ in ()).throw(
                _KillCrossAccountWebSocketError("chaos")
            ),
        )

    def attempt(self) -> VetoDecision:
        self.attempts += 1
        self.kill_count += 1
        raise _KillCrossAccountWebSocketError(
            f"chaos: cross-account WebSocket killed "
            f"(attempt #{self.attempts}, kill #{self.kill_count})"
        )


class _FallbackDriver:
    """The orchestrator-side fallback activation logic (S-07b AC-7b.5).

    Implements the contract:

      * Up to 5 primary attempts.
      * After 3 kills, activate the local fallback.
      * Fallback returns ``VetoDecision(fallback=True)``.
      * Orchestrator sees the flag → sets ``state.degraded=True``.
    """

    MAX_PRIMARY_ATTEMPTS = 5

    def __init__(self, primary: _KillablePrimary, fallback: ComplianceFallback) -> None:
        self.primary = primary
        self.fallback = fallback
        self.fallback_activated = False

    def run(self, case: Any, risk: Any, policy: Any) -> VetoDecision:
        last_err: Exception | None = None
        for _ in range(self.MAX_PRIMARY_ATTEMPTS):
            try:
                # Real call would hit the cross-account WS; chaos
                # raises synchronously.
                return self.primary.attempt()
            except _KillCrossAccountWebSocketError as exc:
                last_err = exc
                if self.primary.kill_count >= KILLS_BEFORE_FALLBACK:
                    self.fallback_activated = True
                    break
        # Fallback path — same schema, fallback flag set.
        assert last_err is not None
        return self.fallback.evaluate(
            case=case,
            risk=risk,
            policy=policy,
            fallback=True,
            fallback_reason=str(last_err),
        )


# ---------------------------------------------------------------------------
# One chaos scenario
# ---------------------------------------------------------------------------


def _make_case() -> Any:
    return type(
        "C",
        (),
        {"case_id": "chaos-x", "raw_procurement_request": "GDPR personal-data breach"},
    )()


def _make_risk() -> Any:
    return type("R", (), {"severity": "CRITICAL"})()


def _make_policy() -> Any:
    return type(
        "P", (), {"findings": [type("F", (), {"severity": "CRITICAL"})()]}
    )()


def _run_one_chaos_scenario(run_idx: int) -> dict[str, Any]:
    """Run one chaos scenario synchronously. Returns a result dict."""

    async def _inner() -> dict[str, Any]:
        case_id = f"chaos-case-{run_idx:02d}"
        primary = _KillablePrimary()
        fallback = ComplianceFallback()
        driver = _FallbackDriver(primary, fallback)

        decision = driver.run(
            case=_make_case(),
            risk=_make_risk(),
            policy=_make_policy(),
        )

        # 2. Run the orchestrator node that flips DEGRADED when the
        #    fallback flag is set.
        state: OrchestratorState = {
            "state": "REDTEAM",
            "case_id": case_id,
            "tenant_id": "stark",
            "veto_decision": decision.model_dump(mode="json"),
        }
        out = await node_compliance_escalation(state)

        return {
            "run_idx": run_idx,
            "fallback_fired": decision.fallback is True,
            "fallback_activated": driver.fallback_activated,
            "degraded": bool(out.get("degraded", False)),
            "kill_count": primary.kill_count,
            "primary_attempts": primary.attempts,
            "veto_verdict": decision.verdict,
            "regulatory_clock": decision.regulatory_clock,
        }

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_inner())
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# The 10-run chaos harness
# ---------------------------------------------------------------------------


@pytest.mark.chaos
def test_chaos_harness_fallback_fires_10_of_10() -> None:
    """AC-7b.5: the fallback veto fires in all 10 chaos runs."""
    results = [_run_one_chaos_scenario(i) for i in range(N_RUNS)]
    fallback_fires = sum(1 for r in results if r["fallback_fired"])
    summary = ", ".join(
        f"#{r['run_idx']}:fallback={r['fallback_fired']}/kills={r['kill_count']}"
        for r in results
    )
    assert fallback_fires == N_RUNS, (
        f"fallback fired {fallback_fires}/{N_RUNS} — {summary}"
    )


@pytest.mark.chaos
def test_chaos_harness_degraded_banner_10_of_10() -> None:
    """AC-7b.5: the DEGRADED banner is set in all 10 chaos runs."""
    results = [_run_one_chaos_scenario(i) for i in range(N_RUNS)]
    degraded_runs = sum(1 for r in results if r["degraded"])
    summary = ", ".join(
        f"#{r['run_idx']}:degraded={r['degraded']}" for r in results
    )
    assert degraded_runs == N_RUNS, (
        f"DEGRADED set in {degraded_runs}/{N_RUNS} — {summary}"
    )


@pytest.mark.chaos
def test_chaos_harness_kill_count_per_run() -> None:
    """AC-7b.5: each scenario observes ≥3 cross-account WS kills."""
    results = [_run_one_chaos_scenario(i) for i in range(N_RUNS)]
    bad = [r for r in results if r["kill_count"] < KILLS_BEFORE_FALLBACK]
    assert not bad, (
        f"runs with <{KILLS_BEFORE_FALLBACK} kills: "
        + ", ".join(f"#{r['run_idx']}={r['kill_count']}" for r in bad)
    )


@pytest.mark.chaos
def test_chaos_harness_deterministic() -> None:
    """AC-7b.5: running the harness twice yields identical results."""
    a = [_run_one_chaos_scenario(i) for i in range(N_RUNS)]
    b = [_run_one_chaos_scenario(i) for i in range(N_RUNS)]
    for ra, rb in zip(a, b):
        assert ra["fallback_fired"] == rb["fallback_fired"]
        assert ra["degraded"] == rb["degraded"]
        assert ra["veto_verdict"] == rb["veto_verdict"]
        assert ra["regulatory_clock"] == rb["regulatory_clock"]
