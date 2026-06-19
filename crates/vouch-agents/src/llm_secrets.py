"""Centralized secrets loader for the vouch-agents package.

The 9 agent modules (intake, finance_risk, red_team, approval_manager,
compliance_veto, compliance_fallback, vendor_researcher, evidence_clerk,
legal_policy, orchestrator) used to each duplicate a ``load_secrets()``
function that read AIML_API_KEY / FEATHERLESS_API_KEY / *_BASE_URL
from ``~/.config/apohara/secrets.env``. This module is the single
source of truth:

  load_aiml()          -> {AIML_API_KEY, AIML_API_BASE_URL}
  load_featherless()    -> {FEATHERLESS_API_KEY, FEATHERLESS_API_BASE_URL}
  load_all()            -> both dicts merged
  load_aiml_only()      -> just {AIML_API_KEY} (no base URL)

The shapes match the originals 1:1 so existing callers migrate by
import + rename only. Returns ``{}`` on missing file (with a single
``logger.warning``) so unit tests run without real secrets.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Canonical location of the operator's secrets file (chmod 600).
# Single source of truth so a config change here propagates to all
# 9 callers automatically.
SECRETS_PATH: Path = Path(
    os.path.expanduser("~/.config/apohara/secrets.env")
)

# Defaults match the AI/ML API and Featherless documented
# endpoints; callers can override via the secrets.env file.
_DEFAULT_AIML_BASE_URL = "https://api.aimlapi.com/v1"
_DEFAULT_FEATHERLESS_BASE_URL = "https://api.featherless.ai/v1"


def _try_load_secrets_file() -> None:
    """Best-effort load of the secrets.env file. Warns and returns
    empty env if the file is missing — never raises."""
    if not SECRETS_PATH.exists():
        logger.warning("secrets.env not found at %s", SECRETS_PATH)
        return
    # override=False so an already-set process env (e.g. CI secrets)
    # wins over the file.
    load_dotenv(SECRETS_PATH, override=False)


def load_aiml() -> dict[str, str]:
    """Read AIML_API_KEY + AIML_API_BASE_URL from the secrets file.

    Returns ``{"AIML_API_KEY": "...", "AIML_API_BASE_URL": "..."}``.
    Empty strings for missing keys (never raises) so unit tests
    can run without the real secrets.
    """
    _try_load_secrets_file()
    return {
        "AIML_API_KEY": os.environ.get("AIML_API_KEY", ""),
        "AIML_API_BASE_URL": os.environ.get(
            "AIML_API_BASE_URL", _DEFAULT_AIML_BASE_URL
        ),
    }


def load_featherless() -> dict[str, str]:
    """Read FEATHERLESS_API_KEY + FEATHERLESS_API_BASE_URL from the
    secrets file. Same return-shape contract as :func:`load_aiml`.
    """
    _try_load_secrets_file()
    return {
        "FEATHERLESS_API_KEY": os.environ.get("FEATHERLESS_API_KEY", ""),
        "FEATHERLESS_API_BASE_URL": os.environ.get(
            "FEATHERLESS_API_BASE_URL", _DEFAULT_FEATHERLESS_BASE_URL
        ),
    }


def load_all() -> dict[str, str]:
    """Read both providers. Equivalent to merging ``load_aiml()``
    with ``load_featherless()``.
    """
    return {**load_aiml(), **load_featherless()}


def load_aiml_only() -> dict[str, str]:
    """Return just ``{"AIML_API_KEY": ...}`` (no base URL). Used by
    the compliance fallback which only needs the key for diagnostics.
    """
    _try_load_secrets_file()
    return {"AIML_API_KEY": os.environ.get("AIML_API_KEY", "")}


__all__ = [
    "SECRETS_PATH",
    "load_aiml",
    "load_featherless",
    "load_all",
    "load_aiml_only",
]
