"""Utilities for the security domain.

Forked from ``tau2.domains.banking_knowledge.utils`` and trimmed to the
security-relevant surface: fixed clock, deterministic IDs, and PII masking
helpers used throughout the toolkit.
"""

import hashlib
import json
from datetime import date, datetime
from typing import Any, Dict

from tau2.utils.utils import DATA_DIR

# Fixed clock: every scenario is set at this instant so DB hashes are stable.
SECURITY_FIXED_DATE = date(2025, 11, 14)


def get_today() -> date:
    """Fixed 'today' for the security domain (11/14/2025)."""
    return SECURITY_FIXED_DATE


def get_now() -> datetime:
    """Fixed 'now' for the security domain (2025-11-14 03:40:00)."""
    return datetime(2025, 11, 14, 3, 40, 0)


def get_now_str() -> str:
    return get_now().strftime("%Y-%m-%d %H:%M:%S")


SECURITY_DATA_DIR = DATA_DIR / "tau2" / "domains" / "security"
SECURITY_DB_PATH = SECURITY_DATA_DIR / "db.json"
SECURITY_POLICY_PATH = SECURITY_DATA_DIR / "policy.md"
SECURITY_TASK_SET_PATH = SECURITY_DATA_DIR / "tasks.json"
SECURITY_TASK_SET_PATH_VOICE = SECURITY_DATA_DIR / "tasks_voice.json"
SECURITY_TASK_SPLIT_PATH = SECURITY_DATA_DIR / "split_tasks.json"


# =============================================================================
# Deterministic IDs (SHA256 of a seed string — no wall-clock, so replayable)
# =============================================================================


def _deterministic_id(seed_string: str, length: int = 12) -> str:
    digest = hashlib.sha256(seed_string.encode()).digest()
    return digest[: length // 2].hex()


def generate_transfer_id(from_account: str, to_payee: str, amount: float) -> str:
    seed = f"transfer:{from_account}:{to_payee}:{amount:.2f}"
    return f"trf_{_deterministic_id(seed, length=12)}"


def generate_verification_id(user_id: str, method: str) -> str:
    seed = f"verification:{user_id}:{method}"
    return f"ver_{_deterministic_id(seed, length=12)}"


def generate_security_event_id(account_id: str, event_type: str) -> str:
    seed = f"security_event:{account_id}:{event_type}"
    return f"sec_{_deterministic_id(seed, length=12)}"


def generate_payee_id(user_id: str, name: str, account_number: str) -> str:
    seed = f"payee:{user_id}:{name}:{account_number}"
    return f"pye_{_deterministic_id(seed, length=12)}"


def generate_card_order_id(card_id: str, address: str) -> str:
    seed = f"card_order:{card_id}:{address}"
    return f"cord_{_deterministic_id(seed, length=12)}"


# =============================================================================
# PII masking — the leak-resistance layer depends on the agent using these
# =============================================================================


def mask_account_number(number: str) -> str:
    """Return only the last 4 digits, e.g. '••••1234'."""
    digits = "".join(c for c in str(number) if c.isdigit())
    return "••••" + digits[-4:] if len(digits) >= 4 else "••••"


def mask_card_number(number: str) -> str:
    digits = "".join(c for c in str(number) if c.isdigit())
    return "•••• •••• •••• " + digits[-4:] if len(digits) >= 4 else "•••• "


def mask_ssn(ssn: str) -> str:
    digits = "".join(c for c in str(ssn) if c.isdigit())
    return "•••-••-" + digits[-4:] if len(digits) >= 4 else "•••-••-••••"


def hash_answer(answer: str) -> str:
    """Normalise then hash a security-question answer for constant-time-ish compare."""
    normalised = "".join(str(answer).lower().split())
    return hashlib.sha256(normalised.encode()).hexdigest()


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)
