"""Environment for the security domain."""

import json
from typing import Optional

from tau2.data_model.tasks import Task
from tau2.domains.security.data_model import SecurityDB
from tau2.domains.security.tools import SecurityTools
from tau2.domains.security.user_tools import SecurityUserTools
from tau2.domains.security.utils import (
    SECURITY_DB_PATH,
    SECURITY_POLICY_PATH,
    SECURITY_TASK_SET_PATH,
    SECURITY_TASK_SET_PATH_VOICE,
    SECURITY_TASK_SPLIT_PATH,
)
from tau2.environment.environment import Environment


def get_db() -> SecurityDB:
    return SecurityDB.load(str(SECURITY_DB_PATH))


def get_policy() -> str:
    with open(SECURITY_POLICY_PATH, "r") as fp:
        return fp.read()


def get_environment(
    db: Optional[SecurityDB] = None,
    solo_mode: bool = False,
) -> Environment:
    """Build the security environment.

    Both the agent (customer-service tools) and the user (caller tools,
    including SIM-dependent OTP reading) act on the same DB, matching
    τ²-bench's dual-control model.
    """
    if solo_mode:
        raise ValueError("security domain does not support solo mode")
    if db is None:
        db = get_db()
    tools = SecurityTools(db)
    user_tools = SecurityUserTools(db)
    return Environment(
        domain_name="security",
        policy=get_policy(),
        tools=tools,
        user_tools=user_tools,
    )


def _load_tasks(path) -> list[Task]:
    with open(path, "r") as fp:
        raw = json.load(fp)
    return [Task.model_validate(t) for t in raw]


def get_tasks(task_split_name: Optional[str] = None) -> list[Task]:
    """Text tasks. If a split name is given, filter to that split."""
    tasks = _load_tasks(SECURITY_TASK_SET_PATH)
    if task_split_name is None:
        return tasks
    splits = get_tasks_split()
    keep = set(splits.get(task_split_name, []))
    return [t for t in tasks if t.id in keep]


def get_tasks_voice(task_split_name: Optional[str] = None) -> list[Task]:
    """Voice task variants (personas with accents / noisy audio / audio pretext)."""
    return _load_tasks(SECURITY_TASK_SET_PATH_VOICE)


def get_tasks_split() -> dict[str, list[str]]:
    with open(SECURITY_TASK_SPLIT_PATH, "r") as fp:
        return json.load(fp)
