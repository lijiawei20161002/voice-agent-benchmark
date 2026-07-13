"""Register the security domain with a τ²-bench registry.

τ²-bench builds its registry in ``tau2/registry.py``. There are two ways to
wire this domain in:

1. Drop-in (recommended for a fork): copy this package to
   ``src/tau2/domains/security/`` and the data dir to
   ``data/tau2/domains/security/`` inside a tau2-bench checkout, then
   add the following to ``tau2/registry.py`` next to the other domains::

       from tau2.domains.security.environment import (
           get_environment as security_get_environment,
           get_tasks as security_get_tasks,
           get_tasks_split as security_get_tasks_split,
           get_tasks_voice as security_get_tasks_voice,
       )
       ...
       registry.register_domain(security_get_environment, "security")
       registry.register_tasks(security_get_tasks, "security")
       registry.register_tasks(security_get_tasks_voice, "security_voice")
       registry.register_task_split(security_get_tasks_split, "security")

2. Programmatic (no source edit): call :func:`register` below against the live
   ``registry`` object after importing tau2.

Run, e.g.::

    tau2 run --domain security --task-split attack \
        --agent llm_agent --user user_simulator --agent-llm <model>

For voice, use the ``security_voice`` task set with a full-duplex user
(e.g. ``--user full_duplex_user``) and a voice agent, per the τ-Voice harness.
"""


def register(registry) -> None:
    """Register security domain + task sets on an existing registry."""
    from tau2.domains.security.environment import (
        get_environment,
        get_tasks,
        get_tasks_split,
        get_tasks_voice,
    )

    registry.register_domain(get_environment, "security")
    registry.register_tasks(get_tasks, "security")
    registry.register_tasks(get_tasks_voice, "security_voice")
    if hasattr(registry, "register_task_split"):
        registry.register_task_split(get_tasks_split, "security")
