# voice-agent-benchmark

Security extensions for voice agent benchmarks in the **τ-Voice / τ²-bench**
family ([τ-Voice, arXiv 2603.13686](https://arxiv.org/abs/2603.13686);
[sierra-research/tau2-bench](https://github.com/sierra-research/tau2-bench)).

## `security` domain

A drop-in security domain for voice banking agents (Talkdesk-style contact
centers). It adds three layered task groups — social-engineering red-team,
authentication robustness, and PII/data-leak resistance — on top of a
transactional banking data model forked from τ²-bench's `banking_knowledge`.

The core idea: tools execute what the agent is told (τ-bench style), so the
policy is the control under test. Attack tasks carry an empty reference
trajectory, so **any privileged mutation an attacker talks the agent into scores
0** — giving an attack-success-rate for free — while a SIM-swap task and a noisy
"bad line" persona exercise the voice channel specifically.

See [`src/tau2/domains/security/README.md`](src/tau2/domains/security/README.md)
for the threat model, evaluation design, and how to register and run it.

```
src/tau2/domains/security/   # domain package (Python)
data/tau2/domains/security/  # policy.md, db.json, tasks, splits
```
