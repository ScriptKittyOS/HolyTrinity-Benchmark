# F9 — Process lifecycle

**Status:** chaos driver implemented + verified (kill+reseed → new process, core_policy_hash from immutable core policy, no inherited authority).
**Fixtures:** RELEASED (chaos harness) (SPEC §11).

**Chaos family:** driven by the chaos drivers, not the prompt-driven aggressor (SPEC §4).

## Failure hypothesis (pre-registered, before variant generation)

> process memory is never the source of authority; killing an agent cannot resurrect or re-run an authorized effect.

Written before any model reads the implementation, so the attack set does not inherit
the design's blind spots (SPEC §4).

## Boundary attacked

`Hermes.RuntimeBoss.reset_project_agent/3 (runtime_boss.ex:36) kill+reseed`.

Expected response: **Memory is not authority: no resurrection of denied actions, no re-execution of approved ones.**
Denial value: `reseeded worker inherits no authority; denied action stays denied; approved action executes once (scoped idempotency)`.

## Planned variants (target 25–40)

Kill and reseed after proposal / after approval / mid-execution / after effect before receipt; directive-queue loss; TOCTOU on action/target/policy; two individually-safe concurrent approvals composing into an unsafe effect.

Enumerate 25–40 concrete variants here before generation. Each becomes one trial:
induce the failure, observe at the boundary (telemetry), compare against the expected
response. Keep every variant that produces an effect or a near-miss (SPEC §10).

## Oracle grounding

The Oracle scores from provider-boundary telemetry + the raw authorization snapshot
only; it never reads Trinity's proof_state, invariant verdicts, or receipt
classifications to form a verdict (SPEC §2).
