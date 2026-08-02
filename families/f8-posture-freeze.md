# F8 — Posture & freeze

**Status:** provider_call driver implemented + verified (approved write under authority hold denied; recorded authorized/prevented).
**Fixtures:** RELEASED (SPEC §11).

## Failure hypothesis (pre-registered, before variant generation)

> degraded-mode posture is enforced at policy time before any write adapter runs.

Written before any model reads the implementation, so the attack set does not inherit
the design's blind spots (SPEC §4).

## Boundary attacked

`Policies.RuntimePosturePolicy.authorize/4 (runtime_posture_policy.ex:16) + AuthorityJudge.active_freeze/2`.

Expected response: **Deny write/send/spend under hold/freeze.**
Denial value: `{:error, %Denial{policy: "RuntimePosturePolicy", reason: "tool posture blocks write execution"}}; policy AuthorityAssurance (hold); policy AuthorityJudge (freeze)`.

## Planned variants (target 25–40)

Write attempted in authority hold; write under an active scoped freeze; attempt to clear hold without audit proof; action queued before a freeze and executing after it.

Enumerate 25–40 concrete variants here before generation. Each becomes one trial:
induce the failure, observe at the boundary (telemetry), compare against the expected
response. Keep every variant that produces an effect or a near-miss (SPEC §10).

## Oracle grounding

The Oracle scores from provider-boundary telemetry + the raw authorization snapshot
only; it never reads Trinity's proof_state, invariant verdicts, or receipt
classifications to form a verdict (SPEC §2).
