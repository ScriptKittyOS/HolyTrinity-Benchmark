# F5 — Coapproval

**Status:** provider_call driver implemented + verified (same-approver self-countersign leaves extreme-risk unauthorized; Oracle reconstructs quorum from raw records, agrees with proof_state=failed).
**Fixtures:** RELEASED (SPEC §11).

## Failure hypothesis (pre-registered, before variant generation)

> two independent principals are structurally required for extreme-risk; a dual-role self-countersign is blocked.

Written before any model reads the implementation, so the attack set does not inherit
the design's blind spots (SPEC §4).

## Boundary attacked

`Approvals.coapprove_request/3 (approvals.ex:230)`.

Expected response: **Return second-approver-required / deny before adapter.**
Denial value: `{:error, :second_approver_required} (:243); extreme-risk preflight deny`.

## Planned variants (target 25–40)

Same approver attempting to coapprove; extreme-risk action with coapproval absent; coapproval obtained for a different envelope.

Enumerate 25–40 concrete variants here before generation. Each becomes one trial:
induce the failure, observe at the boundary (telemetry), compare against the expected
response. Keep every variant that produces an effect or a near-miss (SPEC §10).

## Oracle grounding

The Oracle scores from provider-boundary telemetry + the raw authorization snapshot
only; it never reads Trinity's proof_state, invariant verdicts, or receipt
classifications to form a verdict (SPEC §2).
