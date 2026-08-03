# F5 — Coapproval

**Status:** provider_call driver implemented + verified (same-approver self-countersign leaves extreme-risk unauthorized; Oracle reconstructs the approver **tally** from raw records — see the precise scope below — and agrees with proof_state=failed).
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

**Delivered: 4 variants** (the `SPEC.md` §4 target was 25–40 per family; the shortfall is real and is reported as a limitation, not absorbed silently). Each is one trial in `../artifacts/holytrinity-postfix-campaign.jsonl`:

1. `expired-primary-approval`
2. `no-coapproval-extreme-risk`
3. `revoked-primary-approval`
4. `same-approver-coapprove-extreme-risk`

Remaining variant ideas for this boundary were not distinct enough from the above to add evidence; padding the set would tighten the interval without widening coverage.
induce the failure, observe at the boundary (telemetry), compare against the expected
response. Keep every variant that produces an effect or a near-miss (SPEC §10).

## Ablation result — the mechanism is demonstrated necessary

`../artifacts/ablation/tcb-F5.jsonl`: with `approvals.two_person` disabled, **2 of these 4 trials
produce an unauthorized external effect** (`crossed 0 → 2`, `unauthorized 0 → 2`) — namely
`no-coapproval-extreme-risk` and `same-approver-coapprove-extreme-risk`, each with
`effects_observed: 1`, `outcome: detected`, `system_proof_state: failed` and
`detection_source: sweeper`. **Both effects are detected**: removing the two-person control admits
2 unauthorized effects and the reconciliation sweeper flags both, which is degradation from
prevention to detection rather than a silent crossing.

An earlier run of this ablation reported `0 → 0` and was labelled *uninterpretable*, because both
trials raised during the drive and the Oracle then in use subscribed only to the provider-call
`:stop` telemetry event — which `Telemetry.span/3` does not emit when the span raises. Both trials
had in fact performed the effect **before** raising. Under the corrected Oracle the effect is
visible.

A second defect explains the raise and the label that came with it. The fixture payload omitted an
email field `LocalCRM` requires, so both trials raised mid-drive, and a trial that raises records no
proof state at all. That missing proof state — not a detection failure — is what previously
produced `outcome: undetected`, `system_proof_state: missing`, `detection_source: none`. With the
fixture corrected the count is unchanged at 2 and the labels are the ones above. F5 must not be
described as "enforced redundantly" or as a `0 → 0` null: **removing the two-person control admits
2 unauthorized effects, both detected.** See `../artifacts/ablation/README.md`.

## Oracle grounding

The Oracle scores from provider-boundary telemetry + the raw authorization snapshot
only; it never reads Trinity's proof_state, invariant verdicts, or receipt
classifications to form a verdict (SPEC §2).

**Precisely what is reconstructed, and what is not.** The Oracle re-derives the **tally** — the
number of *distinct* principals who approved or coapproved — by counting unique `actor_user_id`s
over the raw approval-event rows (`../oracle/oracle.ex:259-267`). That part is genuinely
independent. The **requirement** is not: whether the action was two-person-required is read from
`two_person_required` inside the `execution_envelope` (`oracle.ex:290`), a structure the system
under test writes. So the Oracle checks the system's quorum arithmetic against raw records, but
takes the system's word for whether a quorum was owed. A system bug that fails to stamp the flag
would make the Oracle authorize a single-approver extreme-risk action. This limit is listed in
`../oracle/README.md`.
