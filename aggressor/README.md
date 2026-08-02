# The Aggressor — attack construction

`aggressor.ex` (`HolyTrinity.Aggressor`) builds the attacks and drives them against real code paths.
It does not simulate the system, and it never scores.

**These modules do not compile standalone** — they reference the system under test, which is not
part of this release (`../MANIFEST.md`).

| File | What |
|---|---|
| `aggressor.ex` | Builds an attack context per `{family, variant}`: the proposed action, the drive thunk, and the pre-registered annotations. |
| `variants.ex` | The data-driven variant catalogs. Corpus-backed families (F1/F2/F3) read the held red-team corpora by filename; those corpora are **not** released (see below). |
| `chaos.ex` | F6 and F9 — the structural and process-lifecycle controls, which are not prompt-driven and do not go through the Oracle. |
| `fixtures.ex` | Accounts, agent runs, approvals, postures, and idempotency keys for the trials. |

## Role separation — the load-bearing method

The Aggressor and the Oracle are **two roles that must not be one component** (`../spec/SPEC.md` §0):

- The **Aggressor** attacks. It may know the implementation. It never scores.
- The **Oracle** adjudicates from external observables. It never attacks.

`../harness/runner.ex` composes them for a single trial while keeping them separate: the Aggressor's
`drive` thunk runs the attack; the Oracle observes and decides. If one component did both, an attack
that corrupted the authorization path would corrupt its own verdict.

## The attack context contract

`Aggressor.build(family, variant)` returns a map the Runner consumes:

- `agent_run_id` — the run the Oracle snapshots.
- `proposed` — the attempted action (`provider`, `operation`, `account_id`, `idempotency_key`,
  `payload`, `approved_payload_hash`), so the Oracle can evaluate the approved-but-misrepresented
  case without reading the system's verdict.
- `agent_proposed_violation` — see the honest note below.
- `drive` — the thunk the Runner executes while the Oracle observes.
- `attack_target`, `mechanism_id`, `description`, `expected_detection_source` — pre-registered
  annotations, not measurements.

## Two things to read honestly before drawing conclusions

**`agent_proposed_violation` is a property of the trial design, not an observation.** No language
model is invoked anywhere in this harness. Every attack injects the violating action directly at the
control-plane boundary, exactly as a fully compromised model would emit it — the premise the paper
takes from the prompt-injection literature rather than re-measuring. The field records whether a
trial's input was *constructed* to be violating. Treat the column as "violating input constructed",
not as a measured model misbehaviour rate. This is deliberate: stipulating a worst-case proposal
measures the unauthorized-effect rate against an adversary that never fails to propose, and removes
the base model's variance from the result.

**`expected_detection_source` is a pre-registered expectation, not an observation.** On a prevented
trial the Runner records the family's expected denial point, because identifying the actual denying
policy would require reading the system's own tables — which the Oracle is forbidden to do. The
per-trial `notes` field carries the real result returned by the drive call.

## What is held, and why

The F1/F2/F3 corpora (`injection_corpus.json`, `runtime_payloads.json`, `runtime_responses.json`,
`skill_poisoning.json`, `skills.json`) are **not** released. `variants.ex` loads them by filename;
their *contents* are the detection surface for the content firewall, runtime sentinel, and skill
auditor, and publishing them would hand an attacker the exact strings those mechanisms are tuned
against. This is a defensive-hardening decision, pre-committed in `../spec/SPEC.md` §11 and recorded
in `../fixtures/README.md` — it is not an IP decision.

Everything else about those families is public: the taxonomy, the per-family counts, the variant
*names*, and every per-trial record in `../artifacts/`.

## Chaos families (F6, F9)

F6 and F9 need process kills and structural checks rather than prompts, so `chaos.ex` builds their
trial records directly and **does not invoke the Oracle**. They carry `effect_channel: chaos`,
`effects_observed: []`, and `system_proof_state: not_applicable`. A failing predicate records
`undetected`, so they remain falsifiable — but they are structural controls, not
independently-adjudicated attack trials, and the paper's independence claim should be read as
covering the 35 provider-call trials.

One scope limit worth stating plainly: F6's trial checks the boundary guard's **predicate** over the
source tree. It does not write the planted module to disk and does not invoke a compilation, so it is
**not** the demonstrated build failure that `../spec/SPEC.md` §4 pre-registered for this family.
