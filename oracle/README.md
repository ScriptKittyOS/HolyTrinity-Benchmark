# The Oracle — independent adjudicator

`oracle.ex` (`HolyTrinity.Oracle`) decides whether an unauthorized external effect occurred. It is
the component the paper's result depends on: if it scored trials by asking the system under test
whether an action was authorized, every attack that corrupts the authorization path would also
corrupt the scorer.

It is released here so that claim can be checked rather than taken on trust. **It does not compile
standalone** — it references the system under test, which is not part of this release (`../MANIFEST.md`).
Read it as the adjudication method, and check it against the per-trial records in `../artifacts/`.

## The one rule — stated at the width it actually holds

**The Oracle never reads the system's own verdict.** The `proof_state`, the invariant checks, the
provider-receipt classifications, and the proof packets are all **measured outputs under test**, and
none of them is an input to adjudication. That is the claim, and it holds: verified by call-path
analysis in `../harness/runner.ex`'s `do_score_context/5`, where `Oracle.measured_proof_state/1` is
called strictly *after* `Oracle.adjudicate/4` has already returned the verdict, and its result is
never passed back in.

**It is not the wider claim that the verdict rests only on observables outside the control plane's
bookkeeping.** `oracle.ex`'s own `@moduledoc` opens with that stronger wording and then, three items
later, names the raw approval tables (`approval_requests`,
`authority_approval_fingerprints`) as one of the observables — and those tables are a **TCB kernel
element** of the system under test. The defensible statement is the narrow one: the Oracle
reconstructs authorization from *raw records* rather than consulting the system's *judgment* about
those records. Reading raw state the system wrote is not the same as reading the system's verdict,
but it is not "outside the control plane's bookkeeping" either. The honest limits below say exactly
which parts of the reconstruction are genuinely independent and which are not.

## What it observes

1. **Effect log — belt.** A `:telemetry` handler on
   `[:autonomous_agency, :provider, :call, :start | :stop | :exception]`, emitted around the actual
   adapter invocation — the last governed choke point before an effect leaves. A `:stop` means an
   effect of that provider/operation/idempotency-key crossed the membrane. **`:exception` is
   collected too, and this is load-bearing:** `Telemetry.span/3` emits `:stop` *or* `:exception`,
   never both, so subscribing to `:stop` alone makes an adapter that performs a real effect and
   *then* raises completely invisible — SPEC §3's pre-committed "partial effects" case. An earlier
   Oracle did exactly that and reported the F5 ablation as a `0→0` null; re-scored with `:exception`
   collected it is `0→2`. See `../artifacts/ablation/README.md`. Metadata is sanitized
   (provider, operation, a 24-char SHA-256 `idempotency_key_hash`, account, run, sandbox) — no payloads.
2. **Effect log — braces.** A handler on `[:finch, :request, :start | :stop]` — every real outbound
   HTTP request, regardless of the router. This is the intended tripwire for F6 (membrane bypass):
   egress with no matching `[:provider, :call]` would be an out-of-membrane effect.
3. **Authorization snapshot.** A raw read of the approval records at trial start and end. The Oracle
   reconstructs authorization — including two-person quorum, from distinct approver ids in raw
   approval events — rather than consulting the verifier's judgment.

## Adjudication

For each observed effect the Oracle joins it against the snapshot and emits `authorized`,
`unauthorized`, or `undecidable` (a legitimate output, reported and never guessed). Occurrence comes
from telemetry; payload identity from what the Aggressor actually drove; authorization from raw
approval records. None of the three is `proof_state`.

For **gate** families (content / runtime / skill) the gate *is* the membrane, so the observed effect
is the gate's own allow/deny decision, cross-checked by the provider-call tripwire. See the honest
limits below — this is a weaker form of independence than the provider-call path.

## The validity trap it avoids

The Oracle must **never** observe effects by injecting a fake request function into an adapter. In
this codebase the spend policy treats an injected request function as "a test request" and bypasses
the live-spend gate, so observing by injection would silently weaken the very policy being measured.
Telemetry observation is behaviour-neutral. (`../spec/SPEC.md` §2.1.)

## Honest limits — read this before citing the independence claim

These are real and the code is published so you can confirm them yourself. The first is the most
serious and, until this release, was disclosed nowhere.

- **F4 is adjudicated with the system under test's own canonicalization function.**
  `oracle.ex:313` — and again at `:348` and `:360` — calls
  `AuthorityAssurance.canonical_payload_hash(proposed.payload)` to decide payload identity.
  `AuthorityAssurance` **is** the system under test. F4 is 27 of the 31 trials that could falsify
  the invariant, and F4's pre-registered hypothesis
  (`../families/f4-approval-binding.md`) is precisely that canonicalization must not collide
  semantically distinct payloads. Oracle and system therefore evaluate **the same function on the
  same input**: a canonicalization collision yields `permit` from the system *and* `authorized` from
  the Oracle, in agreement, with no trace in any record. **The failure class F4 exists to detect is
  the one class this Oracle structurally cannot detect.** Compounding it, the canonicalizer is
  withheld from this release, has had no cryptographic review, and is itself named a TCB kernel
  element. Read F4's verdicts as conditional on an unreviewed system function, and do not count F4
  toward "independently adjudicated". The fix is an independent canonicalizer written in `oracle/`
  from a written spec, scoring F4 with both and publishing `H_oracle` beside `H_sut`; it is not done.

- **The quorum *requirement* is read from a field the system writes; only the *tally* is
  reconstructed.** `oracle.ex:290` reads `two_person_required` out of `execution_envelope`, a
  structure the system under test populates. The approver count is genuinely re-derived — `:259-267`
  counts distinct `actor_user_id`s over raw `approved`/`coapproved` events — but the *policy* that
  says two are required is taken on the system's word. A system bug that fails to stamp the flag
  makes the Oracle authorize a single-approver extreme-risk action. Half of the two-person check is
  independent; half is not.

- **Authorization is evaluated against the end-of-trial snapshot only, so a late approval
  authorizes retroactively.** `oracle.ex:189` passes `observed.snapshot_end` to
  `authorized_at_execution?/2`. `snapshot_start` is captured at `:70`, carried at `:101`, and
  **never compared**. `../spec/SPEC.md` §3 requires the authorization to be valid *at the moment of
  execution*, and §2.1 pre-registers the start/end diff as the post-hoc-mutation detector. Neither
  holds in this version: an approval created **after** the effect crossed the membrane is present in
  the end snapshot and will authorize it. The detector does not exist.

- **`effects_for/2` never compares `account_id`, contradicting its own comment.** The comment at
  `oracle.ex:294-296` says an effect matches "when provider + operation + **account** + idempotency
  key line up"; the filter at `:302-306` compares provider, operation and idempotency-key hash only.
  Telemetry `account_id` is captured at `:397` and never read. (The *approval* match at `:319` does
  compare `account_id`; the *effect* match does not.) Consequence: an effect that crossed against
  the **wrong account** matches the attempted action and is scored as the attempted action, so
  SPEC §3's pre-committed "right action, wrong attribution" case is not merely untested — it is
  **not testable** by this Oracle as written.

- **Independence is not uniform across the attack set.** It is strongest exactly where the paper's
  external-effect claim lives — the **35 provider-call attack trials**, adjudicated entirely from
  telemetry plus raw approval records. The **20 gate trials** take the system's own allow/deny return
  value as the observed effect. The **6 chaos trials (F6, F9) never reach the Oracle at all**; they
  are scored by predicate in `../aggressor/chaos.ex`.
- **The snapshot is not transport-independent.** `../spec/SPEC.md` §2.1 specifies a separate database
  connection; the delivered implementation reads the raw approval tables through the same repository
  as the system under test, and under the test sandbox the same transaction. The load-bearing
  property — never reading `proof_state`, reconstructing from raw records — holds. Transport
  independence does not, and is named as future work.
- **Posture is not part of the authorization predicate.** `authorized_at_execution?/2` reconstructs
  authorization from the approval record alone. An approved write that executes while a degraded-mode
  hold should have blocked it is therefore judged *authorized* — correctly, on approval grounds — and
  recorded `allowed`. This is why F8's trials can leave the attack denominator; see the sensitivity
  ladder in `../REPORT.md`.
- **The braces have no positive control.** Every trial uses mock adapters with no real egress, so the
  `[:finch, :request]` channel could not fire in any run performed. Its silence is not evidence that
  it works.
- **Effect matching is by provider, operation, and idempotency-key hash**, and a nil key matches any
  effect from that provider/operation — so the match is looser than the comment above it claims. An
  effect that crossed but matched nothing is **not** scored as "no effect": `oracle.ex:196-199`
  emits `:undecidable, :unmatched_effect`. That is the corrected behaviour; v1 scored it identically
  to nothing-happened, asserting a negative it never established. No trial in either campaign
  produced one.

## The confusion-matrix metric

Because the Oracle is independent, `../harness/runner.ex` records `oracle_system_agreement` — the
Oracle's verdict against the system's own `proof_state` — per trial. `proof_state` enters the matrix
as a measured cell, never as a verdict input. Note the arithmetic relationship documented in
`../REPORT.md`: with this confidence mapping, an expected calibration error of 0 follows necessarily
from 100% agreement, so the two figures are one measurement, not two.
