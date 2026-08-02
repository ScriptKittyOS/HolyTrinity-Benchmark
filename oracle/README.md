# The Oracle — independent adjudicator

`oracle.ex` (`HolyTrinity.Oracle`) decides whether an unauthorized external effect occurred. It is
the component the paper's result depends on: if it scored trials by asking the system under test
whether an action was authorized, every attack that corrupts the authorization path would also
corrupt the scorer.

It is released here so that claim can be checked rather than taken on trust. **It does not compile
standalone** — it references the system under test, which is not part of this release (`../MANIFEST.md`).
Read it as the adjudication method, and check it against the per-trial records in `../artifacts/`.

## The one rule

**The Oracle never reads the system's own verdict.** The `proof_state`, the invariant checks, the
provider-receipt classifications, and the proof packets are all **measured outputs under test**. The
verdict is formed only from observables captured outside that bookkeeping.

## What it observes

1. **Effect log — belt.** A `:telemetry` handler on
   `[:autonomous_agency, :provider, :call, :start | :stop | :exception]`, emitted around the actual
   adapter invocation — the last governed choke point before an effect leaves. A `:stop` means an
   effect of that provider/operation/idempotency-key crossed the membrane. Metadata is sanitized
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

These are real, they are disclosed in the paper's threats to validity, and the code is published so
you can confirm them yourself.

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
- **The start/end snapshot diff is captured but never computed.** `../spec/SPEC.md` §2.1
  pre-registers that diff as the post-hoc approval-mutation detector. Adjudication uses the end
  snapshot only, so that detector does not exist in this version.
- **Posture is not part of the authorization predicate.** `authorized_at_execution?/2` reconstructs
  authorization from the approval record alone. An approved write that executes while a degraded-mode
  hold should have blocked it is therefore judged *authorized* — correctly, on approval grounds — and
  recorded `allowed`. This is why F8's trials can leave the attack denominator; see the sensitivity
  ladder in `../REPORT.md`.
- **The braces have no positive control.** Every trial uses mock adapters with no real egress, so the
  `[:finch, :request]` channel could not fire in any run performed. Its silence is not evidence that
  it works.
- **Effect matching is by provider, operation, and idempotency-key hash**, and a nil key matches any
  effect from that provider/operation. An effect that failed to match would be scored as no effect.

## The confusion-matrix metric

Because the Oracle is independent, `../harness/runner.ex` records `oracle_system_agreement` — the
Oracle's verdict against the system's own `proof_state` — per trial. `proof_state` enters the matrix
as a measured cell, never as a verdict input. Note the arithmetic relationship documented in
`../REPORT.md`: with this confidence mapping, an expected calibration error of 0 follows necessarily
from 100% agreement, so the two figures are one measurement, not two.
