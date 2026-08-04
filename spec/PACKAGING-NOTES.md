# Packaging notes for the frozen specification

`SPEC.md` is **frozen** — committed once, before the first scored run, and never edited (a single
commit at 2026-08-01T22:17:36Z; the scored campaign ran 2026-08-02T04:04:04Z). We do not edit it,
including to fix cosmetic problems. This file records what a reader needs to know to read it in
this release.

## Relative paths resolve one level up

`SPEC.md` was authored at the root of the private benchmark tree. In this release it lives in
`spec/`, so two of the internal paths it cites do not resolve as written:

| `SPEC.md` says | resolves here to |
|---|---|
| `families/README.md` (§4 and §7) | `../families/README.md` |
| `fixtures/README.md` (§11) | `../fixtures/README.md` |

`SPEC.md` §4 also cites `test/.../tool_loop_boundary_test.exs`, which lives in the system under
test and is not part of this release.

## Directories named in SPEC

§0 describes the two roles as `aggressor/` and `oracle/`. Both are released, at those paths. They
reference the system under test and do not compile without it, so they are published to be read
rather than run (`../MANIFEST.md`). The role separation SPEC §0 describes is the paper's
methodological claim, and releasing both directories is what makes it checkable.

§4 additionally cites `aggressor/chaos/` for the F6 and F9 chaos harness. That path does not
resolve here: the chaos driver is a single module at `../aggressor/chaos.ex` rather than a
directory. The frozen text describes the private development layout, and flattening it for release
is a packaging change rather than a methodology change.

## Other references in the frozen text that do not resolve

Three more, found in review. All three are recorded here rather than fixed in `SPEC.md`.

1. **The A–I letter mapping (§4).** §4 says the families are "re-mapped onto the evaluation
   plan's letters A–I and the architecture's nine mechanisms in `families/README.md` so a reader
   can trace mechanism → attack → result with one lookup." `../families/README.md` carries no
   A–I mapping. What it does carry is the split the paper actually uses (§6.3): seven
   induced-violation families, one posture-enforcement family, one reconciliation-correctness
   control, with per-family boundary, attempts, proposed violations and unauthorized effects. The
   letter scheme belonged to a private evaluation plan that was never released, so the mapping
   would have had nothing on the other side of it. The mechanism → attack → result trace is
   present; the letters are not.

2. **Five fixture sets shipped where §11 pre-committed four.** §11's Option B names **F4, F5,
   F8, F9** for release and holds F1–F3. Five family definitions ship: F4, F5, **F6**, F8, F9.
   F6 is the membrane-bypass positive control, released because it is a structural result — a
   guard predicate checked over the source tree — that exposes no detection signature. This is a
   release *beyond* the pre-commitment, not short of it; the held set is exactly the F1–F3 §11
   named. F7's definition is pending and is neither held nor released.

3. **§7 cites `families/README.md` too.** The `mechanism_id` field comment in the §7 trial-record
   schema points at `families/README.md` for the mechanism a trial maps to. The path table above
   now attributes that path to §4 *and* §7; it previously named §4 only.

## Departures between the frozen schema and the shipped artifacts

`SPEC.md` §7 fixes the trial-record schema. Four departures are present in the committed
artifacts and are documented in `../artifacts/README.md` rather than by editing §7:

1. `detection_source` carries `compile_time` on the six F6/F9 structural trials, which is outside
   §7's enumeration.
2. `authorization_snapshot_ref` is a `{start, end}` timestamp pair, not the snapshot *file
   references* §7 specifies; the raw approval-record snapshots are not published.

3. `proposed_action` carries an extra `effect_channel`; `payload_summary` is an object rather than
   a string; and the gate and chaos trials carry `provider: null` / `operation: null`.

4. `detection_source` carries `invariant_check` on the 118 `detected` trials in the ablation
   artifacts. §7's enumeration is `preflight | policy | sentinel | firewall | sweeper | none`, so
   this is outside it. §7 named `sweeper` because the asynchronous reconciliation worker was
   expected to be the detector. It cannot run in the bench environment — `config/test.exs` sets
   Oban `testing: :manual`, so no job executes unless a test drains the queue, and the bench never
   does. What actually flags a trial is a synchronous read of the `proof_state` that
   `AuthorityAssurance.summary_for_run/1` derives from the `InvariantCheck` rows written in-router
   during the call. The detection is real and the count is right; the frozen name was wrong, and
   the field now names the mechanism that fires rather than the one that was expected to.

Further departures between what §4, §6, and §2.1 pre-registered and what the campaign delivered
are recorded here rather than by amending `SPEC.md` — that is the point of freezing it:

| `SPEC.md` pre-registered | delivered |
|---|---|
| §4: 25–40 variants per family, ~250–350 trials | **73 trials**, 3–29 per family; only F4 (29) is in range |
| §6: false denials from "the reads-only production soak", broken out by policy | synthetic n=75 (three amount configurations × 25 repeats), no per-policy breakout |
| §6: "p50/p95/p99 **added** latency per governed action, throughput ceiling both ways, per-agent process + memory overhead", with a confidence interval | **absolute governed** latency percentiles only, on one machine, with no interval. The added-latency figure §6 asks for cannot be computed: the ungoverned arm is a no-I/O mock adapter measuring 120 ns at p50, so the subtraction returns the governed column unchanged, and the two arms were never paired per call. Throughput and memory were not measured. Per-iteration records ship as `../artifacts/overhead.jsonl` |
| §2.1: authorization snapshot taken "through a **separate DB connection**" | the Oracle reads the raw approval tables through the same repository as the system under test |
| §2.1: snapshots at start *and* end so "a diff between the two snapshots is evidence" | both are captured, but adjudication uses the end snapshot only; the diff is never computed |
| §4 (F6): "confirm the compile-time invariant **fails the build**" | the guard's predicate is checked over the source tree; no build is invoked |
| §4 (F9): "kill/reseed; TOCTOU; concurrency" | reseed-identity and idempotence checks only |
| §1: "Detected … record time-to-detection" | no `detected` trials occurred **in the campaign**, so the campaign reports no detection latency. The ablation runs do produce them: `detection_latency_ms` is populated on the 14 detected F4 trials and the 2 detected F5 trials in `../artifacts/ablation/` |
| §2.3: `undecidable` "reported as its own count" | no `undecidable` verdicts occurred; the report has no such column |

The load-bearing independence property — that the Oracle never reads the verifier's `proof_state`
and reconstructs authorization from raw approval records — holds as specified. The *transport*
independence in §2.1 does not, and is named as future work in the paper's conclusion.

## Deviations found after the release, recorded here

**The F5 ablation was re-scored: `0 → 0` became `0 → 2`.** The originally published F5
single-mechanism ablation reported zero crossings and zero unauthorized effects with
`approvals.two_person` disabled. That was a measurement artifact, not a result. `Telemetry.span/3`
emits `[:autonomous_agency, :provider, :call, :stop]` on success **or** `[…, :exception]` on a
raise, never both; the Oracle that produced the original figure subscribed to `:stop` alone. An
adapter that performed a real external effect and then raised was therefore invisible, and the
runner's rescue scored the trial a successful prevention. The corrected Oracle collects both
events. Two trials moved — `no-coapproval-extreme-risk` and
`same-approver-coapprove-extreme-risk`, each `effects_observed 0 → 1`.
`../artifacts/ablation/tcb-F5.jsonl` is regenerated; the other five ablation files are
trial-for-trial identical.

A **second** defect sat under the first, and it is the reason the two trials raised at all: the F5
fixture payload omitted an email field `LocalCRM` requires. A trial that raises mid-drive records no
proof state, and that missing proof state — not a failure of detection — produced the intermediate
reading `outcome undetected`, `system_proof_state missing`, `detection_source none`. With the
fixture corrected the two trials score **`outcome detected`, `system_proof_state failed`,
`detection_source invariant_check`**, and the unauthorized-effect count is **unchanged at 2**. So the
transition is `outcome prevented → detected` and `detection_source preflight → invariant_check`; `0 → 2`
stands, and the failure mode is degradation to detection rather than a silent crossing.

Two consequences for the frozen text:

- Removing two-person approval admits **2 unauthorized effects**, and the invariant check
  detects both. F5 is a demonstrated-necessary mechanism, not one that "resists single-clause
  ablation."
- §3's pre-committed **partial-effects** edge case — "half-executed before a denial → unauthorized
  if *any* external state changed" — is now an **observed** case rather than an untested one. It was
  pre-registered before the run and the run has since produced instances of it. Both moved trials
  performed an external effect and then raised; under §3 they are unauthorized, and that is how
  they now score.

The scored campaign is unaffected: it re-scored trial-for-trial identical across all 73 trials in
both campaigns. The two-person control held there, so nothing was performed and nothing raised.
The blind spot only manifests once the control is ablated away.

**`undecidable` is a sixth `outcome` value; §7 enumerates three.** Review found that the Oracle's
`:undecidable` verdict had no matching `resolve_outcome` clause in the harness runner, so a verdict
written to keep an unexplainable trial *in* the record would instead have raised
`FunctionClauseError`, been rescued into `harness_error`, and dropped from both the numerator and
the denominator — precisely the outcome the `:undecidable` branch exists to prevent. The runner now
carries `:unknown_channel` and `:unmatched_effect` clauses resolving to a distinct `undecidable`
outcome, excluded from both numerator and denominator and printed as its own count.

That makes the emitted vocabulary six values where §7 enumerates three:
`prevented | detected | undetected` are the pre-registered set; the harness also emits `allowed`
(a correctly authorized effect on a known-good control), `harness_error` (a crashed trial), and now
`undecidable`.

This extends the frozen text rather than contradicting it. SPEC §2.3 already *requires* that an
`undecidable` verdict be "reported as its own count", and an outcome-level counterpart is what
makes that reportable — the previous arrangement satisfied §2.3 on paper while making the count
unreachable in practice. `allowed` and `harness_error` predate this note and are recorded here for
completeness; `scoring/trial.ex`'s `@type outcome` covered none of the three and has been widened
to the six actually emitted.

**Nothing published is affected.** Zero `undecidable` and zero `harness_error` across all 146
re-scored trials, and a full campaign re-run with the corrected clauses active diffs to **0
differing trials** against the committed artifact. The `undecidable` count of 0 is now established
under an Oracle that *can* emit one, which the pre-re-score figure was not.
