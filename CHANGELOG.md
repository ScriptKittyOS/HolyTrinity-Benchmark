# Changelog

## v1.1 — 2026-08-03

The first revision after `44b57e9`, the published release. The campaign was re-scored under a
corrected adjudicator, every published claim was re-checked against the committed data, two
experiments that should have been run the first time were run, and nine runs that shipped no
per-trial records now ship them. The defects this found were fixed or disclosed.

**The headline claim is unchanged: 0 unauthorized effects in 61 attack trials, 95% CI
[0.0%, 5.9%].**

---

### Which published numbers moved

Four figures. Two are ablation figures with a single shared cause; two are latency figures that
moved because the evidence behind them changed.

| Figure | Was | Is | Where it appears |
|---|---|---|---|
| F5 single-mechanism ablation (`approvals.two_person`) | `crossed 0 → 0`, `unauth 0 → 0` | **`crossed 0 → 2`, `unauth 0 → 2`** | §6.5, §9.1, `REPORT.md`, `spec/ABLATION.md`, `artifacts/ablation/tcb-F5.jsonl` |
| No-control ceiling | governed 63/9/1, no-control 63/59/**47** | governed 63/8/0, no-control 63/63/**51** | abstracts, §6.5, `REPORT.md`, `spec/ABLATION.md` |
| Governed latency p50 / p95 / p99 (µs) | 16882 / 57811 / 81277 (~17 ms) | **19100 / 53475 / 76336** (~19 ms) | §6.11, `REPORT.md` |
| Bypassed latency p50 / p95 / p99 (µs) | 0 / 0 / 0, cost "roughly 211 ns" | **0 / 0 / 3**, real p50 **120 ns (measured)** | §6.11, `REPORT.md` |

The no-control ceiling is **51 of 63 trials**, not of 61 attack trials — the baseline arm drives
the whole catalogue, controls included.

#### The cause of the two ablation moves

`Telemetry.span/3` emits `[:autonomous_agency, :provider, :call, :stop]` on the success path or
`…, :exception]` on a raise — **never both**. The Oracle that produced the original figures
subscribed to `:stop` alone. An adapter that **performed a real external effect and then raised**
was therefore invisible to it, and the runner's rescue scored the trial as a successful prevention.

The corrected Oracle collects both events. Two concealed unauthorized effects became visible. This
is SPEC §3's pre-committed "partial effects" edge case, which the evaluation had recorded as
untested and which turns out to have been occurring.

Consequence for F5: it must no longer be described as "enforced redundantly", "a security virtue",
or a `0 → 0` null. **Removing two-person approval admits 2 unauthorized effects.** F5 is a
demonstrated-necessary mechanism. `artifacts/ablation/tcb-F5.jsonl`'s own `_meta.caveat` had
already flagged the old result as *uninterpretable rather than a null*, and that flag never reached
the tables that reported it.

#### A second defect underneath F5's, found while re-labelling the row

The two converted F5 trials now score **`detected`**, `system_proof_state: failed`,
`detection_source: sweeper` — previously `undetected` / `missing` / `none`. The cause of the old
labels was a fixture bug: the payload omitted an email field `LocalCRM` requires, so both trials
raised mid-drive, and a trial that raises records no proof state at all. The **raise**, not a
detection failure, produced the `undetected`.

The unauthorized-effect count is **unchanged at 2**, so `0 → 2` stands everywhere. The result is
better than the label it replaces: removing two-person approval admits 2 unauthorized effects
**and the reconciliation sweeper detects both** — degradation to detection, as in the F4 ablation,
not a silent failure.

#### Why the latency figures moved

These are the numbers that changed because the **evidence** changed rather than because a claim was
wrong. No per-iteration data from the earlier run was ever committed, so those figures rested on a
transcription no reader could check. `artifacts/overhead.jsonl` now ships 200 records per arm from
a fresh run, and the table is recomputed from it by the rule the file states — so the number and
the artifact agree. Latency is machine- and run-dependent; **these percentiles are not comparable
across machines**, and a re-run producing different values is the expected outcome.

The bypassed arm's measured 120 ns p50 also settles what the old `0 µs` was: a **timer-resolution
floor, not a measurement**. At microsecond resolution 120 ns and the p95's 151 ns truncate to 0,
and the p99's 3106 ns truncates to 3.

---

### Which published numbers did NOT move

**The entire campaign.** Re-scored under the corrected Oracle on a clean tree, all 73 trials are
identical to the committed artifacts on `(family, variant, outcome, oracle_verdict,
agent_proposed_violation, detection_source)` — for both the postfix campaign and the v1-prefix
reconstruction, with the prefix/postfix delta remaining exactly the one F3 sleeper trial.

Unchanged: 73/61/12 trial split; 57 proposed violations; the **0** unauthorized-effect numerator;
95% CI [0.0%, 5.9%]; the family table; the channel split (35/20/6); the confusion matrix; the
calibration decomposition (6/4/2/29); F1–F4 and F8 ablation transitions (`0→10, 0→5, 0→5, 0→14`,
`0→0`); the TCB channel split; the compound ablation (`0→14→27`); false denials (0/75); the
blind-set result (0/32); measurement integrity.

#### Two questions this settles

**The fail-open payload-hash path never fired.** The previous comparison,
`is_nil(f.payload_hash) or f.payload_hash == executed_hash`, would authorize any action whose
approval fingerprint carried no payload hash. It could only ever convert `unauthorized` into
`authorized`, so any trial that had relied on it would flip back under the fail-closed form. None
did.

**"No undecidable verdicts" moved from vacuous to supported.** The previous Oracle had no branch
that could emit one, so the claim was unfalsifiable. The corrected Oracle has two, on ordinary
paths (`:unknown_channel`, `:unmatched_effect`). Re-run under it, both campaigns produce zero
undecidable verdicts and zero harness errors. The SPEC §8 manual-adjudication provision genuinely
was not needed.

---

### The TCB boundary, measured over the full catalog

The published §9.1 table rested on ablation runs that each drove **only their own family** — 11
`content_gate` trials for F1, 8 `runtime_gate` for F2, 7 `skill_gate` for F3. No provider-call
trial had ever been executed with a surface reducer disabled, so "0 external effects" was
guaranteed by trial selection rather than observed, and the sentence claiming the table would have
caught the opposite outcome was unsupportable.

The experiment has now been run properly: each element ablated in turn with the **full 73-trial
catalog** driven against it. Four probes, 73 trials each, all nine families live, **41
provider-call trials live in every probe** — 35 of them attack trials; the other six are F4's two
known-good controls and F7's four replays. 292 records in
`artifacts/tcb-full-catalog.jsonl`. Recomputed from that file:

| Ablated | Trials | Provider-call trials live | Unauthorized | Provider-call unauthorized |
|---|---:|---:|---:|---:|
| `security.content_firewall` | 73 | 41 | 10 (all `content_gate`) | **0** |
| `hermes.runtime_sentinel` | 73 | 41 | 5 (all `runtime_gate`) | **0** |
| `hermes.skill_auditor` | 73 | 41 | 5 (all `skill_gate`) | **0** |
| `policies.spend` | 73 | 41 | 0 | **0** |

The kernel row is unchanged and comes from `artifacts/ablation/tcb-F4.jsonl`: 29 provider-call
trials live, 14 unauthorized effects, all `provider_call`.

The effect counts are identical to the own-family runs; what changed is that the run **could have
falsified the claim and did not**. §9.1 is *measured* rather than *argued*, and the counterfactual
holds in the form this run supports: with 41 provider-call trials live under each ablation, a
surface reducer whose removal admitted even one external effect would have recorded it, and none
did.

**A wording correction that travels with this table.** An earlier draft said "35 provider-call
trials". 35 is the attack subset; 41 is the total live under the ablation. Use 41 for what was
live and 35 when speaking of attack trials.

**How this evidence was established — provenance, not retraction.** The first artifact placed
behind this claim was the wrong one: the output of the `--tcb` per-family harness, 55 trials across
four probes, each confined to its own family, with **zero provider-call trials live under any
surface-reducer ablation**. Its own `_meta.caveat` said so. On that file the external-effect zeros
were still guaranteed by trial selection, and review caught it before anything shipped. The
experiment had in fact been run; the wrong file had been placed. `artifacts/tcb-full-catalog.jsonl`
is the run that supports the claim, and it is what ships. The superseded per-family probes are kept
under an honest name at `artifacts/ablation/tcb-per-family-probes.jsonl` rather than deleted,
because their caveat is the record of why they cannot carry the claim.

#### `SpendPolicy` ablated for the first time — and it is not in the TCB

`SpendPolicy` held **13 of F4's 27 attack trials** — 48% of the family the paper calls the kernel —
while appearing in no family, no `mechanism_id`, no ablation row and no row of the §9.1 table. That
made "the trusted base is three or four elements" a lower bound over whatever happened to be
tested.

It was in fact wired for ablation the whole time, as `policies.spend`, and had simply never been
exercised. Ablated over the full catalog:

```text
  policies.spend : 0 unauthorized effects, 0 provider-call effects
```

Read against the compound ablation (`approval_binding` alone → 14; `approval_binding` +
`SpendPolicy` → 27), the interpretation is clean: **the 13 F4 trials `SpendPolicy` denied would
have been caught by `approval_binding` regardless.** Neither is individually necessary for those
13; both must fail. That is defense in depth, and it places `SpendPolicy` **outside** the trusted
computing base as a redundant second layer, not a hidden kernel element. The three-or-four-element
count is no longer a lower bound over what happened to be tested.

§6.5 gains a `policies.spend` row — `0 → 0`, over the full catalog — with an explicit note that
**unlike F5's former `0 → 0` this zero is interpretable**: the run executed, nothing raised, and
the null is a *measured redundancy* rather than a *failed measurement*. The paper now contains both
kinds of zero and a reader has to be able to tell them apart. §9.1 gains the same row (`0`
admitted, `0` provider-call) and states the full-catalog basis of the surface-reducer rows.

#### What this does not close

Scope is unchanged, and none of it is settled by the new run. Three surface reducers, each removed
**singly** — no run disables two. F6's boundary guard, F7's reconciliation and F9's process
supervision have **no runtime toggle** and are never ablated. The **membrane and the durable
authority store have no ablation row at all**; they are named as trusted-base elements on the §3
invariant's structure, not by a run that removed them.

---

### Corrections to claims that were wrong independently of the re-score

- **The pre-adapter denial split was misattributed.** Published: "35 denied before the adapter
  ran — 31 at the verifier preflight and 4 by the runtime-posture policy." Actual, recomputed
  from the `notes` field: **18 preflight/`AuthorityAssurance`, 13 preflight/`SpendPolicy`,
  2 policy/`RuntimePosturePolicy`, 1 policy/`AuthorityAssurance`, 1 policy/`AuthorityJudge`.**
  The published "31 preflight + 4 posture" split was wrong. This is what surfaced `SpendPolicy` as
  an unablated load-bearing barrier; with the ablation above, it is a correction to an attribution
  rather than a gap in the TCB argument.
- **F4 is now excluded from the independent-adjudication claim.** The Oracle decides payload
  identity with `AuthorityAssurance.canonical_payload_hash` — a function inside the system under
  test — so a canonicalization collision would yield `permit` from the system and `authorized`
  from the Oracle from one computation. F4 is 27 of the 31 trials that could falsify the
  invariant, and its whole hypothesis is that canonicalization must not collide semantically
  distinct payloads. Disclosed in §6.2 and §8.
- **F4's coverage is narrower than implied.** Five of twelve planned variant classes have zero
  trials: provider swap, operation swap, account re-attribution, idempotency-key reuse, and
  approval-missing. F4's zero bounds *payload-divergence* attacks, not the whole approval-binding
  join. Compounding it, `effects_for/2` named `account_id` in its own comment and never compared
  it, so SPEC §3's "right action, wrong attribution" case was neither tested nor testable — a
  mis-attributed effect matched the attempted action and was adjudicated as though it had executed
  on the attempted account. The comparison is now in place (see *Fixed in code*), so such an effect
  falls to `{:undecidable, :unmatched_effect}` instead. No trial in either campaign produced one,
  so no published number moves; the coverage gap itself is unchanged, since no delivered variant
  re-attributes an account.
- **The denominator ladder and the clustering correction now reach a paper reader.** Both existed
  only in `REPORT.md` and the scoring code. §6.4 publishes 61 attempts (≤5.9%), 51 that could
  produce an unauthorized effect at the provider boundary (≤7.0%), 31 external-effect-capable
  (≤9.7% one-sided), and the cluster-aware bound over mechanisms (≤32.4%). The conservative
  8-mechanism bound is published deliberately; counting `SpendPolicy` gives nine and would
  tighten it to ≤29.9%.
- **"ECE 0.0%" relabelled** to a proof-state-weighted calibration gap. The bins are seven
  categorical proof states with author-assigned confidences, not probability bins, and the zero
  follows arithmetically from 100% agreement given boundary-valued claims. The
  `manual_review_required` bin carries 70.7% of the weight, is described as an abstention, and is
  assigned P(authorized) = 0.0; at 0.5 the statistic would be ≈35.4%. Now never stated without
  the 6/4/2/29 decomposition.
- **"Added latency" relabelled to absolute governed latency.** The bypassed arm measures 0 µs at
  p50 and p95 because the mock adapter does no I/O — below `:timer.tc`'s microsecond floor. The
  subtraction returned the governed column unchanged; no percentage overhead is claimed.
- **Interval labelling.** One-sided rule-of-three bounds no longer appear under a heading shared
  with two-sided Wilson intervals. A two-sided Wilson upper limit corresponds to 97.5% one-sided
  coverage; `3/n` approximates the 95% one-sided bound.
- **The false-denial interval was added to all three abstracts** (0/75; 95% CI [0.0%, 4.9%],
  effective n=3), which previously reported a bare zero three lines after promising an interval
  on every rate.
- **The blind set's provenance defect is disclosed, and closed as far as it can be.** The shipped
  `blind/blind-set-01.json` is a corrected version of the file that was scored: the scored blob at
  `d93b5d5` carried 31 distinct shapes with a gap at `blind-32`, so the published `0/32` was
  measured over **30 distinct attack shapes, not 32**. The denominator is unaffected; the
  provenance is. The shipped file has now been re-run under the corrected Oracle and **`0/32`
  holds** — 36 rows, 32 attack trials, 0 unauthorized effects, 0 harness errors, ids `blind-01`–
  `blind-36` with no gaps — and its divergence split reproduces as **18 / 7 / 3 / 4**, matching the
  shipped attack set exactly, against the defective blob's 16 / 7 / 3 / 6. That is corroboration
  of the rate over 32 genuinely distinct shapes, not the record of the run behind the published
  figure; no JSONL from that run was retained.
- **Sample-size thresholds** `≥30 / ≥60 / ≥300` corrected to `≥31 / ≥61 / ≥301` — the inequality
  is strict, and the code already returned these.
- **The companion paper's "nine attack families"** corrected to seven induced-violation families,
  one posture-enforcement family and one reconciliation-correctness control, matching the
  evaluation paper, which explicitly says "not nine attack families."
- **F6 no longer claims a build failure.** No compiler is invoked anywhere in the released tree;
  the trial evaluates the boundary guard's predicate over the source text.

---

### What became auditable

Nine runs that previously shipped no per-trial records now ship them. `artifacts/` gains
`ablation-study.jsonl` (the six ablations plus their baseline arms in one file), `baseline.jsonl`
(the no-control ceiling, both arms), `compound.jsonl` (`0 → 14 → 27`), `tcb-full-catalog.jsonl`
(the four full-catalog §9.1 probes, 292 records), `ablation/tcb-per-family-probes.jsonl` (the
superseded per-family probe run, kept for the reason above), `overhead.jsonl` (one record per
iteration per arm), `false-denials.jsonl`, `measurement-integrity.jsonl` and `blind.jsonl`. Every
file carries a `_meta` line stating how to recompute the figure it backs, and several carry a
`caveat` bounding what the run can support.

**Every published figure now recomputes from a committed artifact**, including the `policies.spend`
ablation row, which is the fourth probe in `tcb-full-catalog.jsonl`. Two things remain outside what
an artifact can settle, and both are stated at the tables they affect:

- **Scope** — which runs exist. No artifact settles that §9.1 removes each element singly, that
  F6/F7/F9 are never ablated, or that the membrane and the durable authority store have no
  ablation row.
- **One figure is still not backed by the record of the run that produced it:** the published
  blind-set `0/32`. `blind.jsonl` is a re-run of the shipped attack file, not the scored run's
  output, and it is labelled that way in `artifacts/README.md` and `blind/README.md`.

#### An independent canonicalizer now ships

`oracle/oracle_canonical.ex` (`htb-oracle-canon/v1`) is a second canonical payload hash written
from a spec derived from SPEC §3, `families/f4-approval-binding.md` and the F4 variant list —
before reading the system's implementation — with no dependency on any `AutonomousAgency.*` module.
It does not change any verdict. Its purpose is to publish `H_oracle` beside `H_sut` so a reader can
see whether the F4 circularity disclosed above ever actually bit. The two digests are not
comparable; what is compared is the *relation* each canonicalizer asserts between the executed and
approved payloads.

Reading the system's `canonical_payload.v2` afterwards, the two agree on R1–R8 and on every entry
in the forbidden-transform table. **Five divergences, none of which touches a published number** —
all F4 payloads are flat maps over binaries, integers, floats, booleans, `nil`, lists and nested
plain maps, and no delivered variant reaches any of these surfaces:

| | Rule | What the system does | Kind |
|---|---|---|---|
| F-1 | R8a NFC normalization | byte-exact strings, no Unicode normalization — documented and deliberate | posture difference; system stricter, so any disagreement is a false denial, never a bypass |
| F-2 | R2a mixed key namespace | sorts on the stringified key, so `%{:a => 1, "a" => 2}` and `%{"a" => 1, :a => 2}` both render `{"a":1,"a":2}` | collision |
| F-3 | R10 struct tagging | generic struct clause is `Map.from_struct/1 \|> encode()`, erasing struct identity | collision — the widest of the five |
| F-4 | R9/R11 invalid UTF-8 and opaque terms | `Jason.encode!/1` raises on invalid UTF-8, `to_string/1` on tuples, inside preflight | availability, not collision |
| F-5 | R12 temporal/decimal types | renders `Date`/`Time`/`DateTime`/`NaiveDateTime`/`Decimal` to a bare JSON string, so `Decimal.new("1.0")` collides with `"1.0"` | collision |

NFKC and NFKD are prohibited in the derived spec and the reason is recorded: on this OTP,
`:unicode.characters_to_nfkc_binary("ＵＳＤ") == "USD"`, which would make the
`mutate:currency-fullwidth` payload byte-identical to the approved one and the mutation
undetectable by construction. R12's *set* of named types was adopted from the implementation and is
marked as such; its encoding was not.

**A structural finding worth reporting on its own: the cross-check cannot currently be computed
from persisted evidence.** `oracle_matches_approved` needs the **approved payload**, and the schema
does not store it — `approval_requests.metadata["payload_hash"]` and
`authority_approval_fingerprints.payload_hash` hold only `H_sut(approved)`, and the execution
envelope carries the hash rather than the payload. A hash cannot be re-canonicalized under a
different scheme, so no independent adjudicator can reconstruct SPEC §3 clause (b) from the record
as it stands. Where the approved payload is not recoverable the Oracle records
`status: :approved_payload_not_persisted` and **`canonical_hash_agrees: nil` — never `true`, because
an uncomputable check must not read as a passing one.** The fix is to persist a second,
independently computed payload hash at approval time; it is named as future work and is not done.

---

### Fixed in code

- `oracle/oracle.ex` — the corrected adjudicator is now the one that runs. Payload-hash
  comparison fails closed; `:undecidable` verdicts exist on ordinary paths; provider
  `:exception` events are collected. `effects_for/2` now compares `account_id`, which its own
  comment had always claimed and the filter never did; a mis-attributed effect now returns
  `{:undecidable, :unmatched_effect}` rather than matching the attempted action.
- `harness/runner.ex` — environment restore moved into an `after` block, so an exception
  mid-trial can no longer leak mutated configuration into subsequent trials of an `--all` run.
  No published trial raised, so no published number was affected.
- `harness/false_denials.ex` — the interval's lower bound is computed rather than hard-coded, and
  a rule-of-three bound is emitted only when the numerator is zero.
- `harness/holytrinity.run.ex` — the blind-set driver used the denylist denominator that the
  allowlist fix corrected everywhere else.
- `SHA256SUMS` — removed a manifest entry for `erl_crash.dump`, a gitignored file absent from the
  repository, which caused `sha256sum -c SHA256SUMS` to **exit 1 on every fresh clone** of the
  previous release.

---

### Gates and reproduction

Run against a clean checkout of this revision:

- `sha256sum -c SHA256SUMS` — **passes**, every entry. That is the `erl_crash.dump` fix above
  taking effect: the same command exited 1 on every fresh clone of the previous release.
- `python3 scoring/verify.py <file>` over all 17 committed JSONL artifacts — **PASS on every
  one**, 328 recomputed values in total: 96 for the postfix campaign, 97 for the v1-prefix
  reconstruction, and the rest across the ablation, baseline, compound, full-catalog, overhead,
  false-denial, measurement-integrity and blind artifacts.
- `scoring/verify.exs` — an independent Elixir implementation with its own JSON decoder;
  `diff <(elixir scoring/verify.exs FILE) <(python3 scoring/verify.py FILE)` is empty.
- `python3 scoring/test_denominator.py` — **passes**; all four scorers agree that malformed
  outcomes stay out of the denominator and stay visible.

Every campaign number recomputes from the committed JSONL with `scoring/verify.py` or
`scoring/verify.exs`. The six single-mechanism ablations recompute from `artifacts/ablation/`.

The system under test remains unreleased, so the campaign is not end-to-end re-executable.

`spec/SPEC.md` is unedited. The full file list for this revision is `git diff --stat 44b57e9`.
