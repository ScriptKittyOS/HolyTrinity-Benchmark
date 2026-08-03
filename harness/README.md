# The harness — runner and campaign drivers

The modules that compose the Aggressor with the Oracle and run the campaigns behind every number in
`../REPORT.md`.

**None of these compile standalone** — they reference the system under test, which is not part of
this release (`../MANIFEST.md`). They are published so the method is inspectable and the numbers'
provenance is checkable, not so the campaign can be re-executed today.

| File | What it produces |
|---|---|
| `runner.ex` | The core loop. Builds a trial context, starts the Oracle, drives the attack, adjudicates, and writes one `../spec/SPEC.md` §7 trial record. Everything else calls into this. |
| `ablation_study.ex` | The per-mechanism ablation and the no-control baseline (paper §6.5). |
| `measurement_integrity.ex` | The F10 controls — does the effect log fire when an effect occurs, and what is invisible to it (paper §6.7). |
| `blind_set.ex` | Compiles a declarative attack file from `../blind/` into real trials and scores them through the same Oracle (paper §6.9). |
| `overhead.ex` | **Absolute governed latency** percentiles, against a no-I/O adapter floor (paper §6.11). Read them as the cost of the governed path, not as an overhead differential — see the note below. |
| `false_denials.ex` | The synthetic legitimate-action baseline (paper §6.12). |
| `holytrinity.run.ex` | The `mix holytrinity.run` task — the entry point for every campaign. |

## How a trial is scored

`Runner.score_context/5` is the whole method in one function, and it is worth reading before the
paper's §6.2:

1. Start the Oracle's telemetry collectors and take the authorization snapshot.
2. Run the Aggressor's `drive` thunk.
3. Stop collecting, take the closing snapshot.
4. Ask the Oracle to adjudicate — from telemetry and raw approval records only.
5. Read the system's `proof_state` **as a measured output**, for the confusion matrix.
6. Resolve the outcome and write the record.

Step 5 happens after step 4 by construction. The `proof_state` is never an input to the verdict.

## Reading the numbers these produce

Every campaign writes JSONL. The two campaign files ship in `../artifacts/`, and
`../scoring/verify.py` (or `../scoring/verify.exs`) recomputes every published campaign number from
them and exits non-zero on any disagreement.

**Every driver in the table above now ships its run's per-trial records**, in `../artifacts/`:
`ablation/tcb-F*.jsonl` and `ablation-study.jsonl` (`ablation_study.ex`), `baseline.jsonl` (the
no-control arm of the same module), `compound.jsonl`, `tcb-full-catalog.jsonl` (four full-catalog
probes, 292 records; the superseded per-family probe run is kept beside it as
`ablation/tcb-per-family-probes.jsonl`), `overhead.jsonl` (one record per iteration per arm),
`false-denials.jsonl`, `measurement-integrity.jsonl`, and `blind.jsonl`. Earlier revisions of this file listed most of these among the unauditable ones; that
is no longer true, and the list is corrected rather than quietly dropped.

Every published figure therefore recomputes from a committed artifact. What the artifacts do not
settle is **scope**: §9.1 removes each element singly and never in combination, F6/F7/F9 have no
runtime toggle and are never ablated, and the membrane and durable authority store have no ablation
row at all. `../scoring/VERIFY.md` lists the split it checks.

**Read each file's `_meta.caveat` before citing it.** `tcb-full-catalog.jsonl`'s states the scope
above; `false-denials.jsonl`'s notes that 75 rows are 3 configurations × 25 repeats; and
`overhead.jsonl`'s notes that the two arms are unpaired series on one machine.

## Two behaviours worth knowing about before you read the results

- **`detection_source` on a prevented trial is pre-registered, not measured.**
  `resolve_outcome(:prevented, ...)` writes the family's expected denial point, because attributing
  the denial to a specific policy would require reading the system's own tables. The `notes` field
  carries the actual drive result.
- **`harness_error` records exist** (`../scoring/trial.ex`) for trials that crash, so a failure is
  visible rather than silently dropped. `../scoring/report.ex` excludes them from the attack
  denominator — a trial that did not complete must never tighten a bound — and prints them in the
  outcome block with a total. No harness errors occurred in the published campaign (61 + 12 = 73).
- **`overhead.ex` measures absolute governed latency, not an overhead differential.** The comparison
  arm is degenerate: it times `MockStripe.execute/3`, a pure in-memory function whose measured p50 is
  **120 ns**, roughly 0.0006% of a governed path in the tens of milliseconds. Printed at microsecond
  resolution that floor truncates to a literal **0 µs at p50 and p95** (and 3 µs at p99), so the
  published "added latency" was the governed latency relabelled. The 120 ns is the point: the old
  `0 µs` was a timer-resolution floor, not a measurement, and `../artifacts/overhead.jsonl` now
  carries the real nanosecond distribution behind it. Higher resolution does not rescue the
  difference — and the subtraction was not paired in any case, being a difference of order
  statistics between two independent series rather than a distribution of per-call deltas. Read the
  percentiles as **the absolute cost of the governed path measured against a no-I/O adapter floor**,
  on one machine; the module's own `@moduledoc` states the same and no longer reports an `added` row.

## Reproduction

The commands in `../REPORT.md` and the paper's Appendix A drive the real membrane and therefore need
the system under test. They become runnable when it is released. What you can do **today**, with
nothing but this repository:

```bash
python3 ../scoring/verify.py ../artifacts/holytrinity-postfix-campaign.jsonl
elixir  ../scoring/verify.exs ../artifacts/holytrinity-postfix-campaign.jsonl
```
