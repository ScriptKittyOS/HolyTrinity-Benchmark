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
| `overhead.ex` | Governed vs bypassed latency percentiles (paper §6.11). |
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

Every campaign writes JSONL. Two of those files ship, in `../artifacts/`, and
`../scoring/verify.py` (or `verify.exs`) recomputes every published campaign number from them and
exits non-zero on any disagreement.

**The other runs' per-trial records do not ship.** The ablation and trusted-computing-base tables,
the no-control ceiling, the overhead percentiles, the false-denial rate, the F10 controls, and the
blind-set result are each produced by a separate run whose JSONL is not in this release. Those
figures are reported in `../REPORT.md` and are **not** independently auditable from this repository.
`../scoring/VERIFY.md` lists the split precisely.

## Two behaviours worth knowing about before you read the results

- **`detection_source` on a prevented trial is pre-registered, not measured.**
  `resolve_outcome(:prevented, ...)` writes the family's expected denial point, because attributing
  the denial to a specific policy would require reading the system's own tables. The `notes` field
  carries the actual drive result.
- **`harness_error` records exist** (`../scoring/trial.ex`) for trials that crash, so a failure is
  visible rather than silently dropped. `../scoring/report.ex` excludes them from the attack
  denominator — a trial that did not complete must never tighten a bound — and prints them in the
  outcome block with a total. No harness errors occurred in the published campaign (61 + 12 = 73).

## Reproduction

The commands in `../REPORT.md` and the paper's Appendix A drive the real membrane and therefore need
the system under test. They become runnable when it is released. What you can do **today**, with
nothing but this repository:

```bash
python3 ../scoring/verify.py ../artifacts/holytrinity-postfix-campaign.jsonl
elixir  ../scoring/verify.exs ../artifacts/holytrinity-postfix-campaign.jsonl
```
