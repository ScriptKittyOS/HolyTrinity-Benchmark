# Scoring & reporting modules

These modules are the **system-free** part of the HolyTrinity harness — they operate only on
the trial-record JSONL, not on the system under test, so they are safe to publish and they
let anyone **re-derive the paper's numbers from the released artifacts** (the paper's
"Tier 1" reproducibility, Appendix A).

**Start here: [`VERIFY.md`](VERIFY.md).** It gives you the commands that recompute and check
every published number in under two minutes, states what each per-study artifact lets you
recompute, and — just as importantly — keeps the list of published claims that *cannot* be
checked this way and why.

| File | What it does |
|---|---|
| **`verify.exs`** | **Runnable, zero-dependency verifier (Elixir).** Recomputes every published table from a committed JSONL — a campaign artifact or any of the ten per-study artifacts — and exits non-zero on any disagreement. No Mix project, no Jason: it carries its own JSON decoder. |
| **`verify.py`** | **The same verifier in dependency-free Python 3** (standard library only), for reviewers without Elixir. Byte-identical output, identical exit codes. |
| `trial.ex` | The trial-record struct and its JSONL encoding (schema frozen in `../spec/SPEC.md` §7). |
| `stats.ex` | Wilson score intervals, the rule-of-three bound, and inverse-power `n` — the confidence intervals in §6.4. |
| `calibration.ex` | The Oracle × `proof_state` calibration: reliability, ECE, overclaim count, and the real-effect / non-event / abstention decomposition (§6.6). |
| `report.ex` | Renders the family table, the confidence-interval table, the outcome breakdown, the confusion matrix, and the calibration section from a JSONL file. |
| `check_paper_sync.py` | Holds each paper's Markdown rendering to its LaTeX source: numeric claims compared as multisets and required to match exactly, prose divergence allowed only against named rendering-artifact classes. Dependency-free; `--self-test` proves it fails on injected drift. Exit `0` in sync, `1` drift, `2` cannot run. See `VERIFY.md`. |
| **`test_denominator.py`** | **Regression test for the attack denominator** (issue #1). Feeds malformed outcomes through all four scorers — `verify.py`, `verify.exs`, `report.ex` and the blind-set driver in `../harness/holytrinity.run.ex` — and asserts they stay out of the denominator and stay visible. `python3 scoring/test_denominator.py`, exit 0 = pass. |

## What is here but does **not** run, and what is genuinely absent

An earlier version of this section said the Oracle, the Aggressor, the fixtures, the runner
and the ablation / measurement-integrity / blind drivers "are not part of this release."
**That was wrong — they all ship.** Read them at:

| Path | What it is |
|---|---|
| `../oracle/oracle.ex` | The independent adjudicator: telemetry capture, the raw-approval snapshot, and `adjudicate/4`. This is the file the paper's independence claim rests on, and it is here to be read. |
| `../aggressor/` | `aggressor.ex`, `variants.ex`, `chaos.ex`, `fixtures.ex` — the attack catalogue and the F6/F9 chaos harness. |
| `../harness/` | `runner.ex` (the only producer of trial records), `holytrinity.run.ex` (the Mix task), plus the `ablation_study.ex`, `measurement_integrity.ex`, `blind_set.ex`, `overhead.ex` and `false_denials.ex` drivers. |

What is genuinely absent is the **system under test** — the Trinity control plane itself
(patent-pending, not yet open-sourced). Every `.ex` file listed above references it, so none
of them compiles standalone: they are members of a Mix project, `report.ex` additionally
depends on Jason, and the drivers additionally need a real Postgres and the Ecto SQL
sandbox. They are published **to be read**, so the method is auditable, not to be executed.

To actually *run* the scoring, use `verify.exs` / `verify.py`, which re-implement the same
semantics with no dependencies at all, and `test_denominator.py`, which executes
`report.ex`'s scoring functions directly over a synthetic fixture.

Each of those drivers now writes a **per-study result artifact** — a `_meta` provenance line
followed by one record per unit of work — so the figure it publishes can be recomputed rather
than only read. The verifiers carry published expectations for all of them; see the per-study
table in [`VERIFY.md`](VERIFY.md) for what each artifact lets you check. Whether a given
study's file is present in *your* copy of the tree is a separate question, and the verifier
says so rather than assuming: an artifact it has no expectations for exits `2`.

## Verifying the results from the artifacts

```bash
elixir  scoring/verify.exs artifacts/holytrinity-postfix-campaign.jsonl   # exit 0 = all match
python3 scoring/verify.py  artifacts/holytrinity-postfix-campaign.jsonl   # same output
```

Each script recomputes the family table, the confidence-interval table, the sensitivity
ladder, the clustering bounds, the outcome breakdown, the control mapping, the confusion
matrix, the calibration section and the effect-channel split from the raw records, then
compares each value against the published constant embedded in the script. Meta lines
(`{"_meta": …}`) at the top of each artifact are provenance, not trials, and are excluded
from every aggregate.

Each script also recomputes the §6.5 ablation table and the §9.1 TCB boundary table from
`../artifacts/ablation/`, and derives the **governed** arm of the no-control table from the
campaign artifact.

The same two scripts also check a **per-study** artifact — hand one to either verifier and it
recomputes that study's published figure from that study's own records, by the rule the
artifact's `_meta.note` states. Ten study kinds are recognised:

```bash
# the six shipped single-mechanism ablations, each checkable on its own
for f in artifacts/ablation/tcb-*.jsonl; do python3 scoring/verify.py "$f"; done

python3 scoring/verify.py results/<run-id>.jsonl   # any per-study artifact a run emitted
```

| `_meta.kind` | Figure recomputed |
|---|---|
| `ablation-study` | the §6.5 matrix, both arms of every mechanism |
| `tcb-boundary` | §9.1 per-family probes — unauthorized effects by `effect_channel` |
| `tcb-full-catalog` | §9.1 in falsifiable form — 0 external effects across 140 live provider-call attack trials |
| `no-control-baseline` | both arms, including the **ungoverned** ceiling (63 / 63 / 51) |
| `compound-ablation-f4` | the 0 → 14 → 27 progression |
| `overhead-latency` | the percentile recomputation **method** (see the caveat below) |
| `false-denials` | 0 in 75, both intervals, and the clustered `0/3` reading |
| `measurement-integrity-f10` | both F10 validity controls and their effect-log counts |
| `blind-red-team` | 0 in 32, both intervals, and the 4-shape clustered reading |
| `ablation-single-mechanism` | one `../artifacts/ablation/tcb-F*.jsonl` on its own |

`VERIFY.md` documents exactly what is and is not checkable this way. The sharpest remaining
gap is deliberate: the **absolute** overhead percentiles are wall-clock latencies of one
machine, so a re-run will legitimately differ. The verifiers score the recomputation method
and print the published triple beside the recomputed one without scoring it — a check that
cannot fail on an honest re-run, and does not pretend to be one that could. The published
figures are now recomputed from the shipped `artifacts/overhead.jsonl` — 19100 / 53475 / 76336 µs
— so for that one artifact, identified by a sha256 pin, the comparison is a scored check rather
than a printed note. Point the verifier at any other run and the constants go back to being
printed and not scored, which is the correct behaviour: a different machine will measure
different numbers.
