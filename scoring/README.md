# Scoring & reporting modules

These modules are the **system-free** part of the HolyTrinity harness — they operate only on
the trial-record JSONL, not on the system under test, so they are safe to publish and they
let anyone **re-derive the paper's numbers from the released artifacts** (the paper's
"Tier 1" reproducibility, Appendix A).

**Start here: [`VERIFY.md`](VERIFY.md).** It gives you the two commands that recompute and
check every published number in under two minutes, and — just as importantly — the list of
published numbers that *cannot* be checked from the shipped artifacts.

| File | What it does |
|---|---|
| **`verify.exs`** | **Runnable, zero-dependency verifier (Elixir).** Recomputes every published table from a committed JSONL and exits non-zero on any disagreement. No Mix project, no Jason — it carries its own JSON decoder. |
| **`verify.py`** | **The same verifier in dependency-free Python 3** (standard library only), for reviewers without Elixir. Byte-identical output, identical exit codes. |
| `trial.ex` | The trial-record struct and its JSONL encoding (schema frozen in `../spec/SPEC.md` §7). |
| `stats.ex` | Wilson score intervals, the rule-of-three bound, and inverse-power `n` — the confidence intervals in §6.4. |
| `calibration.ex` | The Oracle × `proof_state` calibration: reliability, ECE, overclaim count, and the real-effect / non-event / abstention decomposition (§6.6). |
| `report.ex` | Renders the family table, the confidence-interval table, the outcome breakdown, the confusion matrix, and the calibration section from a JSONL file. |

## What is **not** here

The drivers that exercise the system under test — the independent Oracle's telemetry
capture, the Aggressor, the fixtures, the runner, and the ablation / measurement-integrity /
blind drivers — reference the Trinity control plane and are **not** part of this release
(the system is patent-pending and not yet open-sourced). They ship when the system does.
Consequently the four `.ex` files above are **not standalone-compilable**: they are members
of a Mix project and `report.ex` depends on Jason. They are published as the auditable
scoring/reporting *method*. To actually *run* the scoring, use `verify.exs` / `verify.py`,
which re-implement the same semantics with no dependencies at all.

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

`VERIFY.md` documents exactly what is and is not checkable this way — several published
figures (the ablation, the TCB table, the no-control baseline, overhead, false denials, F10
and the blind-set result) have no committed result file in this release and are **not**
verified by these scripts.
