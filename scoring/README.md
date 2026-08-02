# Scoring & reporting modules

These four Elixir modules are the **system-free** part of the HolyTrinity harness — they
operate only on the trial-record JSONL, not on the system under test, so they are safe to
publish and they let anyone **re-derive the paper's numbers from the released artifacts**
(the paper's "Tier 1" reproducibility, Appendix A).

| Module | What it does |
|---|---|
| `trial.ex` | The trial-record struct and its JSONL encoding (schema frozen in `../spec/SPEC.md` §7). |
| `stats.ex` | Wilson score intervals, the rule-of-three bound, and inverse-power `n` — the confidence intervals in §6.4. |
| `calibration.ex` | The Oracle × `proof_state` calibration: reliability, ECE, overclaim count, and the real-effect / non-event / abstention decomposition (§6.6). |
| `report.ex` | Renders the family table, the confidence-interval table, the outcome breakdown, the confusion matrix, and the calibration section from a JSONL file. |

## What is **not** here

The drivers that exercise the system under test — the independent Oracle's telemetry
capture, the Aggressor, the fixtures, the runner, and the ablation / measurement-integrity /
blind drivers — reference the Trinity control plane and are **not** part of this release
(the system is patent-pending and not yet open-sourced). They ship when the system does.
Consequently these four files do not compile standalone; they are published as the
auditable scoring/reporting method, and to let you check the released JSONL yourself.

## Verifying the results from the artifacts

`report.ex` reads a JSONL file and prints the tables. `calibration.ex` and `stats.ex` are
pure functions over the decoded records. Point them at `../artifacts/holytrinity-postfix-campaign.jsonl`
(or the v1-prefix reconstruction) to reproduce the numbers in `../REPORT.md` and the paper —
no system under test required. Meta lines (`{"_meta": …}`) at the top of each artifact are
provenance, not trials, and `report.ex` skips them.
