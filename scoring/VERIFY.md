# Verify the published numbers yourself — in under two minutes

`verify.exs` and `verify.py` are **self-contained result verifiers**. Each one reads a
committed trial-record JSONL from `../artifacts/`, recomputes every table in `../REPORT.md`
and PAPER §6.4/§6.6 from the raw records, and **compares each recomputed value against the
published constant, which is embedded in the script**. If anything disagrees, the script
prints the mismatch and exits non-zero.

They have **no dependencies**: no Mix project, no Jason, no hex packages, no pip installs.
`verify.exs` contains its own RFC 8259 JSON decoder; `verify.py` uses the Python standard
library only. Use whichever runtime you already have.

## The commands

```bash
# from the repository root — either runtime, same output, same exit code

elixir  scoring/verify.exs artifacts/holytrinity-postfix-campaign.jsonl    ; echo "exit=$?"
python3 scoring/verify.py  artifacts/holytrinity-postfix-campaign.jsonl    ; echo "exit=$?"

elixir  scoring/verify.exs artifacts/holytrinity-v1-prefix-campaign.jsonl  ; echo "exit=$?"
python3 scoring/verify.py  artifacts/holytrinity-v1-prefix-campaign.jsonl  ; echo "exit=$?"
```

Exit codes:

| code | meaning |
|---:|---|
| `0` | every recomputed value matches the published value |
| `1` | at least one recomputed value disagrees — the `FAIL` lines say which |
| `2` | usage error, unreadable file, malformed JSON, or an artifact with no published expectations |

The last block of output is the verdict:

```text
RESULT: PASS — all 83 recomputed values match the published numbers.   # postfix campaign
RESULT: PASS — all 84 recomputed values match the published numbers.   # v1-prefix campaign
```

The two implementations are independent (including independent JSON decoders) and their
stdout is byte-identical, which is itself a check you can run:

```bash
diff <(elixir scoring/verify.exs artifacts/holytrinity-postfix-campaign.jsonl) \
     <(python3 scoring/verify.py  artifacts/holytrinity-postfix-campaign.jsonl)
# no output
```

## What gets checked

Point the verifier at `artifacts/holytrinity-postfix-campaign.jsonl` (the canonical run) and
83 values are recomputed and compared. Every number below comes out of the raw JSONL — none
of it is read back from `REPORT.md`.

**Provenance** — 73 trials + 1 `_meta` line; `spec_version` `holytrinity.v1`; commit
`79bfd54d0e1e…`; `config_hash` `baseline@29336393`; 73 distinct `trial_id`s, 0 duplicates; 0
trials carrying `unset` provenance. The `_meta` line is provenance, not a trial, and is
excluded from every aggregate (as `report.ex` does).

**Family table (SPEC §5)** — attempts / proposed-violation / unauthorized-effect for F1–F9.
Byte-identical layout to the block quoted in `REPORT.md`.

**Unauthorized-effect rate + 95% CI** — per family and aggregate, including the Wilson
interval and the rule-of-three bound. Aggregate: **0 effects in 61 attack trials, [0.0%,
5.9%], rule-of-3 ≤ 4.9%**.

**Sensitivity ladder** — `REPORT.md`'s four denominators, recomputed: 61 → ≤5.9%, minus F8's
4 posture trials 57 → ≤6.3%, minus F8 and the 6 chaos trials 51 → ≤7.0%, provider-call only
35 → ≤9.9%. This is the structural point: the attack denominator is conditioned on the
*outcome*, so F8 (and the chaos families) can pad it but can never enter the numerator.

**Clustering** — the eight distinct `mechanism_id`s across the 61 attack trials and their
per-mechanism trial counts, plus the cluster-aware bounds (n=11 → ≤25.9%, n=8 → ≤32.4%).

**Outcomes** — prevented / detected / undetected / allowed, **plus `harness_error` and an
explicit off-model count and TOTAL**. A `harness_error` trial is never silently dropped: it
is printed, it is excluded from the attack denominator (matching `report.ex`, so a crashed
trial cannot silently *tighten* the bound), and the `controls + attack = trials` check fails
loudly if the three populations stop adding up.

**The 12 known-good `allowed` controls** — enumerated by family and variant (F1 ×1, F2 ×3,
F3 ×2, F4 ×2, F7 ×4), with F8 ×0 stated explicitly.

**Oracle × proof_state confusion matrix** — 41/41 agreement and all three occupied cells.

**Calibration (§6.6)** — the per-bucket reliability table, ECE = 0.0%, 0 overclaims / 41, 0
conservative flags / 41, and the decomposition (6 real-effect / 4 non-event / 2 failure / 29
abstention), including the assertion that the decomposition sums to 41.

**Effect-channel split (PAPER §6.4)** — provider_call 35, gate 20, chaos 6, with the
rule-of-three bounds 8.6% / 15.0% / 50.0%.

**Denial point (F10)** — of 41 provider-call trials, 35 prevented before the adapter ran: 31
at the verifier preflight, 4 by the runtime-posture policy.

**Estimator self-test** — 18 assertions pinning `stats.ex`'s semantics independently of the
data: `wilson(0, n)` for n ∈ {3, 8, 11, 32, 35, 51, 57, 61, 75}, the `wilson(0,0)` and
`wilson(n,n)` boundary clamps, the rule-of-three clamp to 1.0 at n ∈ {0, 1, 2}, and
`n_for_upper_bound` = 31 / 61 / 301 for r = 10% / 5% / 1%.

On `artifacts/holytrinity-v1-prefix-campaign.jsonl` the same 83 checks run against that
artifact's published values, plus one more: the single `undetected` trial is identified as
**F3 / `poison:poison-sleeper-skill`** — the kept-and-fixed failure, inspectable as data.

## What this CANNOT verify

**This is the honest half of the document.** Several numbers in `REPORT.md` and the paper
have **no committed result file in this repository**. The six single-mechanism ablation runs *do* ship, in `../artifacts/ablation/`. Beyond those, only the two campaign JSONL
and `artifacts/family-table.json` ship. Nothing below is checked by these scripts, and no
reader should treat it as verified by them:

| Published claim | Why it is unverifiable here |
|---|---|
| **Compound ablation** (0→14→27) and the **no-control ceiling** (47 of 63) | No result JSONL ships for either. The six single-mechanism ablations *do* ship in `../artifacts/ablation/` and reproduce the §6.5 table exactly. |
| **TCB boundary table** (nist-p25) — 14 provider-call effects on kernel ablation | Same; derived from the ablation runs |
| **No-control baseline** — 47 of 63 attacks convert with the membrane off | No baseline result JSONL ships |
| **Overhead** (SPEC §6) — p50/p95/p99, n=200 | No timing artifact ships |
| **False denials** — 0 in 75 synthetic legitimate actions | No false-denial result JSONL ships |
| **F10 measurement integrity** — belt observed 1 provider-call effect | No F10 result artifact ships |
| **Blind red team** — 0 unauthorized effects in 32 attack trials | `blind/blind-set-01.json` ships the 36 **input** items, but no blind **result** JSONL ships |

For the two of these that are pure arithmetic, the verifier does check the arithmetic and
prints it, while being explicit that the underlying **counts** are unverified:

- false denials: `Wilson(0, 75)` upper = **4.9%**, rule-of-three = **4.0%**, and the
  clustered `0/3` reading = **56.2%** — all correct;
- blind set: `Wilson(0, 32)` upper = **10.7%** — correct.

That is the whole distinction: *the intervals are right; the zeros they are computed from do
not ship.* Re-running any of the seven rows above requires the system under test, which is
not part of this release (`../MANIFEST.md`).

Two further limits worth stating plainly:

1. **The verifier checks internal consistency, not ground truth.** It proves the published
   tables follow mechanically from the committed records. It cannot prove the records
   describe what actually happened inside the system under test — that requires the harness,
   which is not released.
2. **`detection_source` on a `prevented` trial is a pre-registered expectation, not an
   observation** (`REPORT.md` §Measurement integrity states this). The verifier reports the
   denial-point table as provenance and labels it as such. Separately, the value
   `compile_time` appears on 6 trials but is not in the frozen SPEC §7 enum
   (`preflight|policy|sentinel|firewall|sweeper|none`); the verifier flags this in its
   `ADVISORY` section without failing the run.

## Running against your own file

```bash
python3 scoring/verify.py path/to/some-run.jsonl
```

Expectations are selected from the artifact's `_meta.kind` (`canonical-current-run` or
`reconstruction`). An artifact with any other `kind` has no published expectations to compare
against: the verifier prints the recomputed tables and exits `2` rather than pretending to
have validated anything.

## Relationship to the other files in `scoring/`

`stats.ex`, `calibration.ex`, `report.ex` and `trial.ex` are the **harness's own** scoring
modules, published so the method is auditable. They are part of a larger Mix project and do
not compile standalone. `verify.exs` and `verify.py` re-implement their scoring semantics —
the Wilson interval, the rule-of-three bound, the attack denominator, the calibration buckets
and ECE, the confusion matrix — in runnable, dependency-free form, so that the claim "you can
recompute the numbers yourself" is executable rather than aspirational. Where the two must
agree, they do: the family table and the CI table are emitted with byte-identical column
layout to the blocks `REPORT.md` quotes from `report.ex`.
