# Paper clarifications and corrections

> **Status, 2 August 2026 (second revision): all seven items below are now applied.**
>
> An earlier version of this banner claimed the same thing prematurely. At the time it was
> written, items 1, 2, 3, 4 and 7 had been applied to `REPORT.md` and `README.md` only — the
> papers still carried the original wording, so the claim "every correction below has been
> applied" was true of the repository documents and false of the papers. It is recorded here
> rather than quietly amended, because a status banner that overstates its own completeness is
> the same class of defect as the ones this file catalogues.
>
> As of this revision the corrections are in `papers/authority-bound-agentic-execution.tex`,
> `papers/the-model-proposes-the-system-authorizes.tex` and `PAPER.md` as well. Two items were
> also strengthened beyond what is described below:
>
> * **Item 1** now publishes the full sensitivity ladder rather than the single stricter
>   denominator this file proposed — 61 attempts (≤5.9%), 51 that could produce an unauthorized
>   effect at the provider boundary (≤7.0%), and 31 external-effect-capable (≤9.7% one-sided),
>   plus the cluster-aware bound over mechanisms (≤32.4%). Note the correction in item 1's own
>   text: F7 is **not** a second instance of the F8 problem. All four F7 trials are `allowed`
>   and were already excluded, so F7 contributes nothing to the 61.
> * **Item 3** is resolved by relabelling rather than by re-measurement. A corrected bypassed
>   path was not built; empirically it would not change the figure, because the mock adapter's
>   measured p50 is 120 ns, roughly 0.0006% of the governed path even at nanosecond resolution.
>
> This file predates the ablation re-score. It does not cover the F5 ablation moving from
> `0 → 0` to `0 → 2`, or the no-control ceiling moving from 47 to 51 of 63 — see the `CHANGELOG`
> and `spec/PACKAGING-NOTES.md` for those. Nor does it cover the defects found in the review
> round that followed it: the misattributed pre-adapter denial split, the F4 oracle circularity,
> or the trial-selection limit on the §9.1 table.
>
> **Four things changed after this file was written, and item 3's numbers moved with them
> (v1.1).** (a) Nine runs that previously shipped no per-trial records now ship them, so every
> published figure recomputes from a committed artifact. (b) The trial-selection limit this file's
> closing note flagged on the §9.1 table **is closed**: each element is now ablated with the full
> 73-trial catalog driven against it, 41 provider-call trials live under every ablation. The claim
> was first supported by the wrong artifact — the per-family probe run, in which no provider-call
> trial was live — and review caught that before release; the full-catalog run is what ships, and
> `CHANGELOG.md` records the provenance. (c) The
> governed-latency percentiles moved to **19100 / 53475 / 76336 µs (~19 ms at p50)**, and the
> bypassed arm's real p50 is **120 ns**, because a per-iteration artifact now ships and the
> published figures are recomputed from it. Item 3's `p50 ≈ 17 ms` below is therefore the
> superseded figure; the correction it recommends — report governed latency, drop the
> added/overhead framing — is unchanged and still applied. (d) The two converted F5 ablation
> trials now score `detected` / `failed` / `invariant_check` rather than `undetected` / `missing` /
> `none`, at the same count of 2.
>
> Read it as history: what one adversarial review surfaced, and when.

Every published *number* reproduces exactly from the committed `artifacts/*.jsonl` (verified);
these are matters of framing, labeling, and one methodological baseline — not arithmetic
errors.

## 1. The F8 posture family and the aggregate denominator (most substantive)

The abstract/§6 headline is **0 unauthorized effects in 61 attack trials, 95% CI ≤ ~6% (5.9%)**.
The 61 is **57 induced-violation trials (F1–F6, F9) + 4 F8 posture-enforcement trials**. Every
F8 trial drives a *validly-approved* write, so its oracle verdict is always `authorized` — F8
is structurally unable to produce an *unauthorized* effect. Including it in the denominator
slightly tightens the interval, and it sits inconsistently next to F7 (whose 4 replays are
excluded as `allowed` controls).

**Correction for the revision:** report the stricter denominator alongside the broader one —
**0 / 57 → 95% CI [0.0%, 6.3%]** for trials that *could* yield an unauthorized effect, and 0/61
(≤5.9%) as the all-attack-trials figure — and state the F7/F8 asymmetry explicitly. `REPORT.md`
now does this. The headline claim ("≤ ~6%") is unchanged in substance; 6.3% vs 5.9% does not
alter any conclusion.

## 2. "ECE" labeling

The paper reports "ECE 0.0%." The metric computed (`scoring/calibration.ex`) is a
**proof-state-bucket-weighted calibration error** — Σ (n_bucket/N)·|implied − observed| over
the `proof_state` values — not a standard binned-probability ECE. It is a defensible adaptation
and the code already documents that it "rests heavily on abstentions/non-events," but the label
"ECE" and the bare README headline overstated it.

**Correction:** state it as "the oracle agreed with the system's proof state on all 41
provider-call trials, 0 overclaims, on 6 load-bearing effect trials," and describe the
calibration number as bucket-weighted (not standard ECE). `README.md` and `REPORT.md` are
updated; the paper should adopt the same wording.

## 3. Overhead baseline

The overhead table reports `bypassed = 0/0/0 µs`, so "added latency" equals "governed latency."
The bypassed path is a near-no-op and is not a comparable baseline.

**Correction:** report **governed-action latency** (p50 ≈ 17 ms *as measured at the time; ≈ 19 ms
under the run whose artifact now ships — see the banner*) and drop the "added/overhead"
differential framing until a bypassed path doing the identical mock round-trip minus only the
membrane is measured. `REPORT.md` is updated.

## 4. One-sided vs two-sided intervals

The channel-split and per-family tables mix two-sided Wilson intervals with one-sided
rule-of-three (`3/n`) upper bounds under a shared "95% CI" heading.

**Correction:** label the rule-of-three columns explicitly as **one-sided 95% upper bounds**.
`REPORT.md` is updated.

## 5. Framing of "proposed a violating action in 57"

Better stated as **"in 57 of the 61 attack trials"** (the other 4 are F8, which induces no
proposal; the 12 controls are excluded). `README.md` is updated.

## 6. Internal reference left in the public paper

The front matter reads "written from the public-safe side of the disclosure boundary (private
brief §25)." **Correction:** drop the "(a private-document reference)" parenthetical — it points at a
non-public document.

## 7. False-denial confidence interval

The 0/75 false-denial figure should carry its interval: **95% CI [0.0%, 4.9%]** (Wilson).
`REPORT.md` is updated.

---

*Verified clean and needing no change:* every family-table figure, the aggregate/CI arithmetic,
the ablation and no-control numbers, the TCB channel split, `config_hash`/`commit_sha` present
on all 73 trials, the two campaign files differing in exactly the one F3 sleeper trial, and the
blind set (32 distinct attacks + 4 controls, no gaps or duplicates).
