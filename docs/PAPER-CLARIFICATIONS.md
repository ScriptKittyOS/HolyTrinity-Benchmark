# Paper clarifications and corrections

> **Status, 2 August 2026: superseded. Every correction below has been applied.**
>
> This file was written when `PAPER.md` was expected to be a published arXiv version that could
> not be edited in place. Neither paper has been announced and no arXiv identifier exists, so the
> corrections were applied directly to the paper instead of being deferred to a revision. The
> current sources are `papers/authority-bound-agentic-execution.tex` and its Markdown rendering
> at `PAPER.md`, and both carry the fixes described here plus a further round from a CoSAI
> whitepaper assessment. See `papers/README.md` for the full list.
>
> The file is kept as a record of what an adversarial review surfaced and when. Read it as
> history rather than as an outstanding to-do list.

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

**Correction:** report **governed-action latency** (p50 ≈ 17 ms) and drop the "added/overhead"
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
