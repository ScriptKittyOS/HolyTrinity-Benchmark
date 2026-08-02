# HolyTrinity Bench

**An adversarial security benchmark for agent authorization.** It measures one thing about
an authority control plane: the gap between an agent *proposing* a policy-violating action
and that action *producing an unauthorized external effect*. The agent is stipulated to be
compromised; the question is whether misbehavior converts to effect.

> Companion to the paper **"Authority-Bound Agentic Execution: Measuring Unauthorized Effect
> Under Adversarial Load"** (`PAPER.md`) by Ayla Croft, ScriptKittyOS.

## Headline result

Across **73 trials** (61 attack trials + 12 known-good controls) against the system under
test, the agent proposed a violating action in **57 of the 61 attack trials** (the other 4
are F8 posture-enforcement, which induces no proposal) and produced **0 unauthorized external
effects** (95% CI [0.0%, 5.9%]; see REPORT.md for the denominator breakdown). A zero is what a
reviewer distrusts, so it is not presented alone — the benchmark backs it with:

- an **ablation study** (disable each mechanism; its attacks convert — 0→10, 0→5, 0→5, 0→14);
- a **no-control baseline** (whole membrane off → **47 of 63** attacks convert);
- a **measured trusted-computing-base boundary** (only the kernel element's failure admits a
  provider-call effect; surface reducers admit gate-channel effects only — `spec/ABLATION.md`, paper §9.1);
- a **kept-and-fixed failure** (the one effect an earlier run leaked, closed and re-measured);
- **confidence intervals** on every rate and an **independent-oracle calibration** — the
  oracle agreed with the system's own proof state on all **41** provider-call trials with
  **0 overclaims** (the 6 load-bearing effect trials and the full decomposition are in REPORT.md).

## Reproducibility — partial, stated honestly

This repository open-sources **the benchmark and its results, not the system under test.**
The Trinity control plane is patent-pending and not yet public, so the campaign is **not
re-executable end-to-end here.** Two things are checkable now:

1. **Results are auditable from the released artifacts.** Every number and table follows
   mechanically from the committed JSONL (`artifacts/`). The `scoring/` modules recompute
   them without the system.
2. **The method is inspectable** — the frozen specification, the family taxonomy, the
   oracle/scoring design, and the released fixtures are all here.

Full end-to-end re-execution becomes possible when the system under test is released.

## Layout

```
PAPER.md            the paper (Markdown source; the compiled PDF is on arXiv)
REPORT.md           measured results (auditable from artifacts/)
spec/
  SPEC.md           the frozen methodology (definition of unauthorized effect, outcome model,
                    families, trial schema)
  ABLATION.md       the causal spine + the measured trusted-computing-base boundary
families/           the nine-boundary taxonomy + released family definitions (F4/F5/F6/F8/F9)
blind/              declarative, code-blind attack sets + protocol
fixtures/           released-vs-held disclosure split
artifacts/          committed result JSONL + the family table as data (the auditable results)
scoring/            the system-free scoring/reporting modules (recompute the numbers yourself)
CITATION.cff        citation metadata
MANIFEST.md         exactly what is and is not in this release, and why
docs/               PAPER-CLARIFICATIONS.md — corrections tracked for the paper's next revision
```

## What is not here

The **system under test** (the Trinity control plane), the **held fixtures** for the
content/runtime/skill families (F1–F3 — they would leak detection patterns), and the
system-coupled harness drivers. See `MANIFEST.md`.

## Cite

See `CITATION.cff`. License: CC BY 4.0 (`LICENSE`).
