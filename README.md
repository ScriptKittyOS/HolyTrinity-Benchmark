# HolyTrinity Bench

**An adversarial security benchmark for agent authorization.** It measures one thing about
an authority control plane: the gap between an agent *proposing* a policy-violating action
and that action *producing an unauthorized external effect*. The agent is stipulated to be
compromised; the question is whether misbehavior converts to effect.

> Companion to the paper **"Authority-Bound Agentic Execution: Measuring Unauthorized Effect
> Under Adversarial Load"** (`PAPER.md`) by Ayla Croft, ScriptKittyOS.

## Headline result

Across **73 trials** (61 attack trials + 12 known-good controls) against the system under
test, a violating action was constructed and driven in **57 of the 61 attack trials** and produced
**0 unauthorized external effects** (per-trial 95% CI [0.0%, 5.9%]; cluster-aware ≤32.4% over the
8 distinct mechanisms the set exercises — see `REPORT.md`). A zero is what a reviewer distrusts, so it is not presented
alone — the benchmark backs it with:

- an **ablation study** (disable each mechanism; its attacks convert — 0→10, 0→5, 0→5, 0→14);
- a **no-control baseline** (whole membrane off → **47 of 63** attacks convert);
- a **measured trusted-computing-base boundary** (only the kernel element's failure admits a
  provider-call effect; surface reducers admit gate-channel effects only — `spec/ABLATION.md`, paper §9.1);
- a **kept-and-fixed failure** (the one effect an earlier run leaked, closed and re-measured);
- **confidence intervals** on every rate and an **independent-oracle calibration** (0 overclaims
  in 41 provider-call trials; on all 6 trials where a real effect occurred the system's proof state
  matched the independent verdict — `REPORT.md` gives the decomposition, which is the honest form
  of the claim).

## Reproducibility — partial, stated honestly

This repository open-sources **the benchmark and its results, not the system under test.**
The Trinity control plane is patent-pending and not yet public, so the campaign is **not
re-executable end-to-end here.** Two things are checkable now:

1. **Results are auditable from the released artifacts.** Every number and table follows
   mechanically from the committed JSONL (`artifacts/`). The `scoring/` modules recompute
   them without the system.
2. **The method is inspectable** — the frozen specification, the family taxonomy, the released
   family definitions, the declarative blind-attack sets, the scoring modules, and **the full
   harness: the independent oracle, the aggressor, the runner, and the ablation / TCB /
   measurement-integrity / blind drivers**. These reference the system under test, so they do not
   compile standalone; they are published so the adjudication method can be checked line by line
   rather than taken on trust.

Full end-to-end re-execution becomes possible when the system under test is released.

## Layout

```
papers/             both papers as LaTeX source: the architecture paper that specifies this
                    evaluation, and the evaluation paper itself (see papers/README.md)
PAPER.md            the evaluation paper as Markdown (the rest of the docs link to it here)
REPORT.md           measured results (auditable from artifacts/)
oracle/             the independent adjudicator — the component the result depends on
aggressor/          attack construction, the variant catalogs, the chaos drivers, fixtures
harness/            the runner + the ablation / TCB / measurement-integrity / blind drivers
spec/
  SPEC.md           the frozen methodology (definition of unauthorized effect, outcome model,
                    families, trial schema)
  ABLATION.md       the causal spine (the TCB boundary table is in REPORT.md and paper §9.1)
  PACKAGING-NOTES.md  how to read the frozen SPEC in this layout + the deviation table
families/           the nine-boundary taxonomy + released family definitions (F4/F5/F6/F8/F9)
blind/              declarative, code-blind attack sets + protocol
fixtures/           released-vs-held disclosure split
artifacts/          committed result JSONL + the family table as data, with README.md
                    recording provenance, schema departures, and what they can/cannot verify
scoring/            the system-free scoring modules, plus verify.exs and verify.py —
                    dependency-free verifiers that recompute every published campaign number
                    and exit non-zero on disagreement (see scoring/VERIFY.md)
LICENSE             CC BY 4.0
CITATION.cff        citation metadata
MANIFEST.md         exactly what is and is not in this release, and why
```

## What is not here

The **system under test** (the Trinity control plane) and the **held red-team corpora** for the
content/runtime/skill families (F1–F3) — their contents are the detection surface those mechanisms
are tuned against, so releasing them would be a defensive-hardening problem rather than an IP one.
The harness that drives the benchmark **is** released; it simply cannot compile without the system.
See `MANIFEST.md`.

## Cite

See `CITATION.cff`. License: CC BY 4.0 (`LICENSE`).
