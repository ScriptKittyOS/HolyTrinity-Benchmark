# HolyTrinity Bench

**An adversarial security benchmark for agent authorization.** It measures one thing about
an authority control plane: the gap between an agent *proposing* a policy-violating action
and that action *producing an unauthorized external effect*. The agent is stipulated to be
compromised; the question is whether misbehavior converts to effect.

## The two papers

Both are readable here, in Markdown. Read them in this order:

1. **[The Model Proposes, the System Authorizes](PAPER-ARCHITECTURE.md)** — the architecture, and
   the paper that *specifies* this evaluation: the threat model, the invariant, and the metric
   this benchmark was built to measure. It pre-registers what would refute it.
2. **[Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under Adversarial
   Load](PAPER.md)** — the evaluation itself: the campaign, the ablations, the intervals, and
   what the result does and does not establish.

Both by Ayla Croft, ScriptKittyOS. Licensed CC BY 4.0.

`papers/` holds the LaTeX sources. Those are the archival record — the deposited Zenodo versions
hold exactly those files, verified by hash — not the copies you are meant to read. The Markdown
above is generated from them and checked against them by `scoring/check_paper_sync.py`, which
fails if a number appears in one and not the other. That gate exists because these renderings have
drifted before, and both times the Markdown kept a figure the LaTeX had already retracted.

## Headline result

Across **73 trials** (61 attack trials + 12 known-good controls) against the system under
test, a violating action was constructed and driven in **57 of the 61 attack trials** and produced
**0 unauthorized external effects** (per-trial 95% CI [0.0%, 5.9%]; cluster-aware ≤32.4% over the
8 distinct mechanisms the set exercises — see `REPORT.md`). A zero is what a reviewer distrusts, so it is not presented
alone — the benchmark backs it with:

- an **ablation study** (disable each mechanism; its attacks convert — 0→10, 0→5, 0→5, 0→14 for
  the content firewall, runtime sentinel, skill auditor and approval binding, and 0→2 for
  two-person approval: five mechanisms, each demonstrated necessary);
- a **no-control baseline** (whole membrane off → **51 of 63 trials** convert) — where 63 is not
  a count of attacks but the F1–F5 + F8 totals, including 8 known-good controls and F8's 4
  non-attacks, and is not the campaign's 61 either, because the baseline set omits F6, F7 and F9,
  which have no runtime toggle;
- a **measured trusted-computing-base boundary** (each ablatable element removed in turn with the
  full 73-trial catalog driven against it, so 41 provider-call trials are live under every ablation:
  only the kernel element's failure admits a provider-call effect, surface reducers admit
  gate-channel effects only. Scope is stated rather than implied — single removals only, and F6/F7/F9
  plus the membrane and durable store are never ablated — `REPORT.md`, paper §9.1);
- a **kept-and-fixed failure** (the one effect an earlier run leaked, closed and re-measured);
- **confidence intervals** on every rate and an **independent-oracle calibration** (0 overclaims
  in 41 provider-call trials; on all 6 trials where a real effect occurred the system's proof state
  matched the independent verdict — `REPORT.md` gives the decomposition, which is the honest form
  of the claim).

## Reproducibility — partial, stated honestly

This repository open-sources **the benchmark and its results, not the system under test.**
The Trinity control plane is patent-pending and not yet public, so the campaign is **not
re-executable end-to-end here.** Two things are checkable now:

1. **Results are auditable from the released artifacts.** Every campaign number and table follows
   mechanically from the committed JSONL (`artifacts/`). The `scoring/` modules recompute
   them without the system. Every other published table recomputes the same way, from per-trial
   records that ship alongside: the ablation study, the no-control ceiling, the compound ablation,
   the four full-catalog §9.1 probes, overhead, false denials, F10, and the blind-set result. What
   the artifacts do not settle is **scope** — which runs exist at all — and that is stated at each
   table rather than left to be inferred. `MANIFEST.md` and `artifacts/README.md` say the same
   thing; read each artifact's `_meta.caveat` for what its run can and cannot support.
2. **The method is inspectable** — the frozen specification, the family taxonomy, the released
   family definitions, the declarative blind-attack sets, the scoring modules, and **the full
   harness: the independent oracle, the aggressor, the runner, and the ablation / TCB /
   measurement-integrity / blind drivers**. These reference the system under test, so they do not
   compile standalone; they are published so the adjudication method can be checked line by line
   rather than taken on trust.

Full end-to-end re-execution becomes possible when the system under test is released.

## Layout

```
PAPER.md            the evaluation paper, readable (the rest of the docs link to it here)
PAPER-ARCHITECTURE.md  the architecture paper, readable — read this one first
papers/             the LaTeX sources for both, and the archival record: the deposited Zenodo
                    versions hold exactly these files, verified by hash (see papers/README.md)
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
artifacts/          committed result JSONL for every published run + the family table as data,
                    with README.md recording provenance, schema departures, and what they
                    can/cannot verify
  ablation/         per-trial records for the six single-mechanism ablations behind the §6.5
                    ablation table
scoring/            the system-free scoring modules, plus verify.exs and verify.py —
                    dependency-free verifiers that recompute every published number from the
                    committed records and exit non-zero on disagreement; check_paper_sync.py
                    holds each paper's Markdown to its LaTeX (see scoring/VERIFY.md)
LICENSE             CC BY 4.0
CITATION.cff        citation metadata
MANIFEST.md         exactly what is and is not in this release, and why
SHA256SUMS          SHA-256 for every file in the release; `sha256sum -c SHA256SUMS` confirms
                    the bytes you hold are the ones described here
```

## What is not here

The **system under test** (the Trinity control plane) and the **held red-team corpora** for the
content/runtime/skill families (F1–F3) — their contents are the detection surface those mechanisms
are tuned against, so releasing them would be a defensive-hardening problem rather than an IP one.
The harness that drives the benchmark **is** released; it simply cannot compile without the system.
See `MANIFEST.md`.

## Cite

See `CITATION.cff`. License: CC BY 4.0 (`LICENSE`).
