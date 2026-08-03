# Release manifest — what is and is not in this repository, and why

This is a **partial** open-source release: the benchmark and its results, **not** the system
under test. The Trinity control plane is patent-pending and not yet published.

## Included (public-safe)

| Path | What | Why it is safe |
|---|---|---|
| `papers/` | The LaTeX sources for both papers, with a README on how they relate. This is the archival record, not the reading copy: the deposited Zenodo versions hold exactly these files, verified by hash, and they are the arXiv submission sources | Counsel-cleared; written from the public-safe side of the disclosure boundary. No compiled PDFs are included — this machine has no LaTeX toolchain, so page counts are unverified. |
| `PAPER.md`, `PAPER-ARCHITECTURE.md` | Both papers as readable Markdown — the evaluation paper and the architecture paper that specifies it. These are what a visitor reads; the rest of the documentation links to them at these paths | Rendered from the sources in `papers/` and held to them by `scoring/check_paper_sync.py`, which fails if a number appears in one and not the other. |
| `REPORT.md`, `artifacts/` (incl. `artifacts/README.md` and `artifacts/ablation/`) | Measured results + JSONL + family table as data, with provenance and schema-departure notes. Beyond the two campaign files, `artifacts/` holds per-trial records for the six single-mechanism ablations (`ablation/tcb-F*.jsonl` and `ablation-study.jsonl`), the no-control baseline, the compound ablation, the four full-catalog §9.1 probes plus the superseded per-family probe run kept beside them, the governed-latency iterations, the false-denial actions, the F10 controls, and the blind red team | Redaction-safe by design: canonical hashes only, no raw payloads (SPEC §7). The results are the point of the release. |
| `spec/SPEC.md`, `spec/ABLATION.md`, `spec/PACKAGING-NOTES.md` | Frozen methodology, the causal spine, and the packaging/deviation notes that keep SPEC unedited | Method, not internals — the paper publishes all of it. |
| `families/` (README + F4/F5/F6/F8/F9) | Taxonomy + released family definitions | Released per the pre-committed disclosure split (`fixtures/README.md`). |
| `blind/` | Declarative, code-blind attack sets + protocol | No implementation internals — attacks expressed as approved-vs-executed envelopes. |
| `fixtures/README.md` | Released-vs-held split | The transparency statement itself. |
| `scoring/` (stats, calibration, report, trial, **verify.exs**, **verify.py**, VERIFY.md) | System-free scoring modules plus two dependency-free verifiers that recompute every published campaign number and exit non-zero on disagreement | Operate only on the JSONL; zero references to the system under test |
| `oracle/`, `aggressor/`, `harness/` | The independent oracle, the attack construction and variant catalogs, the chaos drivers, the fixtures, the runner, and the ablation / TCB / measurement-integrity / blind drivers | They reference the system under test and do **not** compile standalone, but they contain no detection signatures and no control-plane internals — they are the *observation* method, not the thing observed. Published so the independence claim can be checked rather than trusted. |
| `docs/PAPER-CLARIFICATIONS.md` | The record of what an adversarial review of the papers surfaced, and when each item was applied | History, not an outstanding to-do list. Kept because a correction trail is more credible than a silently-corrected document. |
| `CHANGELOG.md` | What changed in each revision, and specifically which published numbers moved and which did not | The two figures that moved under the corrected Oracle are named there, with the cause. |
| `CITATION.cff`, `LICENSE` | Metadata + CC BY 4.0 | — |
| `SHA256SUMS` | SHA-256 for every file in the release | Lets a reader confirm the artifact they hold is the one described here: `sha256sum -c SHA256SUMS`. The campaign's system-under-test commit is not resolvable in this repository, so this manifest is the integrity anchor. |

## Deliberately excluded

| Excluded | Why |
|---|---|
| **The system under test** (the Trinity control plane) | Patent-pending; not open-sourcing the system yet. This is the main reason reproducibility is partial. |
| **Held fixtures F1/F2/F3** and their red-team corpora (injection / runtime / skill-poisoning) | Would leak content-firewall, runtime-sentinel, and skill-audit **detection patterns** — a defensive-hardening concern, independent of IP. |
| **F1/F2/F3 family definitions** and **F7** (pending) | Held or not-yet-finalized per the disclosure split. |
| **F11** (control-plane liveness, proposed v2) | Never built. It has no family definition, no fixtures, no harness and no trials; this row is the only place it is named. F10 is **not** in this category — see below. |
| **The held red-team corpora** — `injection_corpus.json`, `runtime_payloads.json`, `runtime_responses.json`, `skill_poisoning.json`, `skills.json` | Their *contents* are the detection surface for the content firewall, runtime sentinel, and skill auditor. `aggressor/variants.ex` loads them by filename, so the schema is visible and the payloads are not. Defensive hardening, not IP. |
| **Internal submission/planning material** | Not part of the artifact. |

**F10 is split, and the split matters.** F10's *probes* ship: `harness/measurement_integrity.ex`
is in this release and carries both variants (`oracle-observes-authorized-effect`,
`out-of-router-effect-invisible-to-belt`), wired in at `harness/runner.ex:32`. Its **result
artifact** now ships too, as `artifacts/measurement-integrity.jsonl` — two trials, which is a
demonstration and not a rate. What is still not here is F10's **family definition**, which is
proposed for v2, and the adversarial half of the family (forged or suppressed telemetry, non-Finch
transports), which is unbuilt. F11 (control-plane liveness) has none of the three: no definition,
no fixtures, no harness, no trials.

## Consequences for reproducibility (matches the paper)

- **Auditable now:** the campaign numbers recompute from `artifacts/` via `scoring/` — no system
  needed (paper Appendix A, "Tier 1"). This covers the family table, the per-family and aggregate
  confidence intervals, the outcome breakdown, the confusion matrix, the calibration decomposition,
  and the effect-channel split. **Every other published table now recomputes too**, from the
  per-trial records that ship alongside: `artifacts/ablation/` and `ablation-study.jsonl` (the §6.5
  ablation), `baseline.jsonl` (the no-control ceiling), `compound.jsonl` (the compound ablation),
  `tcb-full-catalog.jsonl` (the four full-catalog §9.1 probes, including `policies.spend`),
  `overhead.jsonl` (governed latency), `false-denials.jsonl`, `measurement-integrity.jsonl` (F10),
  and `blind.jsonl`. `artifacts/README.md` states the split file by file.
- **Auditable is not unbounded, and what is left is scope rather than arithmetic.** No artifact
  settles which runs exist: §9.1 removes each element **singly**, never in combination; F6, F7 and
  F9 have no runtime toggle and are never ablated; and the membrane and the durable authority store
  have no ablation row at all. Two shipped files additionally support narrower claims than their
  headline numbers suggest, and say so in their own `_meta.caveat`: `false-denials.jsonl`
  (3 configurations × 25 repeats, so 3 clusters, not 75) and `overhead.jsonl` (two unpaired series
  on one machine — no per-call delta, no percentage overhead, and percentiles that do not travel
  across machines).
- **Re-executable later:** the full campaign drives the real membrane and needs the system
  under test; it becomes runnable on the system's release ("Tier 2").

When the system is published, this manifest's "excluded" rows move to "included" and the
paper's reproducibility language upgrades from *partial* to *full*.
