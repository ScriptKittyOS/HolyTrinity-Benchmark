# Release manifest — what is and is not in this repository, and why

This is a **partial** open-source release: the benchmark and its results, **not** the system
under test. The Trinity control plane is patent-pending and not yet published.

## Included (public-safe)

| Path | What | Why it is safe |
|---|---|---|
| `papers/` | Both papers as LaTeX source: the architecture paper that specifies this evaluation, and the evaluation paper itself, with a README on how they relate | Counsel-cleared; written from the public-safe side of the disclosure boundary. Neither carries an archival identifier yet; no compiled PDFs are included. |
| `PAPER.md` | The evaluation paper as Markdown; the rest of the documentation links to it at this path | Same source as `papers/authority-bound-agentic-execution.tex`. |
| `REPORT.md`, `artifacts/` (incl. `artifacts/README.md`) | Measured results + JSONL + family table as data, with provenance and schema-departure notes | Redaction-safe by design: canonical hashes only, no raw payloads (SPEC §7). The results are the point of the release. |
| `spec/SPEC.md`, `spec/ABLATION.md`, `spec/PACKAGING-NOTES.md` | Frozen methodology, the causal spine, and the packaging/deviation notes that keep SPEC unedited | Method, not internals — the paper publishes all of it. |
| `families/` (README + F4/F5/F6/F8/F9) | Taxonomy + released family definitions | Released per the pre-committed disclosure split (`fixtures/README.md`). |
| `blind/` | Declarative, code-blind attack sets + protocol | No implementation internals — attacks expressed as approved-vs-executed envelopes. |
| `fixtures/README.md` | Released-vs-held split | The transparency statement itself. |
| `scoring/` (stats, calibration, report, trial, **verify.exs**, **verify.py**, VERIFY.md) | System-free scoring modules plus two dependency-free verifiers that recompute every published campaign number and exit non-zero on disagreement | Operate only on the JSONL; zero references to the system under test |
| `oracle/`, `aggressor/`, `harness/` | The independent oracle, the attack construction and variant catalogs, the chaos drivers, the fixtures, the runner, and the ablation / TCB / measurement-integrity / blind drivers | They reference the system under test and do **not** compile standalone, but they contain no detection signatures and no control-plane internals — they are the *observation* method, not the thing observed. Published so the independence claim can be checked rather than trusted. | Zero references to the system under test; they operate only on the JSONL. Let readers audit the numbers. |
| `CITATION.cff`, `LICENSE` | Metadata + CC BY 4.0 | — |
| `SHA256SUMS` | SHA-256 for every file in the release | Lets a reader confirm the artifact they hold is the one described here: `sha256sum -c SHA256SUMS`. The campaign's system-under-test commit is not resolvable in this repository, so this manifest is the integrity anchor. |

## Deliberately excluded

| Excluded | Why |
|---|---|
| **The system under test** (the Trinity control plane) | Patent-pending; not open-sourcing the system yet. This is the main reason reproducibility is partial. |
| **Held fixtures F1/F2/F3** and their red-team corpora (injection / runtime / skill-poisoning) | Would leak content-firewall, runtime-sentinel, and skill-audit **detection patterns** — a defensive-hardening concern, independent of IP. |
| **F1/F2/F3 family definitions**; **F7** (pending) and **F10/F11** (proposed v2) | Held or not-yet-finalized per the disclosure split. |
| **The held red-team corpora** — `injection_corpus.json`, `runtime_payloads.json`, `runtime_responses.json`, `skill_poisoning.json`, `skills.json` | Their *contents* are the detection surface for the content firewall, runtime sentinel, and skill auditor. `aggressor/variants.ex` loads them by filename, so the schema is visible and the payloads are not. Defensive hardening, not IP. |
| **Internal submission/planning material** | Not part of the artifact. |

## Consequences for reproducibility (matches the paper)

- **Auditable now:** the campaign numbers recompute from `artifacts/` via `scoring/` — no system
  needed (paper Appendix A, "Tier 1"). This covers the family table, the per-family and aggregate
  confidence intervals, the outcome breakdown, the confusion matrix, the calibration decomposition,
  and the effect-channel split. It does **not** cover the ablation and TCB tables, the no-control
  ceiling, overhead, false denials, F10, or the blind-set result: each comes from its own run and
  those runs' per-trial records are not in this release (`artifacts/README.md`).
- **Re-executable later:** the full campaign drives the real membrane and needs the system
  under test; it becomes runnable on the system's release ("Tier 2").

When the system is published, this manifest's "excluded" rows move to "included" and the
paper's reproducibility language upgrades from *partial* to *full*.
