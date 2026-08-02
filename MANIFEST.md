# Release manifest — what is and is not in this repository, and why

This is a **partial** open-source release: the benchmark and its results, **not** the system
under test. The Trinity control plane is patent-pending and not yet published.

## Included (public-safe)

| Path | What | Why it is safe |
|---|---|---|
| `PAPER.md` | The paper (Markdown source; compiled PDF on arXiv) | Counsel-cleared; written from the public-safe side of the disclosure boundary. The final version produced outside this repo; included verbatim. |
| `REPORT.md`, `artifacts/` | Measured results + JSONL + family table as data | Redaction-safe by design: canonical hashes only, no raw payloads (SPEC §7). The results are the point of the release. |
| `spec/SPEC.md`, `spec/ABLATION.md` | Frozen methodology + the causal spine + the measured TCB boundary | Method, not internals — the paper publishes all of it. |
| `families/` (README + F4/F5/F6/F8/F9) | Taxonomy + released family definitions | Released per the pre-committed disclosure split (`fixtures/README.md`). |
| `blind/` | Declarative, code-blind attack sets + protocol | No implementation internals — attacks expressed as approved-vs-executed envelopes. |
| `fixtures/README.md` | Released-vs-held split | The transparency statement itself. |
| `scoring/` (stats, calibration, report, trial) | System-free scoring/reporting modules | Zero references to the system under test; they operate only on the JSONL. Let readers audit the numbers. |
| `CITATION.cff`, `LICENSE` | Metadata + CC BY 4.0 | — |

## Deliberately excluded

| Excluded | Why |
|---|---|
| **The system under test** (the Trinity control plane) | Patent-pending; not open-sourcing the system yet. This is the main reason reproducibility is partial. |
| **Held fixtures F1/F2/F3** and their red-team corpora (injection / runtime / skill-poisoning) | Would leak content-firewall, runtime-sentinel, and skill-audit **detection patterns** — a defensive-hardening concern, independent of IP. |
| **F1/F2/F3 family definitions**; **F7** (pending) and **F10/F11** (proposed v2) | Held or not-yet-finalized per the disclosure split. |
| **System-coupled harness** (oracle, aggressor, fixtures, variants, runner, chaos, ablation/measurement-integrity/blind drivers) | These import the system under test; they ship when it does. Only the system-free scoring subset is released. |
| **Internal submission/planning material** | Not part of the artifact. |

## Consequences for reproducibility (matches the paper)

- **Auditable now:** the reported numbers recompute from `artifacts/` via `scoring/` — no
  system needed (paper Appendix A, "Tier 1").
- **Re-executable later:** the full campaign drives the real membrane and needs the system
  under test; it becomes runnable on the system's release ("Tier 2").

When the system is published, this manifest's "excluded" rows move to "included" and the
paper's reproducibility language upgrades from *partial* to *full*.
