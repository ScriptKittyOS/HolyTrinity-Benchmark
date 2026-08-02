# Papers

Two papers describe this work. They are siblings and should be read together: the first states
the architecture and specifies the evaluation, the second runs it.

| File | Paper | Dated |
|---|---|---|
| `the-model-proposes-the-system-authorizes.tex` | **The Model Proposes, the System Authorizes: An Authority Control Plane for AI Agents on the BEAM** | 29 July 2026 |
| `authority-bound-agentic-execution.tex` | **Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under Adversarial Load** | 2 August 2026 |

Both are LaTeX sources and both compile with `pdflatex` alone: no `.bib`, no figures, no external
inputs. `../PAPER.md` is a Markdown rendering of the second paper, kept at the repository root
because the rest of the documentation links to it.

## Why the pair matters, and how to check it

The architecture paper states the threat model, the security invariant, and the nine mechanisms.
Its evaluation section, written before any harness existed, fixes the evaluation the second paper
reports: the primary metric (unauthorized-effect rate), three secondary metrics (evidence
completeness, benign-task false-denial rate, overhead against an ungoverned baseline), a
twelve-item attack-class list, and the strong test, *"replace the agent entirely with an
adversarial oracle that emits worst-case output at every step,"* together with its falsification
criterion, *"a single unauthorized effect under the adversarial oracle refutes invariant I."*
Of that test it says: *"I state plainly that I have not run this test."*

The second paper runs it. That ordering is the reason the evaluation's stipulated adversary is a
pre-registered method rather than a convenient shortcut, so the claim is worth checking rather
than taking on trust. Two things make it checkable, and a third bounds it:

- **This file.** The architecture paper is here, dated, and diffable against any later version.
- **The frozen specification.** `../spec/SPEC.md` fixes the definition of an unauthorized effect,
  the scoring rules, and the trial schema. It has exactly one commit in its history in the private
  development tree, timestamped `2026-08-01T22:17:36Z`, and the campaign's earliest trial is
  `2026-08-02T04:04:04Z`, five hours and forty-seven minutes later. It was never edited, before or
  after the run.
- **The bound.** The architecture paper has a Zenodo DOI, `10.5281/zenodo.21754763`, and that
  deposit is timestamped `2026-08-02T05:34:27Z`, roughly ninety minutes *after* the campaign's
  earliest trial. It makes the companion citable and fixes its text at a third-party host. It does
  nothing to corroborate the 29 July date, which remains the manuscript's own assertion. The
  specification's commit history is the harder evidence, and it is the one to lean on.

## Status

Both papers were submitted to arXiv and neither is announced, so neither has an arXiv identifier.

The architecture paper is deposited on Zenodo as a preprint under CC-BY-4.0: version DOI
`10.5281/zenodo.21754763`, concept DOI `10.5281/zenodo.21754762`, which always resolves to the
newest version. Cite the concept DOI unless you mean that specific version. The evaluation paper
has no DOI yet.

One caveat if you fetch the deposit: its file is the pre-correction draft, 74,120 bytes against the
79,021-byte source in this directory. The corrections listed below are in the copy here and not yet
in the copy there. Diff them before quoting either.

Compiled PDFs are not in this directory; build them with `pdflatex` if you want them.

## Corrections applied to both

Both sources here incorporate an adversarial audit and a CoSAI whitepaper assessment run against
them. The changes a reader of an earlier draft would notice:

The architecture paper corrects its test count to a figure that verifies (1,286 test blocks across
287 test files), replaces "compile-time invariants" with "CI-enforced structural invariants"
throughout, because the guard is an ExUnit test rather than a compiler hook and `mix compile`
succeeds with a violating caller present. It names the SRF **IaaS** operating model rather than an
invented "customer-built" label, lists seven proof states rather than six, describes agent reset as
a supervised shutdown with a bounded grace period rather than a kill, discloses the Jido dependency,
cites Brady's Springdrift as the nearest prior work on the same substrate, and reconciles its
evaluation-status section with the evaluation that has since run.

The evaluation paper corrects three misattributions to canonical sources: defense in depth is not
a Saltzer and Schroeder principle, Anderson's reference monitor is tamper-proof rather than
tamper-evident, and Kerckhoffs was cited against the wrong reference. It corrects the denial split
(31 at preflight, 4 by posture policy), reports the false-denial rate with an interval and its
clustering caveat, states the denominator sensitivity, and corrects its measurement-integrity claim:
the F1, F2, and F3 ablation conversions carry empty effect logs, so the evidence that the effect log
fires is F4's 16 records and F8's 4, not those.
