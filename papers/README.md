# Papers

Two papers describe this work. They are siblings and should be read together: the first states
the architecture and specifies the evaluation, the second runs it.

| Source (archival) | Readable | Paper | Dated |
|---|---|---|---|
| `the-model-proposes-the-system-authorizes.tex` | [`../PAPER-ARCHITECTURE.md`](../PAPER-ARCHITECTURE.md) | **The Model Proposes, the System Authorizes: An Authority Control Plane for AI Agents on the BEAM** | 29 July 2026 |
| `authority-bound-agentic-execution.tex` | [`../PAPER.md`](../PAPER.md) | **Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under Adversarial Load** | 2 August 2026 |

**Read the Markdown; keep the LaTeX.** The `.tex` files in this directory are the archival record
— the deposited Zenodo versions hold exactly these files, verified by hash, and they are the arXiv
submission sources. They are not the copies you are meant to read: GitHub renders LaTeX as plain
text with the markup left in. The Markdown renderings at the repository root are for reading, and
the rest of the documentation links to them.

Both `.tex` files compile with `pdflatex` alone: no `.bib`, no figures, no external inputs. No
compiled PDFs ship, and the machine these were last revised on had no LaTeX toolchain, so the page
counts are unverified.

The two forms are held together by `../scoring/check_paper_sync.py`, which normalizes each pair and
fails if a number appears in one and not the other. That gate exists because these renderings have
drifted twice, and on both occasions the Markdown retained a figure the LaTeX had already retracted
— the `57/73` denominator and the "observed 47" effect-log claim. A rendering nobody checks is a
second place for a retracted number to survive.

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
- **The bound.** The architecture paper has a Zenodo DOI, and its earliest deposit is timestamped
  `2026-08-02T05:34:27Z`, roughly ninety minutes *after* the campaign's earliest trial. It makes the
  companion citable and fixes its text at a third-party host. It does nothing to corroborate the
  29 July date, which remains the manuscript's own assertion. The specification's commit history is
  the harder evidence, and it is the one to lean on.

## Status

Both papers are deposited on Zenodo as preprints under CC-BY-4.0.

| Paper | Concept DOI (cite this) | Latest deposit | Matches this directory? |
|---|---|---|---|
| The Model Proposes, the System Authorizes | `10.5281/zenodo.21754762` | `10.5281/zenodo.21764616` | **no — re-deposit pending** |
| Authority-Bound Agentic Execution | `10.5281/zenodo.21755869` | `10.5281/zenodo.21780658` | yes |

Cite the concept DOI unless you mean one specific version; it resolves to whatever the current
version is.

**On the correspondence between the archive and this directory, stated exactly.** Zenodo records
are immutable once published: a deposit's files cannot be edited, only superseded by a new version.
So the archive tracks this directory only as fast as new versions are minted, and right now the two
papers are in different states.

`10.5281/zenodo.21780658` is the current deposit of the evaluation paper and holds
`authority-bound-agentic-execution.tex` as it stands here. It supersedes `10.5281/zenodo.21764581`,
which predates the corrections in `../CHANGELOG.md` — three published figures moved (the F5
ablation, the no-control ceiling, and the governed-latency percentiles) and several claims were
narrowed. Do not quote the superseded version for any of them.

`the-model-proposes-the-system-authorizes.tex` has since changed too — Appendix B's reviewers' note
no longer says the paper has no measured results, because the companion evaluation now exists and
is reported in §11 and §12, and that evaluation is now a numbered reference rather than four
uncited mentions of "reported separately". **The latest deposit, `10.5281/zenodo.21764616`, does
not contain those changes.** Until a new version is minted, cite the concept DOI and read the
source here for the current text.

The v1.0 deposits (`10.5281/zenodo.21754763` and `10.5281/zenodo.21755870`) hold the original
pre-correction drafts and are superseded twice over; do not quote them.

Both papers were also submitted to arXiv. Neither is announced, so neither has an arXiv identifier.

Compiled PDFs are not in this directory; build them with `pdflatex` if you want them.

## Corrections applied to both

Both sources here incorporate an adversarial audit and a CoSAI whitepaper assessment run against
them. The changes a reader of an earlier draft would notice:

The architecture paper corrects its test count to a figure that verifies (1,286 test blocks across
287 test files), and replaces "compile-time invariants" with "CI-enforced structural invariants"
throughout, because the guard is an ExUnit test rather than a compiler hook and `mix compile`
succeeds with a violating caller present. It names the SRF **IaaS** operating model rather than an
invented "customer-built" label, lists seven proof states rather than six, describes agent reset as
a supervised shutdown with a bounded grace period rather than a kill, discloses the Jido dependency,
cites Brady's Springdrift as the nearest prior work on the same substrate, and reconciles its
evaluation-status section with the evaluation that has since run.

The evaluation paper corrects three misattributions to canonical sources: defense in depth is not
a Saltzer and Schroeder principle, Anderson's reference monitor is tamper-proof rather than
tamper-evident, and Kerckhoffs was cited against the wrong reference. It corrects the denial split,
reports the false-denial rate with an interval and its clustering caveat, states the denominator
sensitivity, and corrects its measurement-integrity claim: the F1, F2, and F3 ablation conversions
carry empty effect logs, so the evidence that the effect log fires is F4's 16 records and F8's 4,
not those.

The corrected **denial split** is worth stating outright, because an earlier draft got it wrong in
both terms. Of the 41 provider-call trials, 35 were denied before the adapter ran, and they break
down as **18 preflight / `AuthorityAssurance`, 13 preflight / `SpendPolicy`, 2 policy /
`RuntimePosturePolicy`, 1 policy / `AuthorityAssurance`, 1 policy / `AuthorityJudge`** — not "31 at
preflight, 4 by posture policy". The old preflight figure folded 13 `SpendPolicy` denials into
`AuthorityAssurance`, which hid a load-bearing barrier that no family definition names.
`../REPORT.md` carries the full breakdown.
