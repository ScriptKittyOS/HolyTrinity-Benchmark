# Blind held-out red team

The direct answer to the sharpest question about a benchmark whose attacks and system share
an author: *"how do you know your attacks aren't shaped by the code you wrote?"*

## The guarantee

The authored attack set (`HolyTrinity.Aggressor`, held) is written against the implementation, so
its blind spots correlate with the design's (SPEC §4). This channel is **designed** to score an
attack set written by an **independent party who has not read the implementation** — given only:

1. the family definitions (`../families/*.md`), and
2. the §3 definition of an unauthorized effect (`../spec/SPEC.md`).

The blind author expresses each attack **declaratively** (what the human approved, what
actually executes) rather than as code that drives named internal seams. `HolyTrinity.BlindSet`
compiles each into a real trial and scores it through the **exact same independent Oracle**
as the authored set (`Runner.score_context/5`) — so the two rates are directly comparable.

## Protocol for a genuine blind set — not yet executed

1. **Generation.** An independent model or person, given ONLY inputs (1) and (2) above and
   no repository access, writes a set of declarative attacks in the schema below. Record
   who/what generated it and confirm in writing they did not see the source.
2. **Freeze.** Commit the blind set file before scoring; its commit SHA must predate the
   result commit (same discipline as the authored set, SPEC §4).
3. **Score.** `MIX_ENV=test mix holytrinity.run --run-id blind --blind-set blind/blind-set-01.json`
   (needs the system under test, which is not part of this release).
4. **Report.** The blind unauthorized-effect rate + 95% CI is reported **separately** from
   the authored set. If the blind set finds nothing the authored set missed, that bounds
   author bias; if it finds something, that is the paper's strongest kept-failure (SPEC §10).

## Declarative attack schema

One JSON array of objects. Each object:

| field | meaning |
|---|---|
| `id` | unique attack id (string) |
| `approved_amount_cents` | what the human approved (int, default 100) |
| `approval` | `"normal"` \| `"expired"` \| `"revoked"` (the approval's lifecycle state) |
| `driven_amount_cents` | amount that actually executes (omit = same as approved) |
| `driven_extra` | object of fields added/changed post-approval (clause-b divergence) |
| `expect` | the author's prediction `"prevented"` \| `"effect"` — recorded, **never used to score** |

The Oracle scores from telemetry + the raw authorization snapshot only; the author's
`expect` field is not consulted (that would leak the author's belief into the verdict).

## Scope (stated honestly)

**Neither committed set is a blind result under the protocol above, and both are labelled here.**
`example.json` is a **format demonstration** written by the implementation's author. `blind-set-01.json`
(32 attacks + 4 controls) is **also author-constructed**, under a self-imposed blindness discipline
— built only from the family definition and the §3 definition, without reference to the
canonicalization internals — but it does not satisfy step 1 (no independent generator, no written
attestation) and it did not satisfy step 2: the set and its result landed in the **same** commit
(`d93b5d5`), so the file's SHA does not predate the result's — and, as the provenance note below
records, the blob at that commit is **not** the file shipped here. Four of the 36 entries shipped
here are also identical to entries in `example.json` apart from the `id` field (`blind-19`,
`blind-27`, `blind-28`, `blind-33`); in the file that was actually scored, **nine** were
(`blind-19`, `blind-27` through `blind-30`, and `blind-34` through `blind-37`). A genuine blind
result requires an independent generator per step 1 and remains future work.

### Provenance: the file shipped here is not the file that was scored

State this plainly, because it is the same failure mode the corrected Oracle had — a repaired
artifact presented as the one that produced the number.

**The published `0/32` was measured against the blob committed at `d93b5d5`** (sha256
`6559b208…`). **The file shipped in this directory is a later, corrected version** (sha256
`7e6f878e…`). They differ:

| | scored (blob at `d93b5d5`) | shipped here |
|---|---|---|
| sha256 | `6559b208…` | `7e6f878e…` |
| entries | 36 | 36 |
| **distinct shapes** | **31** | **36** |
| distinct *attack* shapes | **30** of 32 | **32** of 32 |
| ids | gap at `blind-32`, run to `blind-37` | `blind-01`–`blind-36`, no gaps |

The scored file carried five redundant entries: `blind-29` repeated `blind-27` (expired-approval
replay), `blind-30` repeated `blind-28` (revoked-approval replay), and `blind-35`, `blind-36` and
`blind-37` each repeated `blind-34` (the honest control). The shipped file closes the id gap,
renumbers `blind-01`–`blind-36`, and differentiates all five — the two lifecycle replays now carry
a distinct payload divergence each, and the four controls now carry four distinct approved amounts.

Two consequences, stated exactly:

1. **The published interval was measured over 30 distinct attack shapes, not 32.** `0/32, 95% CI
   [0.0%, 10.7%]` is arithmetically correct for the trials driven, but two of those 32 trials were
   duplicates of two others, so the *coverage* behind the interval is 30 shapes.
2. **The scored file's mechanism split was 16 extra-key / 7 amount / 3 both / 6 lifecycle**, not
   the 18 / 7 / 3 / 4 that describes the file shipped here. Anywhere the shipped file's split is
   quoted against the published result, the two do not correspond.

**The denominator is unaffected.** Both files carry 32 attacks and 4 controls, so `Wilson(0, 32)`
= `[0.0%, 10.7%]` either way, and nothing in the published rate or interval changes.

**Re-run of the shipped file: still `0/32`, and the records now ship.** Under the corrected Oracle
(`../oracle/oracle.ex`, sha256 `f1448c9e…`) the *shipped* file — the one with 32 distinct attack
shapes — was re-run and again produced **0 unauthorized effects in 32 attacks**. So the result is
not an artifact of the duplicates. `../artifacts/blind.jsonl` is that re-run: 36 rows, 32 attack
trials, 0 unauthorized effects, 0 harness errors, ids `blind-01`–`blind-36` with no gaps, splitting
**18 / 7 / 3 / 4** — the shipped file's split, matching this directory's attack set exactly.

That does not repair the provenance defect, and we are not presenting it as if it did. **The number
in `../REPORT.md` was produced by the defective file, and no JSONL from that run was retained.**
What ships is corroboration of the rate over 32 genuinely distinct shapes, not the record of the run
behind the published figure. Read `blind.jsonl` as the former.

### What the 32 attacks actually cover

The 32 attacks exercise **three divergence mechanisms plus their combination** — an added payload
key, a changed amount, both, and an expired/revoked approval. The counts differ by file: **18 / 7 /
3 / 4** for the attack file shipped here, which is also the split of the re-run records in
`../artifacts/blind.jsonl`, against **16 / 7 / 3 / 6** for the defective blob that produced the
published number. Quote each split against its own file. Either way it is four mechanisms, not 32
independent probes: within a mechanism the attacks are near-perfectly correlated, so **the
per-payload interval overstates the evidence.** Report the pair:

| denominator | numerator | Wilson 95% upper |
|---|---|---|
| per-trial (32 payloads) | 0 | **10.7%** |
| per-mechanism (4 mechanisms) | 0 | **49.0%** |

The honest reading is the second. It is the same clustering discipline the papers already apply to
the false-denial rate. The paper's §6.9 carries this caveat; if you find §6.9 describing "a
32-attack set of diverse divergences" with an unqualified `[0.0%, 10.7%]` and no mechanism count,
that text is stale against this file, and this file is the authority on what is in the set.

The driver currently realizes the **F4/F7-shaped** provider-call attack (the approval→
execution join — the deepest, most-contested boundary). Blind coverage of the gate families
(F1–F3) needs a declarative content/skill schema and is declared future work, not silently
omitted.
