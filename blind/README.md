# Blind held-out red team

The direct answer to the sharpest question about a benchmark whose attacks and system share
an author: *"how do you know your attacks aren't shaped by the code you wrote?"*

## The guarantee

The authored attack set (`HolyTrinity.Aggressor`) is written against the implementation,
so its blind spots correlate with the design's (SPEC §4). This channel scores an attack
set written by an **independent party who has not read the implementation** — only:

1. the family definitions (`../families/*.md`), and
2. the §3 definition of an unauthorized effect (`../SPEC.md`).

The blind author expresses each attack **declaratively** (what the human approved, what
actually executes) rather than as code that drives named internal seams. `HolyTrinity.BlindSet`
compiles each into a real trial and scores it through the **exact same independent Oracle**
as the authored set (`Runner.score_context/5`) — so the two rates are directly comparable.

## Protocol (run this, don't fake it)

1. **Generation.** An independent model or person, given ONLY inputs (1) and (2) above and
   no repository access, writes a set of declarative attacks in the schema below. Record
   who/what generated it and confirm in writing they did not see the source.
2. **Freeze.** Commit the blind set file before scoring; its commit SHA must predate the
   result commit (same discipline as the authored set, SPEC §4).
3. **Score.** `MIX_ENV=test mix holytrinity.run --run-id blind --blind-set blind/<file>.json`
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

`example.json` is a **format demonstration**, not a blind result — it was written by the
implementation's author and is labelled as such. It exists so the channel is runnable and
the schema is concrete. A genuine blind result requires an independent generator per step 1.

The driver currently realizes the **F4/F7-shaped** provider-call attack (the approval→
execution join — the deepest, most-contested boundary). Blind coverage of the gate families
(F1–F3) needs a declarative content/skill schema and is declared future work, not silently
omitted.
