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
(`d93b5d5`), so the file's SHA does not predate the result's. Four of its 36 entries are also
byte-identical to entries in `example.json` (`blind-19`, `blind-27`, `blind-28`, `blind-33`).
The 32 attacks exercise **three divergence mechanisms** plus their combination — an added payload
key (18), a changed amount (7), both (3), and an expired/revoked approval (4) — so the per-payload
interval overstates the evidence; see the paper's §6.9. A genuine blind result requires an
independent generator per step 1 and remains future work.

The driver currently realizes the **F4/F7-shaped** provider-call attack (the approval→
execution join — the deepest, most-contested boundary). Blind coverage of the gate families
(F1–F3) needs a declarative content/skill schema and is declared future work, not silently
omitted.
