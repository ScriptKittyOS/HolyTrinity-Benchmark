# Packaging notes for the frozen specification

`SPEC.md` is **frozen** — committed once, before the first scored run, and never edited (a single
commit at 2026-08-01T22:17:36Z; the scored campaign ran 2026-08-02T04:04:04Z). We do not edit it,
including to fix cosmetic problems. This file records what a reader needs to know to read it in
this release.

## Relative paths resolve one level up

`SPEC.md` was authored at the root of the private benchmark tree. In this release it lives in
`spec/`, so two of its internal references do not resolve as written:

| `SPEC.md` says | resolves here to |
|---|---|
| `families/README.md` (§4) | `../families/README.md` |
| `fixtures/README.md` (§11) | `../fixtures/README.md` |

`SPEC.md` §4 also cites `test/.../tool_loop_boundary_test.exs`, which lives in the system under
test and is not part of this release.

## Directories named in SPEC

§0 describes the two roles as `aggressor/` and `oracle/`. Both are released, at those paths. They
reference the system under test and do not compile without it, so they are published to be read
rather than run (`../MANIFEST.md`). The role separation SPEC §0 describes is the paper's
methodological claim, and releasing both directories is what makes it checkable.

§4 additionally cites `aggressor/chaos/` for the F6 and F9 chaos harness. That path does not
resolve here: the chaos driver is a single module at `../aggressor/chaos.ex` rather than a
directory. The frozen text describes the private development layout, and flattening it for release
is a packaging change rather than a methodology change.

## Departures between the frozen schema and the shipped artifacts

`SPEC.md` §7 fixes the trial-record schema. Three departures are present in the committed
artifacts and are documented in `../artifacts/README.md` rather than by editing §7:

1. `detection_source` carries `compile_time` on the six F6/F9 structural trials, which is outside
   §7's enumeration.
2. `authorization_snapshot_ref` is a `{start, end}` timestamp pair, not the snapshot *file
   references* §7 specifies; the raw approval-record snapshots are not published.
3. `proposed_action` carries an extra `effect_channel`; `payload_summary` is an object rather than
   a string; and the gate and chaos trials carry `provider: null` / `operation: null`.

Further departures between what §4, §6, and §2.1 pre-registered and what the campaign delivered
are recorded here rather than by amending `SPEC.md` — that is the point of freezing it:

| `SPEC.md` pre-registered | delivered |
|---|---|
| §4: 25–40 variants per family, ~250–350 trials | **73 trials**, 3–29 per family; only F4 (29) is in range |
| §6: false denials from "the reads-only production soak", broken out by policy | synthetic n=75 (three amount configurations × 25 repeats), no per-policy breakout |
| §6: overhead with "throughput ceiling both ways, per-agent process + memory overhead" and a confidence interval | latency percentiles only |
| §2.1: authorization snapshot taken "through a **separate DB connection**" | the Oracle reads the raw approval tables through the same repository as the system under test |
| §2.1: snapshots at start *and* end so "a diff between the two snapshots is evidence" | both are captured, but adjudication uses the end snapshot only; the diff is never computed |
| §4 (F6): "confirm the compile-time invariant **fails the build**" | the guard's predicate is checked over the source tree; no build is invoked |
| §4 (F9): "kill/reseed; TOCTOU; concurrency" | reseed-identity and idempotence checks only |
| §1: "Detected … record time-to-detection" | no `detected` trials occurred, so no detection latency is reported |
| §2.3: `undecidable` "reported as its own count" | no `undecidable` verdicts occurred; the report has no such column |

The load-bearing independence property — that the Oracle never reads the verifier's `proof_state`
and reconstructs authorization from raw approval records — holds as specified. The *transport*
independence in §2.1 does not, and is named as future work in the paper's conclusion.
