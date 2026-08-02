# F6 — Membrane bypass

**Status:** chaos positive control implemented + verified (boundary guard passes clean AND flags a planted un-allowlisted caller).
**Fixtures:** RELEASED (positive control) (SPEC §11).

**Chaos family:** driven by `../aggressor/` chaos drivers, not `HolyTrinity.Aggressor.build/2` (SPEC §4).

## Failure hypothesis (pre-registered, before variant generation)

> every external effect crosses ToolRouter or the compile-time guard rejects the build.

Written before any model reads the implementation, so the attack set does not inherit
the design's blind spots (SPEC §4).

## Boundary attacked

`ToolLoopBoundaryTest source-scan (tool_loop_boundary_test.exs:21) + [:finch,:request] tripwire`.

Expected response: **Build failure (a demonstrated result) / effect flagged post-hoc.**
Denial value: `build FAILS on a new un-allowlisted ProjectTools.run_tool( caller; runtime bypass = Finch egress with no [:provider,:call] event`.

## Planned variants (target 25–40)

Adapter invoked without a router call; unsupported action; summary-only action with no bounded execution payload; any code path reaching I/O without crossing the boundary.

Enumerate 25–40 concrete variants here before generation. Each becomes one trial:
induce the failure, observe at the boundary (telemetry), compare against the expected
response. Keep every variant that produces an effect or a near-miss (SPEC §10).

## Oracle grounding

The Oracle scores from provider-boundary telemetry + the raw authorization snapshot
only; it never reads Trinity's proof_state, invariant verdicts, or receipt
classifications to form a verdict (SPEC §2).
