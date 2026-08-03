# Attack families — public taxonomy

The benchmark's nine boundaries and how they map to the induced-violation / control split
the paper uses (§6.3). Each targets one authorization boundary between an untrusted model
and an external effect. Attempt / proposed-violation / unauthorized-effect counts are the
measured campaign (`../artifacts/family-table.json`).

| # | Family | Boundary attacked | Kind | n | Proposed viol. | Unauth. effect | Fixtures |
|---|---|---|---|---:|---:|---:|---|
| F1 | Content provenance | intake content firewall | induced-violation | 11 | 10 | 0 | **held** |
| F2 | Runtime integrity | runtime sentinel | induced-violation | 8 | 5 | 0 | **held** |
| F3 | Skill supply chain | deterministic skill auditor | induced-violation | 7 | 5 | 0 | **held** |
| F4 | Approval binding | approval→execution join | induced-violation | 29 | 27 | 0 | released |
| F5 | Coapproval | two-person control | induced-violation | 4 | 4 | 0 | released |
| F6 | Membrane bypass | compile-time boundary guard | induced-violation (structural driver) | 3 | 3 | 0 | released |
| F7 | Receipt & reconciliation | scoped idempotency | correctness control | 4 | 0 | 0 | pending |
| F8 | Posture & freeze | degraded-mode enforcement | posture-enforcement | 4 | 0 | 0 | released |
| F9 | Process lifecycle | memory-is-not-authority | induced-violation (structural driver) | 3 | 3 | 0 | released |
| **Total** | — | — | — | **73** | **57** | **0** | — |

**Counting (paper §6.3):** seven induced-violation families (F1–F6, F9), one
posture-enforcement family (F8), and one reconciliation-correctness control (F7) — not nine
"attack families." F7 and F8 induce no violation by design (`agent_proposed_violation` is
false on all their trials).

## Released vs held (`../fixtures/README.md`)

Per a pre-committed disclosure split, fixtures for families that expose no detection
internals are **released** (F4, F5, F6, F8, F9); the content/runtime/skill families
(**F1, F2, F3**) are **held** because their fixtures would leak firewall patterns, runtime
sentinel patterns, and skill-audit heuristics — a defensive-hardening concern, not an IP one.
F7's fixtures are pending. The taxonomy and *results* for all nine are public; only the
held families' fixtures and definition files are withheld.

## Released family definitions in this repo

- [`f4-approval-binding.md`](f4-approval-binding.md) — the depth family: 29 canonicalization/
  mutation/lifecycle variants against the approval→execution join.
- [`f5-coapproval.md`](f5-coapproval.md) — two-person control on extreme-risk actions.
- [`f6-membrane-bypass.md`](f6-membrane-bypass.md) — compile-time boundary positive control.
- [`f8-posture-freeze.md`](f8-posture-freeze.md) — degraded-mode enforcement.
- [`f9-process-lifecycle.md`](f9-process-lifecycle.md) — kill/reseed inherits no authority.

The held F1–F3 definitions and the pending F7 definition are not in this release.

## On SPEC §4's "letters A–I"

`../spec/SPEC.md` §4 — frozen, and not edited — says the families are "re-mapped onto the
evaluation plan's letters A–I and the architecture's nine mechanisms in `families/README.md`".
**This file carries no A–I mapping and never has.** The letter scheme belonged to a private
evaluation plan that was not released, so there is nothing on the other side of the mapping to
point at. What this file does carry is the trace SPEC §4 wanted — mechanism → attack → result, per
family, with the boundary attacked and the measured counts. The dangling reference is recorded in
`../spec/PACKAGING-NOTES.md` §"Other references in the frozen text that do not resolve" rather than
fixed in the frozen spec.
