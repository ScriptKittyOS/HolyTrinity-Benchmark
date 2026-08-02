# Fixtures — released vs held

A benchmark nobody can inspect is not a benchmark; but fixtures for some families would leak
detection patterns. The pre-committed decision (SPEC §11, "Option B": partial release with a
stated rationale) is:

| Family | Fixtures | Rationale |
|---|---|---|
| F4 approval binding | **RELEASE** | payload mutation + replay expose no internals |
| F5 coapproval | **RELEASE** | two-person logic is public-safe |
| F6 membrane bypass | **RELEASE** | the positive control is a public result |
| F8 posture & freeze | **RELEASE** | posture enforcement is public-safe |
| F9 process lifecycle | **RELEASE** | kill/reseed + TOCTOU expose no internals |
| F1 content provenance | **HOLD** | would leak content-firewall static-scan patterns |
| F2 runtime integrity | **HOLD** | would leak runtime-sentinel patterns + core-policy hash inputs |
| F3 skill supply chain | **HOLD** | would leak skill-audit heuristics |
| F7 receipt & reconciliation | **PENDING** | pending a disclosure decision on reconciliation logic |

**What "RELEASE" means in this table, precisely.** It means the family's **definition file**
(`../families/fN-*.md`) is published and its fixture data carries no detection signature, so it
ships when the harness does. It does **not** mean fixture payloads are in this directory — this
release contains the family definitions, the declarative F4-shaped attack sets in `../blind/`, and
the per-trial records in `../artifacts/`, but the fixture modules themselves import the system
under test and ship with it (`../MANIFEST.md`). We state this rather than let a **RELEASE** row
imply files that are not here.

We publish the **taxonomy and results for all nine** families (see `../families/README.md`
and `../artifacts/`); we withhold the fixtures — and the definition files — for the
families whose release would leak detection signatures. Partial release with a stated
rationale reads as rigor; silent non-release reads as evasion.

## Held families draw on curated red-team corpora (not released)

The content, runtime, and skill families (F1/F2/F3) are driven by curated adversarial corpora
whose *contents are the detection surface* — releasing them would hand an attacker the exact
strings and structures the firewall, sentinel, and auditor are tuned against. Those corpora
are **not** part of this release. The released families (F4/F5/F6/F8/F9) carry no such
signatures: their fixtures are payload mutations, approval-lifecycle states, and process events.
Their **family definitions** are published here; the fixture data itself is part of the harness and
ships when the system under test does.

This is a disclosure choice, not an IP one — the system itself is separately protected by a
pending patent. On the held families' eventual release, the same held-internals list in the
paper's §11 continues to apply.
