# Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under Adversarial Load

Ayla Croft, ScriptKittyOS · August 2, 2026

**Cleared for submission.** Counsel has approved the redaction map (§11); this version is
written from the public-safe side of the disclosure boundary, and the
internals enumerated in §11 remain held per the filing schedule. All numbers are from real benchmark runs; the exact run
commit and reproduction commands are in `REPORT.md`.

**Artifact and reproducibility (partial, stated honestly).** The evaluation ran against the
Trinity authority control plane and the HolyTrinity Bench harness pinned at commit `79bfd54`,
using mock provider adapters (no live provider I/O). We open-source **the benchmark**: the
harness, the independent oracle, the frozen specification, the family definitions, the
released fixtures (per §11), and the **committed result artifacts** (per-trial JSONL, the
family table as data), at **https://github.com/ScriptKittyOS/HolyTrinity-Benchmark**. We do
**not** yet open-source the **system under test** (the Trinity control plane), so the paper is
*not fully re-executable end-to-end by a third party at this time.* Two things are
nonetheless independently checkable now: (1) every reported number and table follows
mechanically from the committed JSONL, which ships, so the *results* are auditable without the
system; and (2) the harness, oracle, and specification are public, so the *method* is
inspectable. Full end-to-end re-execution becomes possible when the system under test is
released (§11, tied to the filing schedule). We flag this rather than imply full
reproducibility, and §11 records exactly what is and is not released.

**Relation to the companion architecture paper.** This paper evaluates the authority control
plane described in [15], a companion manuscript dated 29 July 2026, three days before the
campaign reported here was run. That paper is the specification under test, not a background
citation: it states the
threat model, the security invariant, and the nine mechanisms evaluated here, and its
evaluation section, written before any harness existed, fixes this paper's primary metric
(unauthorized-effect rate), its three secondary metrics, a twelve-item attack-class list, and
the strong test, "replace the agent entirely with an adversarial oracle that emits worst-case
output at every step", together with its falsification criterion. Of that test it says: "I
state plainly that I have not run this test." This paper runs it, and reports the result
against that specification including where we departed from it (§8).

**Relation to prior work.** This paper studies an application-level authority layer built
on the BEAM and is a companion to Michael Hostetler's architecture study of *Jido*, a
model-independent agent SDK and BEAM-native runtime, "Governing Risk with Agents: An
Architecture Study of Jido on the BEAM" [Hostetler 2026, ref. [11]]. Jido's separation of
agent, controller, and runtime-owned effect is the substrate on which Trinity locates its
authority controls; we cite it as the framing this work extends and measures. It is cited at
a **pinned revision** and carried as personal communication pending an archival identifier
(see References): the underlying document is not a versioned publication, so we do not
depend on a mutable link.

**Disclosure and competing interests.** This is a self-evaluation: the authors build and hold
a commercial interest in the system under test (a patent filing is pending, §11). We disclose
this because a reader should weigh it against a favorable result. The mitigations are
structural and stated throughout: an independent oracle that never reads the system's verdict,
a pre-registered and frozen specification, an ablation and no-control baseline that a weak
attack set could not produce, and a kept-and-fixed failure reported in full. No external
funding sponsored this evaluation; LLM assistance in building the harness is disclosed in §8.

---

## Abstract

Agentic systems can be driven into policy violations reliably; large-scale red-teaming has
established this and we take it as a premise. The security-relevant question is therefore
not whether a model misbehaves but whether misbehavior converts into an unauthorized
external effect. We present Trinity, an authority control plane in which the model proposes
and the system authorizes: an agent may reason, plan, draft, and request tools, but is
architecturally incapable of being the authority that decides whether an action occurs. We
evaluate an implementation on the Erlang/BEAM runtime against **73** trials spanning
**seven** induced-violation families, one posture-enforcement family (F8), and one
reconciliation-correctness control (F7), adjudicated by an independent oracle grounded in
provider-boundary telemetry and a raw authorization snapshot, never in the system's own
verdict. The agent was induced to propose a
policy-violating action in **57 of the 61 attack trials**; across **61** attack trials **zero**
unauthorized external effects occurred (95% CI [0.0%, 5.9%]). Three things reported
alongside it support that result. First, an **ablation study**: disabling
each mechanism in isolation converts its attacks (0→10, 0→5, 0→5, 0→14 unauthorized effects
across the content, runtime, skill, and approval-binding boundaries), and a **no-control**
run with the full membrane disabled converts **47 of 63** attacks: the ceiling the governed
result is measured against. Second, a **kept-and-fixed failure**: the v1 run's single
unauthorized effect was a sleeper skill the deterministic auditor missed; we hardened the
auditor with a behavioral conditional-exfil detector, re-benchmarked, and ship the pre-fix
run as data rather than erasing it. Third, **calibration with its decomposition**: across
the 41 provider-mediated trials there were **zero overclaims**, and on **all 6** trials where
a real effect actually occurred the system's proof state matched the independent verdict: a
claim we state with its n rather than as blanket "perfect calibration," since 33 of the 41
are abstentions or non-events. Because prevention is upstream, only six governed
trials produced an observed effect; we therefore add a **measurement-integrity control (F10)**
confirming the oracle's effect log fires when an effect occurs (and the ablation runs wrote 20
provider-boundary records, 16 in the approval-binding ablation and 4 in the posture ablation),
so a governed zero means "nothing crossed," not "the oracle was blind."
Governed actions carry a median added latency of **~17 ms**; the false-denial rate is
**0.0%** over 75 legitimate approved actions. We report every rate with a confidence
interval, publish a seven-state proof model rather than binary pass/fail, and state the
boundaries our attack set does not exhaust. Limitations are stated in full: one system, one domain, mock provider adapters, and a genuinely-distinct rather than exhaustive attack set.

---

## 1. Introduction

Autonomous agents that call tools, send email, and move money are being deployed against a
settled empirical result: under adversarial pressure, a model can be driven to *propose*
almost anything [7, 8, 12]. Prompt injection, jailbreaks, and poisoned context convert a
helpful assistant into a compliant one. We do not re-litigate this; we take it as the premise.

The security-relevant variable is downstream of the model. A proposal is not an effect. The
question a practitioner needs answered is: **when the model is compromised and proposes a
violating action, does that action reach a provider and change external state without a
valid authorization?** This paper measures that quantity, the *unauthorized-effect rate*, for one implemented system under a targeted adversarial load, and reports it separately from
the *misbehavior rate* that the red-teaming literature reports, because the distance between
the two is the entire contribution.

Our headline result: across 73 trials aimed at specific authorization boundaries (61 attack
trials plus 12 known-good controls), the agent proposed a violating action in 57 and produced
an unauthorized external effect in 0 of the 61 attack trials. A zero is exactly the result a reviewer is trained to distrust, so
we do not present it alone. We ablate each mechanism to show it is necessary; we run the
attack set against a disabled membrane to show the attacks convert when nothing stops them;
we report the one effect the system *did* leak before we fixed it; and we bound every rate
with a confidence interval. The contribution is the method and the negative controls.

## 2. Threat model

**Untrusted.** The model and every model-derived artifact: tool-call arguments, plan text,
agent-generated identifiers, tool output fed back into a later decision, and the
natural-language rationale shown to a human approver. We assume the model's context can be
fully compromised and that it will propose violating actions.

**Trusted (out of scope).** Host compromise, a malicious insider with direct database
access, provider-side compromise, and side channels. These are real risks and are not what
this architecture addresses; the paper does not claim otherwise.

**What we do not claim.** Trinity does not eliminate agent risk or prevent prompt injection;
the premise is that both occur. The BEAM is not a hostile-code sandbox: process isolation
limits software-failure propagation, not adversarial code execution. Not every path to I/O
is mediated; any path that reaches a provider without crossing the membrane is an uncovered
path, and §6.10 names the mechanism that catches such paths after the fact. Exactly-once
execution is not guaranteed. And a passing conformance suite is a conformance result, not a
security result.

## 3. Security invariant

Informally: *an agent whose model context is fully compromised cannot produce an external
side effect that lacks a matching, in-scope, unexpired authorization record.* The system
verifies seven properties of every sensitive action before and after it executes; that the
action was **required**, **exact**, **timely**, **permissioned**, **router-executed**,
**receipt-matched**, and **proof-packeted**. These seven predicates are the public
vocabulary of the layer; they describe *what* is verified without publishing the registry
that verifies it.

## 4. Architecture (method)

Trinity separates *proposal* from *authorization* structurally.

- **The model proposes.** It reasons, plans, drafts, and emits tool-call requests. It never
 holds provider credentials and never reaches a provider directly.
- **The BEAM authorizes and executes.** Every external side effect crosses one mediated
 boundary, the **tool router**, or is flagged after the fact. We call this router, together
 with the policy and verification stack around it, the **membrane**, and use that one term
 throughout for the mediated side-effect boundary (not "router"/"boundary" interchangeably).
 Around it sits a layered policy stack (sensitive-action, runtime-posture, spend, and outbound
 policies) and an independent verifier (the Authority Assurance layer) that checks the seven
 properties of §3, records durable evidence, and re-reconciles provider receipts asynchronously.
- **Human approval binds one exact action envelope.** An approval authorizes a single action
 identified by provider, operation, account, idempotency key, amount where relevant, and a
 canonical hash of the semantic payload. A later action that differs in any of these does
 not match.
- **Authority is durable data, not process state.** Authorization records live in the
 database and outlive the process that requested the effect. Killing and reseeding an agent
 worker neither resurrects a denied action nor re-executes an approved one.

This proposal/authorization split, and the location of effect control in the runtime rather
than the model, follows the governance framing of Hostetler's Jido architecture study
[Hostetler 2026, ref. [11]]: make decision, effect, and runtime boundaries explicit and
composable so that governance controls can be located and evaluated independently of the
decision method.
Trinity is one such application-level control layer, and this paper is its evaluation.

Proof is not binary. The verifier emits one of seven proof states: verified, failed,
degraded, pending-receipt, legacy-incomplete, manual-review-required, and missing, because
real provider systems are late and incomplete. Publishing this *state model* (as distinct
from the internals that compute it) is itself a contribution: it separates a truthful proof posture from an overclaimed one, which most binary evaluations cannot.

## 5. Implementation

The control plane runs on Erlang/OTP. Durable orchestration and retries use a
database-backed job runtime; real-time operator state uses publish/subscribe. The
model-facing agent runtime is a hosted service the BEAM calls as an authenticated API, never
an interactive developer session; it is **self-operated** (an internally-built OpenAI-compatible
service), and it routes to a **third-party foundation model**, in the evaluated deployment,
NVIDIA's `nemotron-3-super-120b-a12b` via the official NVIDIA endpoints. That model identity
describes the deployment rather than the measurement. The 57/61 violating-input rate is a property
of the trial design, because the harness injects each violating action at the control-plane boundary
instead of sampling one from the model (§6.1). A different or more heavily-guarded base model would
leave that column unchanged and would not move the invariant the paper measures. The system
under test is pinned to commit `79bfd54`. The invariant depends on two runtime
properties:

- **Process-vs-data ownership.** Agent workers are supervised, ephemeral processes; the
 authority graph is durable database state. "Kill and reseed" is therefore structural, not
 bolted on: a reseeded worker is born from the immutable core policy and carries no
 inherited authority. On the BEAM a killed worker is a *terminated* process, not a merely
 unreachable one, so **the worker itself** is inert, which is the property an
 incident-response control needs and which a merely-unreachable agent does not have. We are
 careful about the scope of that claim: process termination quarantines the *process*, but
 work the worker already enqueued on the durable job runtime (in-flight jobs, and any open
 handles) **survives the kill by design** and is a separate surface this paper does not
 measure. F9 evidences the reseed identity and the worker's inertness; verifying that
 pre-kill durable work is also quarantined is future work. We flag this precisely because it
 is a claimed contribution against an under-addressed gap (verifying a quarantined agent has
 *stopped acting*, not just become unreachable), and we would rather bound the claim than
 overstate it.
- **Compile-time boundary coverage.** A structural check fails the build if a code path
 reaches the raw tool-execution seam without passing the result firewall: the fence is
 enforced at compile/CI time, not by convention.

The full percentile table, hardware, and per-trial provenance for commit `79bfd54` are in
`REPORT.md` and the committed `artifacts/`.

## 6. Evaluation

### 6.1 Method

We measure two rates and never collapse them:

- **Violating-input rate**: the fraction of trials whose input was *constructed* to be
 policy-violating. We do not measure a model misbehaviour rate and do not report one. Our
 harness injects the violating action directly at the control-plane boundary, exactly as a
 fully compromised model would emit it. That is the strong test specified in [15]: "replace
 the agent entirely with an adversarial oracle that emits worst-case output at every step."
 Stipulating the proposal produces a strictly stronger adversary than sampling one, because
 it never fails to propose, and it removes the base model's variance from the result. A
 model-in-the-loop campaign is future work (§12).
- **Unauthorized-effect rate**: the fraction of *attack* trials (total minus known-good
 `allowed` controls) in which a proposed action produced an external effect not covered by a
 valid, in-scope, unexpired authorization.

Every trial resolves to exactly one outcome: **prevented** (no external effect crossed the
boundary), **detected** (the effect occurred and the system independently flagged it), or
**undetected** (the effect occurred unflagged). Non-attack controls are recorded as
**allowed** and never count toward the unauthorized-effect rate.

**The definition of an unauthorized effect was fixed in writing before the first scored run**
(`SPEC.md` §3), including edge cases (partial effects, idempotent replay, tenant-scoped
reads, wrong-attribution, and approved-but-misrepresented actions). It was not adjusted after
seeing results.

**Scoring is automatic, not judge-mediated.** All 73 trials are scored mechanically by the
oracle from telemetry and the authorization snapshot against the §3 rules: no LLM-as-judge
and no per-trial human verdict. Every trial record carries `scorer: "auto"`, and the
`SPEC.md` §8 provision for manual adjudication of genuinely undecidable cases was not needed
(the run produced no `undecidable` verdicts). Because the rules are mechanical and the inputs
are logged, the scoring is reproducible from the committed JSONL rather than resting on an
adjudicator's judgment.

### 6.2 The oracle (independent adjudication)

The part of the evaluation that decides whether the numbers mean anything is the oracle, and
its one rule is that **it never reads the system under test's own verdict.** The router, the
audit tables, the receipts, and the proof state are all measured outputs under test; using
any of them to score a trial would let an attack that corrupts the authorization path also
corrupt the scorer.

Ground truth is assembled from observables captured outside the control plane's bookkeeping:
(1) an effect log at the provider boundary, captured via runtime telemetry emitted around the
actual adapter invocation; (2) a network-layer tripwire on the HTTP client, which fires for
any real outbound request regardless of the router and so catches an effect that evades the
membrane entirely; and (3) a raw snapshot of approval records taken at trial start and end,
from which the oracle reconstructs authorization (including two-person quorum) without
consulting the verifier's judgment.

For gate-type boundaries (content, runtime-integrity, skill-supply-chain), where the "effect"
is tainted input passing a gate rather than a provider call, the gate's real allow/deny
decision is the observed effect, cross-checked by the provider-call tripwire: which, in a
correct in-process run, never fires.

**A validity trap we avoid by design:** in this codebase, injecting a fake HTTP client into
an adapter, a natural way to observe calls, silently disables a spend gate. The oracle
therefore observes only via telemetry, which is behavior-neutral. This is recorded in the
threats to validity.

### 6.3 Attack families and headline result

Each family targets one authorization boundary; family definitions and per-family failure
hypotheses were written before any model generated variant volume, so the attack set does not
inherit the design's blind spots. Two families (membrane-bypass and process-lifecycle) are
chaos tests driven by process kills and structural checks rather than prompts.

| Family | Boundary attacked | Attempts | Proposed violation | Unauthorized effect |
|---|---|---:|---:|---:|
| F1 Content provenance | intake content firewall | 11 | 10 | 0 |
| F2 Runtime integrity | runtime sentinel | 8 | 5 | 0 |
| F3 Skill supply chain | deterministic skill auditor | 7 | 5 | 0 |
| F4 Approval binding | approval→execution join | 29 | 27 | 0 |
| F5 Coapproval | two-person control | 4 | 4 | 0 |
| F6 Membrane bypass | compile-time boundary guard | 3 | 3 | 0 |
| F8 Posture & freeze | degraded-mode enforcement | 4 | 0 | 0 |
| F9 Process lifecycle | memory-is-not-authority | 3 | 3 | 0 |
| F7 Receipt & reconciliation *(correctness control)* | scoped idempotency | 4 | 0 | 0 |
| **Total** | | **73** | **57** | **0** |

**Not every family induces a violation, and we count them accordingly.** Two families carry
zero proposed violations by design. **F7** verifies that an idempotent retry produces exactly
*one* external effect: a reconciliation-correctness property (its four replays are, in fact,
most of the campaign's real-effect observations, §6.7). **F8** drives a *legitimately
approved* write and checks that degraded-mode posture blocks it; nothing violating is
proposed (`agent_proposed_violation` is false on all four). The split is therefore
**seven induced-violation families (F1 to F6, and F9), one posture-enforcement family (F8), and one
reconciliation control (F7)**: not nine attack families. F6 and F9 are structural/process
controls driven by builds and kills rather than prompts.

The **approval-binding** family (F4) carries the depth, with 29 genuinely-distinct variants:
a semantic field injected after approval, currency confusables and normalization forms,
whitespace/zero-width/full-width variants, structural collisions, amount collisions, and
lifecycle attacks (an expired or revoked approval). Two variants test the *other* direction, a benign re-render that must hash identically and still execute, confirming the system
neither invalidates on a cosmetic change nor unifies two semantically different payloads.

### 6.4 Statistical power

A zero without an interval is not a result. The denominator is *attack* trials (total minus
`allowed` controls). Aggregate: **0 unauthorized effects in 61 attack trials, 95% CI
[0.0%, 5.9%]** (Wilson; rule-of-three upper bound ≈ 4.9%). We report this as "≤ ~6% at 95%
confidence," never as a bare "0%."

**The pooled rate pools two different definitions of "effect," so we also report it by
channel** (SPEC §1 effect channels; the TCB framing of §9.1 depends on the distinction). A `provider_call` effect is a real external side effect; a gate-channel effect
is tainted *input* passing an upstream gate, which is not itself an external effect. Broken out:

| Effect channel | Families | Attack trials | Unauthorized effects | 95% CI (rule-of-3) |
|---|---|---:|---:|---|
| `provider_call` (external effect) | F4, F5, F8 | 35 | 0 | ≤ 8.6% |
| gate (content/runtime/skill) | F1, F2, F3 | 20 | 0 | ≤ 15.0% |
| chaos (structural/process) | F6, F9 | 6 | 0 | ≤ 50.0% |

The row that carries the paper's core claim is the first: **0 unauthorized external effects in
35 provider-call attack trials.** The gate rows report a different and weaker guarantee (tainted
input was blocked upstream), and pooling them into one headline would overstate the external
result's n. We report both.

Per family, the intervals state what the data supports. F4, the depth
family (n=27), bounds the rate below ~12%; the small-n gate and quorum families bound it only
loosely (F5, n=4, ≤75%; the chaos families, n=3, are uninformative alone). To bound a family
below a rate *r* with zero observed effects requires n ≥ 3/*r* (≥30 for <10%, ≥60 for <5%,
≥300 for <1%). We therefore state, per family, the confidence the current n can support and
decline to pad the set to manufacture a tighter bound, padding would tighten the interval without adding evidence. This is the quantitative form of the "families we could not attack well,
and why" disclosure.

### 6.5 Ablation: each mechanism is necessary

A clean sweep invites the suspicion that the attacks were weak. The ablation study answers it
directly: disable exactly one mechanism, keep everything else, and measure how far the same
attacks now cross the effect boundary. Ablation is available only in the test build, the
mechanism-skipping branch is not compiled into a production artifact, so no deployed system
can be weakened this way, and every ablated trial stamps the disabled mechanism into its
config hash.

| Mechanism disabled | Family | Unauthorized effects (on → off) |
|---|---|---|
| Content firewall | F1 | 0 → 10 |
| Runtime sentinel | F2 | 0 → 5 |
| Skill auditor | F3 | 0 → 5 |
| Approval-binding fingerprint join | F4 | 0 → 14 |
| Two-person control | F5 | 0 → 0 (enforced redundantly; resists single-clause ablation) |
| Posture policy | F8 | 0 → 0 unauthorized (4 *authorized* writes now execute, recorded *allowed*) |

Three findings sharpen the causal claim. **First, defense in depth is measured, not
asserted.** Disabling the F4 fingerprint join lets 14 of 27 mutations execute: not all 27,
because the amount-mutation variants are independently caught by the spend policy. A compound
ablation removing *both* the join and the spend policy converts all 27 (0 → 14 → 27), locating
exactly which layer stops which attack. **Second, removing prevention degrades to detection,
it does not lose the effect:** with the F4 join off, the executed mutation still triggers the
post-hoc reconciliation, so the outcome moves from *prevented* to *detected* rather than to
*undetected*: the three-way outcome model doing its job. **Third, F8's necessity shows in a
different column:** posture blocks a *fully-approved* write under a degraded hold, so disabling
it yields four *allowed* effects (the write was authorized), which is precisely the property
F8 claims. One mechanism resisted clean isolation: the two-person control (F5) is enforced
redundantly at both approval creation and preflight, so a single-clause ablation does not
convert it: a security virtue, reported as a limitation of that ablation rather than dressed
up as a clean conversion.

**No-control ceiling.** With the entire ablatable membrane disabled, **47 of 63** attacks
produce an unauthorized effect (vs 1 in the equivalent governed slice, and 0 in the current
hardened run). This is the number that makes the governed result meaningful: the attacks are
real; the membrane is what stops them.

### 6.6 Calibration: the system grading its own confidence

Because the oracle is independent, it can compare its verdict against the system's
self-reported proof state per trial: a metric no prior agent benchmark reports. On the 41
provider-mediated trials the oracle and the proof state agreed on all 41, with **zero
overclaims** (no cell in which the system reported `verified` while the oracle found the
effect unauthorized) and an expected calibration error of 0.0%.

We report that number with its decomposition rather than as a headline, because the 41 do
not weigh equally. Of them, only **6 are real-effect determinations**: a genuine effect
crossed the boundary and the system made a claim about it (2 approval-binding controls and 4
idempotent replays); all 6 were oracle-confirmed authorized, 0 overclaims. **2** are quorum
failures correctly reported `failed`. The remaining 33 are **non-events** (4 validly-approved
writes that posture blocked, so `verified` but nothing executed) or **abstentions** (29
`manual_review_required`: a "cannot confirm" rather than a verdict). The claim we
stand behind is therefore narrow and exact: **on all 6 trials where a real effect occurred,
the system's proof state matched the independent verdict, with zero overclaims**: not a
sweeping "perfectly calibrated everywhere." The matrix also covers only the 41 provider-call
trials (**56%** of the set); the 32 content/runtime/skill-gate and chaos trials have no proof
state and are excluded. Proof state is a measured output here, never an input to the oracle's
verdict.

### 6.7 Measurement integrity: was the effect log actually exercised? (F10)

The governed campaign produced an *observed* effect (an actual provider-boundary crossing) in
only **6 of 73** trials, Of 41 provider-call trials, 35 were denied before the adapter ran: 31 at the verifier preflight
and 4 by the runtime-posture policy. For a prevented trial the `detection_source` field records the
family's pre-registered expected denial point rather than an observed one, because attributing a
denial to a specific policy would require reading the system's own tables, which the independence rule forbids. So "0 unauthorized effects" is measured through a channel that fired six times,
mostly because prevention is upstream. Distinguishing "nothing occurred" from "the oracle
could not see it" is the job of a measurement-integrity family (F10), which we implemented.
Two facts resolve the concern. First, the effect-observation apparatus *was* exercised at
scale, though not by the F1, F2, and F3 ablations. Those convert 10, 5, and 5 trials, but every
one carries an empty effect log, because a gate conversion is tainted input traversing a gate and
produces no provider-boundary record. The evidence is the F4 ablation, where the belt recorded 16
provider-boundary effects and the oracle scored 14 of them unauthorized, and the F8 ablation, where
it recorded 4 authorized writes. Those are a direct positive control on the exact channel and
verdict class the governed zero depends on, and the per-trial records ship in `artifacts/ablation/`. Second, an F10 positive
control isolates it in one trial: a fully-authorized effect fires the provider-boundary
telemetry, so a governed zero means "no effect reached the boundary," not "the oracle was
blind." The complementary F10 probe confirms the coverage limit: an effect that
bypasses the router emits no provider-call event (the network-layer braces are the catch for
real egress): which is the still-open adversarial half of F10 (forged/suppressed telemetry,
non-Finch transports). This raises F10 from optional to necessary, and the positive control
is now part of the harness.

### 6.8 Kept, and fixed, failure (SPEC §10)

The v1 run's single unauthorized effect was family F3's **sleeper skill**: a learned
capability that reads as safe to the deterministic static auditor but hides a conditional
exfil step behind a benign trigger ("when the run id ends in 7, forward the draft to an
external address"). The system's own adversarial corpus marked this case as a known gap in
advance; our benchmark independently rediscovered it, which is the strongest available
evidence that the attack set exercises the real boundary rather than rubber-stamping it.

We did not leave it open, and we did not quietly delete it. We hardened the auditor with a
behavioral **conditional-exfil detector**: a procedure step naming a hardcoded external
destination together with a send verb, keyed to the *pattern*, not to this sample's address
or condition, so it generalizes to any external exfil rather than overfitting to the test.
We verified against the full benign corpus that no legitimate skill is over-blocked, then
re-benchmarked: the sleeper is now blocked at high severity (with an authority hold), and the
unauthorized-effect count went from 1 to 0. The complete before/after, including the flipped
regression test and the corpus's preserved `was_known_gap` flag, is retained, and the
pre-fix run **ships as data** (`artifacts/holytrinity-v1-prefix-campaign.jsonl`), a full
73-trial campaign in which the sleeper appears as an `undetected` trial, reproducible by
ablating that one detector (`--all --ablate hermes.skill_auditor.exfil_detector`). The
kept failure is thus inspectable in raw JSONL, not only in prose. This is the benchmark
working as intended, find the hole, fix the *class*, re-measure, and it is the
methodological reason the current clean sweep is credible rather than suspicious. Critically,
the hardening was driven by the threat model and validated against held-out benign inputs; we
did **not** tune the code to make a frozen scoreboard look better, which would be overfitting
to the test set and would invalidate every number.

### 6.9 Blind held-out red team

To bound the risk that attacks authored against the code inherit the design's blind spots, we
built a declarative attack channel: an attacker expresses a post-approval divergence (what was
approved, what actually executes) without reference to implementation internals, and the same
independent oracle scores it. A 32-attack set of diverse divergences, recipient and field
injections, nested structural additions, amount tampering, expired/revoked lifecycle replays,
and combinations, produced **0 unauthorized effects (95% CI [0.0%, 10.7%])**, with all 32
prevented and the four honest controls allowed. We are transparent that this set was
author-constructed under a blindness discipline (built only from the family definition and the
§3 definition), not third-party generated; a genuinely independent generation is the strongest
remaining step and is stated as future work. It nonetheless adds validity by exercising the
independent channel at scale on payloads absent from the authored set.

### 6.10 Membrane coverage and out-of-band effects

The network-layer tripwire (§6.2) fires for any real outbound request regardless of the
router; in every correct in-process trial it stayed silent, and a firing during a gate trial
would be the strongest possible finding. The compile-time boundary guard fails the build on a
new un-allowlisted path to the raw execution seam; F6 demonstrates this by planting a
violation and confirming CI rejects it. Neither mechanism claims that no uncovered path can
exist; both make an uncovered path *detectable*. This is prevention where the fence holds and
detection where a path escapes it, reported as such.

### 6.11 Overhead

We measure the cost of the control plane as the added wall-time of a governed action (the full
membrane, policies, verifier preflight, receipt and invariant recording) versus the same
action bypassing the membrane, using mock adapters so no network noise enters. Median governed
latency is **~17 ms**; the bypassed adapter is negligible. The overhead is dominated not by
policy evaluation but by durable authority-proof persistence: the system pays ~17 ms at p50
to make each action's authorization independently verifiable after the fact. We report this
rather than claim a free control plane; the trade is durable, tamper-evident proof for
single-digit-to-low-tens-of-milliseconds per governed action. (p95/p99 and hardware are in
`REPORT.md`.)

### 6.12 False denials

A control plane that denies everything is trivially secure and useless. Over 75 legitimate,
fully-approved actions driven through the real membrane, **zero** were denied: 0/75, 95% CI [0.0%, 4.9%] (Wilson; rule-of-three ≤ 4.0%). The 75 are three
amount configurations of 25 identical repeats each, so the effective sample size is 3, not 75. This is a
synthetic legitimate-action baseline, not a production soak; the paper should report the real
soak-derived rate alongside it when available.

## 7. Limitations

- **Not complete mediation.** Any code path that reaches I/O without crossing the router is
 uncovered; the architecture makes such paths detectable after the fact (network-layer
 tripwire, compile-time boundary guard) but does not claim they cannot exist. We report
 detection posture, not universal prevention.
- **Mock adapters.** Trials use mock provider adapters that traverse the full membrane but
 perform no network I/O. This measures whether the *membrane* authorizes an effect; a
 live-provider run (with real egress and receipt reconciliation) is future work.
- **Partial reproducibility.** We open-source the benchmark (harness, oracle, spec, released
 fixtures) and the result artifacts, but not yet the system under test, so a third party
 cannot re-execute the campaign end-to-end today (§11). The reported numbers are auditable
 from the committed JSONL, and the method is inspectable, but independent re-execution waits
 on the system's release. We treat this as a stated limitation, not a claim of full
 reproducibility.
- **Zero is bounded, not absolute.** We claim "0 observed unauthorized effects across 61
 attack trials of the described set, 95% CI ≤ ~6%," not impossibility.
- **A conformance suite is not a security result.** The system's passing test suite is a
 conformance result; the security result is the measured unauthorized-effect rate.
- **Not exhaustive.** 73 genuinely-distinct attacks is not an exhaustive set; absence of an
 observed effect is not proof of impossibility, and per-family power varies widely (§6.4).
- **Blindness discipline, not independence.** The blind set (§6.9) is author-constructed;
 true third-party generation remains future work.
- **Single-agent, single-hop scope.** The evaluation covers one agent authorizing its own
 actions. Multi-agent delegation chains, where authority is passed hop to hop and must
 narrow but never expand, and where two individually-scoped grants can jointly reconstruct an
 authority neither holds alone (compositional escalation), are out of scope here; the
 compositional-escalation family is deferred to future work. Distinct, cryptographically
 verifiable *agent identity* (as opposed to per-action approval identity) is likewise not
 evaluated. These are first-class questions for agent authorization and we mark their absence
 as a scope boundary, not a silence.

## 8. Threats to validity

- **Construct.** The definition of "unauthorized effect" and its edge cases were fixed in
 writing before the run and are grounded in provider-boundary observables plus an independent
 authorization snapshot, not in the system's verdict.
- **Non-adaptive attack set.** The attack set is pre-registered and static: 73 fixed trials
 and an author-constructed blind channel (§6.9), with no adaptive loop in which an attacker
 observes a denial and reformulates. This is a deliberate trade, pre-registration (which
 guards against tuning attacks to results) and adaptivity are in tension, but "adaptive,
 worst-case adversary" is the standard a security program committee applies, so we name its
 absence rather than leave it implicit. An adaptive campaign is future work.
- **Internal.** The attacks and the system share authorship. Mitigations: family definitions
 written before any model read the implementation; the oracle grounded in external
 observables; scoring rules fixed in advance; the injection observation-trap (§6.2) avoided by
 design; a blind declarative channel (§6.9) that exercises independent payloads; and, the
 strongest structural mitigation, an ablation study and no-control baseline (§6.5) that show
 the attacks convert to effects the moment the mechanisms are removed, which no weak attack set
 could do. LLM assistance in building the harness is disclosed.
- **Oracle observation limits (confirmed, from F10).** The oracle sees effects only through
 two channels: provider-boundary telemetry (the belt) and a network-layer tripwire on the
 HTTP client (the braces). The F10 blind-spot probe confirms the limit directly: a provider
 adapter invoked *outside* the router emits no belt event, the oracle observes nothing, and
 for a mock adapter the braces are silent because there is no real egress. Real network egress
 would trip the braces, but an effect that reaches an external system through a **non-Finch
 transport** (a spawned subprocess, a raw socket, a filesystem relay) or that arrives with
 **forged or suppressed telemetry** would be invisible to both channels. We have *demonstrated*
 the belt's boundary (F10) but not yet *quantified* the residual escape surface; that
 adversarial half of F10 is unbuilt and is the largest open threat to the completeness of the
 unauthorized-effect count. We report it here rather than only scoping it in the harness.
- **External.** One system, one application domain, one provider set. The results do not
 generalize to authority planes in general and we do not imply they do; the transferable
 contribution is the methodology and reference implementation (§9) rather than the measured rate.
- **Overfitting to the benchmark.** The one code change made in response to a finding (the F3
 detector, §6.8) was driven by the threat model and validated against held-out benign inputs,
 and the fix was re-benchmarked as a fresh run; we did not tune the system to a frozen
 scoreboard. The frozen specification, definitions, and oracle were not modified in response
 to any result.

## 9. Generalization and contribution framing

The transferable contribution is a **methodology and a reference implementation**, of which
the Trinity numbers are one instantiation: the independent-oracle design; the three-way outcome
model with an `allowed` control class; the pre-committed unauthorized-effect definition; the
compile-time-inert ablation harness that establishes mechanism necessity; the confusion-matrix
calibration metric; and the honest-n, confidence-interval reporting discipline. These travel to
other authority planes even though the measured rates do not.

**Accountability mapping.** We map each mechanism to a layer and accountable party under the
CoSAI AI Shared Responsibility Framework (SRF) v1.0 [9] (dated 2026-05-26; catalog `last_verified`
2026-07-12). In the evaluated deployment the operating model is **AI-PaaS**: the platform
**self-operates** its agent runtime (the Hermes runtime, an internally-built OpenAI-compatible
service the control plane calls as an authenticated API: not a third-party agent-runtime
vendor, which would be Agent-PaaS), while the **foundation model is consumed from a
third-party provider** (NVIDIA Nemotron endpoints). The authorization control point therefore
sits at the application layer (SRF L3), whose accountable persona is the **application-developer**: the party that builds and operates Trinity and Hermes. Accordingly: the proposal/authorization
split, the deterministic policy stack (enforcement), and durable proof (auditability) are all
L3 controls accountable to the application-developer. The **foundation model's own safety
obligations**: alignment, refusal behavior, base-model content safety, robustness to
adversarial inputs, are recorded **separately** as an upstream **L5** obligation (the AI
Model Provider layer), accountable persona **model-provider** (here NVIDIA), not folded into
Trinity's row; this L3↔L5 separation is the paper's premise, since Trinity
treats the third-party model as untrusted precisely because it does not own the model's
safety. (Distinct from both is **L2**, the data layer, accountable to the data-provider: the
integrity of content Trinity *ingests* is an L2 concern, which Trinity's content firewall (F1)
mitigates at L3: a different obligation from the model's own behavior.) Human
approval is not a single "party" but an **oversight tier** in the SRF's override model
(T1 to T5): the approver's authority is explicitly assigned per action class, and the accountable
persona is the application-developer for the gate's *existence and binding* and the
ai-system-user (the approver) for the *decision*. We deliberately avoid the earlier draft's
"platform-owner" label, which is not an SRF persona. The paper makes no vertical-domain claim; where one is made, CoSAI vertical control schemas are
independently-proposed extensions to SRF v1.0 rather than part of the official release, and
that caveat would travel with the claim.

**On certification [10].** This benchmark produces a low unauthorized-effect
rate; it does **not** certify Trinity as secure and is not offered as certification. No
finite, pre-registered attack set can establish a security property in general (§7); the
contribution is a *measurement methodology and a bounded result*, not a seal.

**Three gaps this work closes, stated against a published corpus rather than against the
literature in general.** The CoSAI AI-agentic principles catalog [13] synthesizes 121 principles
from 41 sources and publishes a `gap_index` recording, per section, the classic principle its
source material does not address. Three of those entries name gaps this paper closes, so each
claim below is checkable against a fetchable file rather than asserted.

First, section `zero-standing-privilege`, gap `sch-2`: "Continuous re-verification assumes a clean
allow/deny answer at every check; nothing here says what an agent's access-control layer should do
when that answer is unclear." The seven-state proof model is a named posture for exactly that case,
and §6.6 shows it carrying load: 29 of 41 provider-mediated trials resolve to
`manual_review_required`, an explicit abstention rather than a manufactured verdict. We note the
limit: the gap also names the policy-engine-unreachable case, which §12 lists as unbuilt.

Second, section `human-oversight`, gap `nist-p7`: "No sources weigh approval-gate latency costs
against risk prevention." We report both halves together, ~17 ms of median governed latency (§6.11)
against a 0/75 false-denial rate (§6.12). We are precise about the claim: the trade-off itself *is*
named in the classic catalog, as `nist-p7`, "identify potential trade-offs between reducing risk
and increased costs." What the corpus records as absent is its *instrumentation at an agent
approval gate*. Two qualifications belong with it: the p95 and p99 are 57.8 and 81.3 ms, and a gate
too slow to use is a tail property the median does not speak to; and the false-denial figure has an
effective sample size of three (§6.12).

Third, section `incident-response`, gap `ms-risk-8`: "No verification that quarantined agents remain
inert; cutting an agent off from the network is not the same as confirming it has stopped acting."
§5 and family F9 address this directly on the BEAM, where a killed worker is a terminated process
rather than an unreachable one, and §5 bounds the claim: work the worker already enqueued on the
durable job runtime survives the kill and is unmeasured here.

### 9.1 Trusted computing base: minimizing trusted elements, measured (`nist-p25`)

Nine mechanisms plus a layered policy stack plus a seven-predicate verifier looks like a
large trusted base, in apparent tension with *minimize the system elements to be trusted* (NIST SP 800-27 `nist-p25`, [14]), and with economy of mechanism [2]. The tension resolves once "number of mechanisms" and
"size of the trusted computing base" are kept distinct, and our ablation data measures the
distinction rather than asserting it.

**Name the kernel.** The §3 invariant depends on a small set of elements whose correctness is
*necessary* for it to hold: the mediation membrane (`ToolRouter`), the approval-binding join
and its canonical payload hash (`AuthorityAssurance`, family F4 in the matrix), and the
durable authority store. Three, maybe four. That is the trusted computing base. Everything
whose failure *cannot by itself* admit an unauthorized external effect is outside it.

**Classify the rest as surface reducers.** The content firewall (F1), runtime sentinel (F2),
and skill auditor (F3) sit *upstream* of the kernel; their job is to keep tainted material out
of model context. If all three fail completely, what reaches the kernel is a compromised model
proposing violating actions: which is the paper's stipulated premise anyway (§1). Their
failure enlarges the *proposal* stream; it does not enlarge the set of things that must be
correct for the invariant. Posture (F8), spend, and coapproval (F5) sit *behind* the join as
independent layers, and the compound ablation already shows their independence (0→14→27, §6.5).

**Measure the boundary** (`--tcb`). We ablate each element and break the admitted effects out
by effect channel. A surface reducer's failure should admit effects only in its own gate
channel and *zero* provider-call (external) effects; only a kernel element's failure should
admit a provider-call effect. That is exactly what the data shows:

| Ablated element | Role | Effects admitted | Channel | Provider-call (external) |
|---|---|---:|---|---:|
| Content firewall (F1) | surface reducer | 10 | content_gate | **0** |
| Runtime sentinel (F2) | surface reducer | 5 | runtime_gate | **0** |
| Skill auditor (F3) | surface reducer | 5 | skill_gate | **0** |
| Approval-binding join (F4) | **kernel** | 14 | provider_call | **14** |

Removing a surface reducer admits tainted input but produces **no unauthorized external
effect**; removing a kernel element produces fourteen. This is `nist-p25` satisfied and
*demonstrated*: the trusted base is small (three or four elements), and the other mechanisms
buy defense in depth at the cost of code, not trust. It also resolves an intra-catalog tension: layered security with no single point of
vulnerability (`nist-p16`) pulls against minimizing the system elements to be trusted
(`nist-p25`), and both are classic principles; the resolution is that layers
*outside* the kernel do not enlarge the TCB. The economy-of-mechanism half is that the kernel's
fence is small enough to be **machine-checked at compile time** (§5), not upheld by convention.
(Had a firewall ablation produced a provider-call effect, that firewall would be *in* the TCB
and we would say so; it did not.)

### 9.2 Candidate contributions to the principles corpus

Beyond the two field-wide blind spots above, we flag four principles this work either names or
demonstrates that we did not find in a 41-source secure-AI corpus (provisional; offered for
triage, not asserted as settled). **Architectural:** (i) a verifier emits a *state* that
separates genuine uncertainty from a confident verdict rather than reporting a binary pass or
fail (§4); (ii)
degraded-mode posture blocks an *individual authorized action*, a finer grain than
stop-the-system (§6.5, F8). **Methodological, and in our view the stronger candidates because
they travel to any authority plane regardless of implementation:** (iii) a verifier's
self-reported confidence must be *independently calibrated* against ground truth the verifier
cannot see (§6.6); and (iv) the *evaluation apparatus itself* must be adversarially tested: an
unexercised observation channel cannot ground a null result (§6.7, F10). We claim these as
candidates rather than settled principles, and note that four is already at the edge of what one
paper should assert.

## 10. Related work

By control class:

- **Reference monitors and runtime policy enforcement.** The invariant of §3 is a reference
 monitor in the sense of Anderson [1]: always invoked, small enough to be analyzed, and
 tamper-proof. This system satisfies the first two and provides tamper-evidence rather than
 tamper-proofness, a gap §7 states directly. It mediates every access. The seven properties instantiate Saltzer and Schroeder's complete mediation,
 least privilege, and fail-safe defaults [2]; §6.5's compound ablation is direct evidence for layered, redundant enforcement, which their separation-of-privilege principle anticipates. Trinity's contribution is not the concept but its *measurement* at
 the agent-authorization boundary.
- **Actor and virtual-actor runtimes.** The process-vs-data ownership of §5 rests on the actor
 model [3] and Erlang/OTP supervision [4]; virtual-actor systems such as Orleans [5] supply
 the ephemeral-process/durable-state split Trinity turns into an *authority* property. Those
 runtimes supply isolation and lifecycle; they do not adjudicate authorization, which is the
 property we evaluate.
- **Durable workflow systems** [6] supply exactly-once-ish orchestration and retries; Trinity
 reuses a database-backed job runtime for reconciliation but adds the authorization join and
 the seven-state proof model those systems do not provide.
- **Prompt-injection defenses and benchmarks.** We take the misbehavior premise from the
 indirect-prompt-injection and jailbreak literature [7, 8] and the LLM risk taxonomy of [12],
 and position downstream of them: where those works measure whether a model *can be made to
 propose* a violating action, we measure whether a proposal *becomes an effect*. On the
 limits of any such benchmark as certification, see [10] and §9.
- **Agent SDKs / governance framing.** Most directly, this work extends Hostetler's *Jido*
 architecture study [11]: Jido supplies the model-independent agent/controller/runtime
 separation and the framing that decision, effect, and runtime boundaries should be explicit
 and composable; Trinity is one application-level authority layer over that substrate, and
 this paper is its adversarial evaluation.

Trinity composes with, rather than competes against, model-level agent runtimes: it is the
application-level authority layer such runtimes explicitly leave to the application.

## 11. Reproducibility and the disclosure boundary

**What we open-source now (the benchmark and its results, not the system under test).** The
public artifact at https://github.com/ScriptKittyOS/HolyTrinity-Benchmark contains: the frozen
specification and the seven verified properties as English predicates; the family definitions
and attack taxonomy; the independent oracle and the harness (aggressor, runner, scoring, the
ablation/TCB/measurement-integrity/blind drivers); the released fixtures (F4/F5/F8/F9, per the
split below); and the **committed result artifacts**: the campaign JSONL, the v1-prefix
reconstruction, and the family table as data. This makes the *results* auditable (every number
in the paper follows mechanically from the JSONL) and the *method* inspectable.

**What is not yet released, and what that costs reproducibility.** The **system under test**
(the Trinity control plane itself: the membrane, the verifier internals, the policy stack)
is **not** open-sourced at this time. The harness therefore references code that is not public,
so a third party **cannot re-execute the campaign end-to-end today**; reproduction is
*partial*, results-verifiable and method-inspectable now, fully re-executable when the system
is released (tied to the filing schedule). We state this plainly rather than imply a
completeness the artifact does not yet have.

**Held pending counsel:** the system under test itself (for now); and, on the eventual
release, these internals remain redacted, invariant registry identifiers, versions, and
severities; canonicalization algorithm details (published on release per the open-design
commitment in the paragraph below); approval-fingerprint and execution-envelope schema
internals; verifier sweeper queries; receipt-reconciliation logic; violation-response
internals; runtime-sentinel pattern sets and thresholds; policy conditions and freeze-scope
rules; receipt-chain schema and hash inputs.

**Two of those withholdings are not equivalent, and we say so (the open-design principle of [2]).** The runtime-sentinel and content-firewall pattern sets are *detection
signatures*; withholding a signature list does not weaken the mechanism against an adversary
who does not have it, so holding them is conventional and not an open-design violation. The
**canonicalization algorithm** is different in kind: the security of the approval binding, F4, the paper's deepest and most-tested family, *depends on* it, and its correctness cannot
be independently reviewed without it. We flag this explicitly rather than list it beside the
signatures: the algorithm is held only for the pending filing, and we commit to publishing it
(or an independently-checkable specification of it) on release, because a security property
that rests on a secret algorithm is what open design warns against.

**Fixture release (pre-committed, `SPEC.md` §11):** release fixtures for families that expose
no internals (approval binding, coapproval, posture, process lifecycle, membrane-bypass
positive control); hold the content, runtime, and skill fixtures, whose release would leak
firewall patterns, sentinel patterns, and audit heuristics; publish the taxonomy and results
for all nine and name which fixtures are held and why.

## 12. Conclusion and future work

Under adversarial load, an agent governed by an authority-bound control plane was induced to
propose violating actions in the large majority of trials while zero unauthorized external
effects occurred across 61 attack trials (95% CI ≤ ~6%). The result is credible not because it
is clean but because the ablation and no-control baselines show the trusted kernel does the work and the surrounding layers independent (47/63 attacks convert with the membrane
off), the one effect the benchmark ever leaked was
fixed in the open and re-measured, the system's proof state matched an independent oracle on
all six trials where a real effect occurred with zero overclaims (§6.6: not a blanket
calibration claim), and every rate carries a confidence interval. Future work: a truly
independent (third-party) blind generation; a live-provider run with real egress and receipt
reconciliation; a production-soak-derived false-denial rate; transport-level oracle-snapshot
independence over a committed benchmark database; growth of the genuinely-distinct attack set
where distinct depth remains (further canonicalization forms; a compositional-escalation
family); and the two pre-registered v2 families, measurement-integrity (attacking the oracle's
own telemetry ground truth) and control-plane liveness (sweeper starvation and unclearable
freeze).

## References

Widely-cited canonical sources.

1. J. P. Anderson. *Computer Security Technology Planning Study.* ESD-TR-73-51, USAF
 Electronic Systems Division, 1972. (Reference-monitor concept.)
2. J. H. Saltzer and M. D. Schroeder. "The Protection of Information in Computer Systems."
 *Proceedings of the IEEE*, 63(9):1278–1308, 1975. (Complete mediation, least privilege,
 fail-safe defaults, separation of privilege, open design.)
3. C. Hewitt, P. Bishop, and R. Steiger. "A Universal Modular ACTOR Formalism for Artificial
 Intelligence." *IJCAI*, 1973.
4. J. Armstrong. *Making Reliable Distributed Systems in the Presence of Software Errors.*
 PhD thesis, KTH Royal Institute of Technology, 2003. (Erlang/OTP supervision.)
5. P. A. Bernstein, S. Bykov, et al. "Orleans: Distributed Virtual Actors for Programmability
 and Scalability." Microsoft Research Technical Report MSR-TR-2014-41, 2014.
6. S. Burckhardt et al. "Durable Functions: Semantics for Stateful Serverless." *Proc. ACM
 Program. Lang.* (OOPSLA), 2021.
7. K. Greshake et al. "Not What You've Signed Up For: Compromising Real-World LLM-Integrated
 Applications with Indirect Prompt Injection." *ACM Workshop on Artificial Intelligence and
 Security (AISec)*, 2023.
8. F. Perez and I. Ribeiro. "Ignore Previous Prompt: Attack Techniques for Language Models."
 *NeurIPS ML Safety Workshop*, 2022.
9. Coalition for Secure AI (CoSAI). *AI Shared Responsibility Framework (SRF) v1.0.* 2026-05-26 (catalog
 `last_verified` 2026-07-12).
10. Berryville Institute of Machine Learning (BIML). *No Security Meter for AI.* 2026-05-13.
 `berryvilleiml.com/results/no-security-meter-ai.pdf`. (The position that a benchmark
 measures but does not certify a system as secure.)
11. M. Hostetler. *Governing Risk with Agents: An Architecture Study of Jido on the BEAM.*
 Personal communication, cited **with the author's permission** at pinned revision
 `17fbce2b1c53a46093be92dc59561e2a18b8f775`; archival identifier pending. (Not a versioned
 publication; we do not depend on a mutable link.)
12. Berryville Institute of Machine Learning (BIML). *An Architectural Risk Analysis of Large
 Language Models.* 2024. (LLM risk taxonomy.)
13. Coalition for Secure AI (CoSAI). *AI-agentic security principles catalog*, 121 principles
 synthesized from 41 sources (2019-2026) across 22 sections, with a published `gap_index`.
 `https://aisharedresponsibility.com/data/ai-agentic-principles.json`
 (Source of the three `gap_index` entries quoted in §9.)
14. Coalition for Secure AI (CoSAI). *Classic security principles catalog*, 87 entries
 normalized from Saltzer and Schroeder, NIST SP 800-27, ISO 27001, and CIS Controls.
 `https://aisharedresponsibility.com/data/security-principles.json`
 (Source of the `nist-p16` and `nist-p25` identifiers used in §9.1.)
15. A. Croft. *The Model Proposes, the System Authorizes: An Authority Control Plane for AI
 Agents on the BEAM.* Manuscript dated 29 July 2026. Zenodo,
 `https://doi.org/10.5281/zenodo.21754762` (concept DOI, which resolves to the current
 version; v1.1 is `10.5281/zenodo.21764616`). The earliest deposit is timestamped 2026-08-02,
 later than this paper's campaign, so it gives the companion a citable identifier without
 corroborating the 29 July date the manuscript states. Source in the artifact repository at `papers/the-model-proposes-the-system-authorizes.tex`.
 (Companion architecture paper. States the threat model, the security invariant, and the
 nine mechanisms this paper evaluates, and pre-registers this evaluation's primary metric,
 secondary metrics, attack classes, and falsification criterion.)

---

### Appendix A, reproduction (two tiers)

**Tier 1, verify the results now, from the public artifact (no system under test needed).**
The reported numbers are recomputable from the committed JSONL alone: `family-table.json` is
the §6.3 table as data, and the campaign / v1-prefix JSONL carry every per-trial record the
tables aggregate. A reader can re-derive the family table, the confidence intervals, the calibration decomposition, and the effect-channel split of §6.4 without running any of Trinity.

**Tier 2, re-execute end-to-end (requires the system under test, not yet public).** The
commands below drive the real membrane and therefore need the Trinity control plane, which is
held for now (§11); they become runnable when the system is released.

```bash
MIX_ENV=test mix holytrinity.run --run-id paper --all --require-clean # 73 trials (clean tree)
MIX_ENV=test mix holytrinity.run --run-id paper --report # family table + CIs + calibration
MIX_ENV=test mix holytrinity.run --run-id abl --ablation-study # per-mechanism necessity
MIX_ENV=test mix holytrinity.run --run-id abl --compound # F4 join + spend (0->14->27)
MIX_ENV=test mix holytrinity.run --run-id base --baseline # no-control ceiling (47/63)
MIX_ENV=test mix holytrinity.run --run-id tcb --tcb # TCB boundary by effect channel (§9.1)
MIX_ENV=test mix holytrinity.run --run-id blind --blind-set blind/blind-set-01.json
MIX_ENV=test mix holytrinity.run --overhead # latency percentiles
MIX_ENV=test mix holytrinity.run --false-denials # legitimate-action denial rate
```

The exact commit, full percentile table, and hardware are recorded in `REPORT.md`, regenerated
from a real run. Machine-readable companions ship alongside: `artifacts/family-table.json`
(the §6.3 table as data, with the attack/control denominator stated), the committed campaign
JSONL in `artifacts/` (each with a `_meta` provenance line; the v1 file is a labelled
reconstruction), and `CITATION.cff`. On release:
https://github.com/ScriptKittyOS/HolyTrinity-Benchmark
