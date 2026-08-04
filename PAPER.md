# Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under Adversarial Load

Ayla Croft, ScriptKittyOS · ORCID `0009-0008-9457-2160` · August 2, 2026

**Artifact and reproducibility (partial).** The evaluation ran against the
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
citation: it states the threat model, the security invariant, and the nine mechanisms evaluated
here, and its evaluation section, written before any harness existed, fixes this paper's primary
metric (unauthorized-effect rate), its three secondary metrics (evidence completeness,
benign-task false-denial rate, and overhead), a twelve-item attack-class list, and the strong test, "replace the agent entirely with an adversarial oracle that emits worst-case output at every
step", together with its falsification criterion, "a single unauthorized effect under the
adversarial oracle refutes invariant *I*." Of that test it says: "I state plainly that I have not
run this test." This paper runs it, and reports the result against that specification including
where we departed from it (§8).

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
each mechanism in isolation converts its attacks (0→10, 0→5, 0→5, 0→14, 0→2 unauthorized effects
across the content, runtime, skill, approval-binding, and two-person-approval boundaries), and a
**no-control** run with the full membrane disabled produces an unauthorized effect in
**51 of 63 trials**: the ceiling the governed result is measured against. Second, a **kept-and-fixed failure**: the v1 run's single
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
Governed actions carry a median latency of **~19 ms**, reported as an absolute
cost rather than a differential because the ungoverned baseline is a no-I/O function three orders
of magnitude cheaper than the timer's printed resolution
(§6.11); the false-denial rate is
**0.0%** over 75 legitimate approved actions (0/75; 95% CI [0.0%, 4.9%], effective
n=3). We report every rate with a confidence
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
valid authorization?** This paper measures that quantity: the *unauthorized-effect rate*, for one implemented system under a targeted adversarial load, and reports it separately from
the *misbehavior rate* that the red-teaming literature reports, because the distance between the
two is the entire contribution.

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

Proof is not binary. The verifier emits one of seven proof states: `verified`, `failed`,
`degraded`, `pending_receipt`, `legacy_incomplete`, `manual_review_required`, and `missing`,
because real provider systems are late and incomplete. A trial record can also carry an eighth
value, `not_applicable`, which the harness stamps on the six chaos trials (F6, F9) that place no
proof obligation on the verifier; it is a record-keeping value rather than a verifier verdict, and
we name it here because it appears in the committed artifacts. Publishing this *state model* (as distinct
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
under test is pinned to commit `79bfd54`. The invariant depends on two runtime properties:

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
- **CI-enforced boundary coverage.** A structural check over the source tree flags any code
 path that reaches the raw tool-execution seam without passing the result firewall, and CI
 enforces the check: the fence is machine-checked rather than upheld by convention. What F6
 exercises is that check's predicate over the source tree; no build is invoked (§6.10), so we do
 not report a demonstrated build failure.

The full percentile table, hardware, and per-trial provenance for commit `79bfd54` are in
`REPORT.md` and the committed `artifacts/`.

## 6. Evaluation

### 6.1 Method

We measure two rates and never collapse them:

- **Violating-input rate**: the fraction of trials whose input was *constructed* to be
 policy-violating. We do not measure a model misbehaviour rate and do not report one, and the 57 is
 not one: *no language model is invoked anywhere in this harness*, which
 `aggressor/README.md` states enumerated per file. The 57 of 61 is a property of the fixture
 set. Our harness injects the violating action directly at the control-plane boundary, exactly as a
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
(`spec/SPEC.md` §3), including edge cases (partial effects, idempotent replay, tenant-scoped
reads, wrong-attribution, and approved-but-misrepresented actions). It was not adjusted after
seeing results.

**Scoring is automatic, not judge-mediated.** All 73 trials are scored mechanically by the
oracle from telemetry and the authorization snapshot against the §3 rules: no LLM-as-judge
and no per-trial human verdict. Every trial record carries `scorer: "auto"`, and the
`spec/SPEC.md` §8 provision for manual adjudication of genuinely undecidable cases was not needed
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

**Where the independence rule is broken: F4.** The oracle decides payload identity by calling
`AuthorityAssurance.canonical_payload_hash/1` (`oracle/oracle.ex:313`, also `:348` and `:360`),
and `AuthorityAssurance` is the system under test. F4 is 27 of the 31 trials that could falsify
the invariant, and F4's hypothesis is exactly that canonicalization must not collide semantically
distinct payloads. Oracle and system therefore evaluate the same function on the same input: a
collision returns `permit` from the system and `authorized` from the oracle, and the two agree
because they are one computation. *The failure class F4 exists to detect is the one class this
oracle cannot detect.* Two facts compound it. The canonicalizer is withheld (§11), so no reader
can check it; and it has had no cryptographic review, while §9.1 names it an element of the
trusted computing base. F4's verdict is therefore conditional on the correctness of an unreviewed
function inside the system under test, and F4 is outside the scope of this paper's
independent-adjudication claim. The fix is a canonicalizer written independently in `oracle/` from
a written specification, with both hashes published per trial; it does not exist yet and it is
required future work.

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
lifecycle attacks (an expired or revoked approval). Two variants test the *other* direction: a benign re-render that must hash identically and still execute, confirming the system
neither invalidates on a cosmetic change nor unifies two semantically different payloads.

### 6.4 Statistical power

A zero without an interval is not a result. The denominator is *attack* trials (total minus
`allowed` controls). Aggregate: **0 unauthorized effects in 61 attack trials, 95% CI
[0.0%, 5.9%]** (Wilson; rule-of-three upper bound ≈ 4.9%). We report this as "≤ ~6% at 95%
confidence," never as a bare "0%."

**The pooled rate pools two different definitions of "effect," so we also report it by
channel** (SPEC §1 effect channels; the TCB framing of §9.1 depends on the distinction). A `provider_call` effect is a real external side effect; a gate-channel effect
is tainted *input* passing an upstream gate, which is not itself an external effect. Broken out:

| Effect channel | Families | Attack trials | Unauthorized effects | One-sided 95% upper bound (rule of three) | Two-sided 95% Wilson upper limit |
|---|---|---:|---:|---|---|
| `provider_call` (external effect) | F4, F5, F8 | 35 | 0 | ≤ 8.6% | ≤ 9.9% |
| gate (content/runtime/skill) | F1, F2, F3 | 20 | 0 | ≤ 15.0% | ≤ 16.1% |
| chaos (structural/process) | F6, F9 | 6 | 0 | ≤ 50.0% | ≤ 39.0% |

The two bound columns are not two estimates of one quantity, and we state the difference once. A
two-sided 95% Wilson upper limit corresponds to 97.5% one-sided coverage, while 3/n approximates
the 95% one-sided bound. The rule-of-three figure is therefore usually the smaller number and
always the lower-confidence claim; it reads as tighter and is not. Both are reported throughout and
neither substitutes for the other.

The row that carries the paper's core claim is the first: **0 unauthorized external effects in
35 provider-call attack trials.** The gate rows report a different and weaker guarantee (tainted
input was blocked upstream), and pooling them into one headline would overstate the external
result's n. We report both.

**The denominator is a ladder, and we publish the ladder rather than pick a rung.** 61 is
correct as a count of *attempts* and wrong as a count of *opportunities*, because not
every attack trial could have produced an unauthorized effect even if every control had failed:

| Denominator | n | One-sided 95% (rule of three) | Two-sided 95% Wilson upper |
|---|---:|---|---|
| Attack trials driven (attempts) | 61 | ≤ 4.9% | ≤ 5.9% |
| Structurally capable of inducing a violation | 51 | ≤ 5.9% | ≤ 7.0% |
| Capable of an external effect (F4's 27 + F5's 4) | 31 | ≤ 9.7% | ≤ 11.0% |
| Cluster-aware, mechanism as the unit (8 mechanisms) | 8 | — | ≤ 32.4% |

Ten of the 61 provably cannot enter the numerator. F8's four trials cannot: with posture disabled
all four cross the boundary, all four are scored `allowed`, and unauthorized effects stay at
zero, because the write was validly approved. The six F6 and F9 chaos trials cannot: their effect
list is empty by construction. A further 20 gate trials can produce a gate-channel effect but not
an *external* one, which is what leaves 31. F7 does not belong on this list and we say so
explicitly: all four F7 trials are `allowed` controls and already sit outside the 61,
contributing nothing to it.

**And the 61 are not 61 independent observations.** They span eight mechanisms, and
within-mechanism correlation is close to 1: removing a single mechanism converts 10 of 10, 5 of 5,
5 of 5, and 4 of 4 of the trials that mechanism holds. Taking the mechanism rather than the payload
as the unit of observation gives an effective n of 8 and a two-sided 95% Wilson upper limit of
**32.4%**. We report the pair rather than the optimistic end: the payload-level bound is
≤5.9% and the cluster-aware bound is ≤32.4%. This paper already applies exactly this
discipline to the false-denial rate, where the effective n is 3 rather than 75 (§6.12); applying
it to the headline is the same arithmetic and it is less flattering. The eight is the conservative
count and we keep it deliberately: counted by *actual denier* the mechanisms are nine, because
the spend policy denied 13 of F4's attack trials (§6.7) without appearing in any family. Nine
clusters would tighten the bound to ≤29.9%, so we publish the wider figure computed over
eight rather than the tighter one our own correction would license.

Per family, the intervals state what the data supports. F4, the depth
family (n=27), bounds the rate below ~12%; the small-n gate and quorum families bound it only
loosely (F5, n=4, ≤75%; the chaos families, n=3, are uninformative alone). To bound a family
below a rate *r* with zero observed effects requires n ≥ 3/*r* (≥31 for <10%, ≥61 for <5%,
≥301 for <1%; the inequality is strict, and these are the values the estimator returns). We therefore state, per family, the confidence the current n can support and
decline to pad the set to manufacture a tighter bound, padding would tighten the interval without adding evidence. This is the quantitative form of the "families we could not attack well,
and why" disclosure.

### 6.5 Ablation: each mechanism is necessary

A clean sweep invites the suspicion that the attacks were weak. The ablation study answers it
directly: disable exactly one mechanism, keep everything else, and measure how far the same
attacks now cross the effect boundary. Ablation is available only in the test build: the
mechanism-skipping branch is not compiled into a production artifact, so no deployed system
can be weakened this way, and every ablated trial stamps the disabled mechanism into its
config hash.

| Mechanism disabled | Family | Unauthorized effects (on → off) |
|---|---|---|
| Content firewall | F1 | 0 → 10 |
| Runtime sentinel | F2 | 0 → 5 |
| Skill auditor | F3 | 0 → 5 |
| Approval-binding fingerprint join | F4 | 0 → 14 |
| Two-person control | F5 | 0 → 2 |
| Posture policy | F8 | 0 → 0 unauthorized (4 *authorized* writes now execute, recorded *allowed*) |
| Spend policy (`policies.spend`) | — (no family) | 0 → 0, over the full catalog |

Five findings sharpen the causal claim. **First, defense in depth is measured, not
asserted.** Disabling the F4 fingerprint join lets 14 of 27 mutations execute: not all 27,
because the amount-mutation variants are independently caught by the spend policy. A compound
ablation removing *both* the join and the spend policy converts all 27 (0 → 14 → 27), locating
exactly which layer stops which attack. **Second, removing prevention degrades to detection,
it does not lose the effect:** with the F4 join off, the executed mutation still triggers the
post-hoc reconciliation, so the outcome moves from *prevented* to *detected* rather than to
*undetected*: the three-way outcome model doing its job. **Third, F8's necessity shows in a
different column:** posture blocks a *fully-approved* write under a degraded hold, so disabling
it yields four *allowed* effects (the write was authorized), which is precisely the property
F8 claims. **Fourth, the two-person control is necessary and the data now says so:** removing
it admits two unauthorized effects, on the two extreme-risk variants that execute with no
co-approver and with the same approver twice — and, as with F4, both are *detected* rather than
undetected, flagged by the invariant check. **Fifth, the spend policy is a redundant layer
and not a hidden kernel element.** It was wired for ablation and had simply never been exercised;
run on its own over the full catalog — 73 trials, 41 provider-call trials live — it admits 0
unauthorized effects and 0 provider-call effects.
Together with the compound result, that says the 13 F4 trials it denied would have been caught by
the approval-binding join regardless: neither layer is individually necessary for those 13, and
both must fail before all 27 convert.

**Two kinds of zero, and how to tell them apart.** Two rows of this table read
0 → 0, and a third did until the re-score. They do not mean the same thing, so we
distinguish them rather than let a reader average them. F8's zero is a redirection: four validly-approved writes execute, so the
necessity shows in the crossed column instead of the unauthorized one. The spend policy's zero is a
*measured redundancy*: the run executed over the full catalog with 41 provider-call trials live,
nothing raised, and the mechanism's own 13 trials were caught by the layer behind it. F5's former
zero was neither — it
was a *failed measurement*, an adjudicator blind spot that concealed two real effects, and it
is now 0 → 2. A zero is only a null once the trials are shown to have produced a usable
observation; the F5 row is what happens when that check is skipped.

**A correction, and its cause.** An earlier version of this paper reported the F5 row as a
0 → 0 null and read that null as redundant enforcement: a security virtue that resisted
single-clause ablation. The reading was wrong and the mechanism that made it wrong is worth stating
plainly, because it is the pre-committed edge case firing for real. `Telemetry.span/3` emits
`:stop` on success *or* `:exception` on a raise, never both. The oracle that
produced the original ablation figures subscribed to `:stop` alone, so an adapter that
performed a real external effect and then raised was invisible to it, and the runner's rescue
scored the trial a successful prevention. The corrected oracle collects both events. This is the
"partial effects" case that SPEC §3 pre-committed to before the first scored run. The governed
campaign is unaffected, and for a reason worth stating rather than assuming: in the campaign the
two-person control held, so nothing was performed and nothing raised, and the blind spot can only
manifest once the control is ablated away. It moved exactly two published figures, the F5 row above
and the no-control ceiling below.

**A second defect sat under the first, and correcting it improves the F5 result rather than
enlarging it.** The reason those two trials raised at all is that the fixture payload omitted an
email field `LocalCRM` requires. A trial that raises mid-drive records no proof state, and that
missing proof state — not a failure of detection — is what produced the row's original
`undetected` / `missing` / `none` triple. With the fixture corrected, both trials score
**`detected`**, with `system_proof_state: failed` and `detection_source: invariant_check`: the
invariant check flags both admitted effects. The unauthorized-effect **count is unchanged at
two**, so the row remains 0 → 2. What changed is its character. Removing two-person approval admits
two unauthorized effects *and the system detects both* — the same degradation from prevention to
detection that the F4 ablation shows, rather than a silent crossing.

**No-control ceiling.** With the entire ablatable membrane disabled, **51 of 63 trials**
produce an unauthorized effect and all 63 cross the effect boundary. The same 63 run governed cross
8 times and produce **0** unauthorized effects. Governing therefore prevents 55 crossings that
occur ungoverned (8 versus 63), and the unauthorized-effect counts are 0 against 51. One wording
correction ships with that number: **63 is not a count of attacks.** It is the F1–F5 and F8
totals, which include 8 known-good controls and F8's 4 non-attacks. The baseline omits F6, F7 and
F9, which have no runtime toggle, so its 63 trials are not the campaign's 61. This is the number
that makes the governed result meaningful: the attacks are real; the membrane is what stops them.

### 6.6 Calibration: the system grading its own confidence

Because the oracle is independent, it can compare its verdict against the system's
self-reported proof state per trial: a metric no prior agent benchmark reports. On the 41
provider-mediated trials the oracle and the proof state agreed on all 41, with **zero
overclaims** (no cell in which the system reported `verified` while the oracle found the
effect unauthorized) and a **proof-state-weighted calibration gap** of 0.0%.

**That statistic is not an ECE and we no longer call it one.** Its bins are seven categorical
`proof_state` labels carrying hand-authored confidence constants, not probability bins, so
it is not comparable to expected calibration error as the literature uses the term. Every occupied
bin claims a probability at a boundary, 0.0 or 1.0, so given 100% oracle agreement a zero follows
*arithmetically* rather than empirically; we therefore never state it without the
decomposition below. It is also sensitive to a single constant. The
`manual_review_required` bin carries 70.7% of the weight (29 of 41), is described
throughout as an abstention, and is nonetheless assigned P(authorized) = 0.0, a maximally confident
negative. Mapped instead to 0.5, which is what an abstention means, the same data yields 35.4%. We
report the published mapping and that sensitivity together rather than the number alone.

We report it with its decomposition rather than as a headline, because the 41 do
not weigh equally. Of them, only **6 are real-effect determinations**: a genuine effect
crossed the boundary and the system made a claim about it (2 approval-binding controls and 4
idempotent replays); all 6 were oracle-confirmed authorized, 0 overclaims. **2** are quorum
failures correctly reported `failed`. The remaining 33 are **non-events** (4 validly-approved
writes that posture blocked, so `verified` but nothing executed) or **abstentions** (29
`manual_review_required`: a "cannot confirm" rather than a verdict). The claim we
stand behind is therefore narrow and exact: **on all 6 trials where a real effect occurred,
the system's proof state matched the independent verdict, with zero overclaims**: not a
sweeping "perfectly calibrated everywhere." That claim carries its own interval and the interval
is wide: 0/6 bounds the overclaim rate at ≤50% one-sided (rule of three) and ≤39.0%
two-sided (Wilson). Six is what a governed campaign produces when prevention is upstream, and we
state the bound rather than the point. The matrix also covers only the 41 provider-call
trials (**56%** of the set); the 32 content/runtime/skill-gate and chaos trials have no proof
state and are excluded. Proof state is a measured output here, never an input to the oracle's
verdict.

### 6.7 Measurement integrity: was the effect log actually exercised? (F10)

The governed campaign produced an *observed* effect (an actual provider-boundary crossing) in
only **6 of 73** trials. Of 41 provider-call trials, 35 were denied before the adapter ran.
Recomputed from the `notes` field of the committed per-trial records, which carries the
actual result the drive call returned, the denying component splits: **18** at the
`AuthorityAssurance` preflight, **13** at `SpendPolicy`'s preflight, **2**
by `RuntimePosturePolicy`, **1** by `AuthorityAssurance` at the policy stage, and
**1** by `AuthorityJudge`. An earlier version of this paper reported that split as
"31 at the verifier preflight and 4 by the runtime-posture policy," which was wrong.

The correction is not only arithmetic. `SpendPolicy` held **13 of F4's 27 attack
trials**, 48% of the kernel family, and the two most interesting F4 variants (the zero-width and
Cyrillic-homoglyph currency perturbations) never reached the kernel at all. It appears in no attack
family and carries no `mechanism_id` stamp, and when this recount was first published it had
no ablation row either, which left its position relative to the kernel asserted rather than measured.
It has since been ablated on its own: over the full catalog `policies.spend` admits 0
unauthorized effects and 0 provider-call effects, and it now carries a row in both the §6.5
ablation table and the §9.1 trusted-base table, backed by the same full-catalog run as the other
three §9.1 probes. So the 13 are held by a *redundant* layer —
the approval-binding join catches them in its absence — and we name it here rather than let the 13
sit inside a figure attributed to the verifier. One caveat on the split: for a
prevented trial the `detection_source` field records the family's pre-registered expected
denial point rather than an observed one, because attributing a denial to a specific policy would
require reading the system's own tables, which the independence rule forbids; the component names
above come from the drive call's own return value, not from that field. So "0 unauthorized effects" is measured through a channel that fired six times,
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
independent oracle scores it. A 32-attack set produced **0 unauthorized effects (95% CI
[0.0%, 10.7%])**, with all 32 prevented and the four honest controls allowed.

**The 32 attacks are not 32 independent shapes, and the interval above is computed as though
they were.** They exercise four divergence mechanisms: an added payload key (18 attacks), a changed
amount (7), both together (3), and an expired or revoked approval (4). We therefore report the
bounds as a pair, exactly as we do for the false-denial rate: per trial, 0/32 gives
≤10.7%; per mechanism, the denominator is as small as four and 0/4 gives ≤49.0%. The
second is the honest reading, and it is the one a reader should carry away. The coverage is narrow
in a second way: the declarative channel realizes the approval→execution join, so the
blind result speaks to F4 and F7 and says nothing about the gate families.

**A provenance defect, stated rather than smoothed.** The blind-set file that ships is not
byte-identical to the file that was scored. The scored blob carried **30** distinct attack
shapes, not 32, splitting 16 extra-key / 7 amount / 3 both / 6 lifecycle; the shipped file carries
32 across the four mechanisms above (18 / 7 / 3 / 4). Both files hold 32 attacks and 4 controls, so
the denominator and the ≤10.7% arithmetic are unaffected. What is affected
is provenance: the attack file offered for inspection is a corrected one, not the one that produced
the published result, and we name that here rather than let a reader discover it by hashing the
file. Per-trial records now ship, as `artifacts/blind.jsonl` (36 rows, 32 attack trials, 0
unauthorized effects, 0 harness errors, ids `blind-01` to `blind-36`, splitting 18 / 7 / 3 / 4), and
they too are a *re-run of the corrected file* rather than the original run's records, which were not
retained. That re-run reproduces the same rate and interval over 32 genuinely distinct shapes, so
the published number is not an artifact of the duplicates; it does not repair the provenance defect
and we do not present it as if it did. We are transparent that this set was
author-constructed under a blindness discipline (built only from the family definition and the
§3 definition), not third-party generated; a genuinely independent generation is the strongest
remaining step and is stated as future work. It nonetheless adds validity by exercising the
independent channel at scale on payloads absent from the authored set.

### 6.10 Membrane coverage and out-of-band effects

The network-layer tripwire (§6.2) fires for any real outbound request regardless of the
router; in every correct in-process trial it stayed silent, and a firing during a gate trial
would be the strongest possible finding. The boundary guard is a CI-enforced structural check over
the source tree that flags any new un-allowlisted path to the raw execution seam. F6 plants a
violation in the scanned source and confirms the check's predicate reports it. *No build is
invoked* — no compiler runs anywhere in the released tree, as `aggressor/README.md`
states — so what F6 establishes is that the guard's predicate holds, not a demonstrated build
failure; SPEC §4 pre-registered the stronger form and this campaign did not deliver it. Neither mechanism claims that no uncovered path can
exist; both make an uncovered path *detectable*. This is prevention where the fence holds and
detection where a path escapes it, reported as such.

### 6.11 Governed latency

We measure the wall-time of a governed action end to end: the full membrane, the policy stack, the
verifier preflight, and receipt and invariant recording, using mock adapters so no network noise
enters. Median governed latency is **~19 ms**, with p95 and p99 at 53.5 and
76.3 ms (19100 / 53475 / 76336 µs). The cost is dominated not by policy evaluation but by
durable authority-proof persistence: the system pays ~19 ms at p50 to make each
action's authorization independently verifiable after the fact. We report this rather than claim a
free control plane; the trade is durable, tamper-evident proof for
single-digit-to-low-tens-of-milliseconds per governed action.

**These percentiles have moved since an earlier revision, and the reason is that they now
have an artifact behind them.** We previously published 16882 / 57811 / 81277 µs
(~17 ms at p50). No per-iteration data from that run was ever committed, so the
figures rested on a transcription no reader could check. A fresh run's per-iteration records now
ship as `artifacts/overhead.jsonl`, 200 per arm, and the numbers above are recomputed from
them by the rule the file states, so the figure and the artifact agree. This is the one published
number in the paper that changed because the evidence for it changed rather than because a claim
was wrong. **Latency is machine- and run-dependent**: these percentiles describe one synthetic
single-process loop on one machine, and *percentiles are not comparable across machines*. A
re-run elsewhere yielding different values is the expected outcome, not a failed replication.

**We report this as an absolute cost and claim no percentage overhead, because the comparison
baseline is degenerate by construction.** The ungoverned arm routes to a mock adapter,
`MockStripe.execute/3`, a pure in-memory function that performs no I/O and whose measured
p50 is **120 ns**. That number settles a question the earlier table left open: the bypassed
arm's published **0 µs** was a *timer-resolution floor, not a measurement*. At the
one-microsecond resolution the table is printed at, 120 ns and the p95's 151 ns truncate to 0 and
the p99's 3106 ns truncates to 3, so the bypassed row reads 0 / 0 / 3 µs; the real distribution
behind it is in the artifact. Any "added latency" figure is therefore arithmetically identical to
the governed column: the subtraction returns the governed number unchanged. Raising the timer's
resolution does not rescue the comparison. At 120 ns the baseline is roughly 0.0006% of the
governed path, so a corrected differential rounds to the same ~19 ms. The number is
right; a differential label on it is not, and we have dropped the "added" framing rather than keep
a subtraction that never subtracted anything. The two arms were also never paired per call, so a
percentile-wise difference between them would be a difference of order statistics rather than a
distribution of per-call deltas.

Two boundaries belong with the figure. Against a real provider call these numbers would not
dominate: hundreds of milliseconds of network time would, so the governed path's share of a live
action is smaller than a mock-adapter measurement suggests. And the artifact bounds what it can
support: it is a single-process loop against mock adapters on one machine, not a production latency
profile. (Hardware is in `REPORT.md`.)

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
- **F4's zero bounds payload divergence, not the whole approval-binding join.** The family
 definition lists twelve planned variant classes. The 29 committed F4 trials deliver seven of
 them: 11 currency perturbations, 6 field additions, 2 field removals, 6 amount mutations, 2
 lifecycle replays, and 2 known-good controls. *Five have no trial at all* — provider swap
 (all 29 carry `provider: mock_stripe`), operation swap (all 29 carry
 `operation: buy`), account re-attribution (all 29 carry a single `account_id`;
 `mutate:drop-account` removes the field, it does not re-target), idempotency-key reuse
 across two distinct payloads, and approval-missing execution. What F4's zero bounds is therefore
 the **payload-divergence** class, not the join as a whole. The account gap compounds with a
 defect in the oracle: `effects_for/2` matches on provider, operation and
 idempotency-key hash and never compares `account_id`, so SPEC §3's pre-committed "right
 action, wrong attribution" edge case is neither tested nor testable in this harness. We state
 the two together because either alone understates the hole.
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
- **Oracle independence does not hold for F4.** The oracle calls the system under test's own
 `canonical_payload_hash/1` to decide whether an executed payload is the approved one
 (§6.2). A canonicalization collision would therefore be invisible to both sides at once, and a
 canonicalization collision is precisely the failure F4 was written to find. F4 is 27 of the 31
 trials that could falsify the invariant, so this is not a corner of the evaluation: it is the
 deepest family. The canonicalizer is withheld, has had no cryptographic review, and is named a
 trusted-base element in §9.1, so F4's verdict is conditional on the correctness of an unreviewed
 system function. We do not claim independent adjudication for F4. An independently written
 canonicalizer, scored alongside the system's, is required future work. A second oracle defect
 sits beside it: `effects_for/2` never compares `account_id`, which §7 states
 together with F4's missing account-re-attribution variants. `oracle/README.md` carries
 both in its honest-limits list.
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
against risk prevention." We report both halves together, ~19 ms of median governed latency (§6.11)
against a 0/75 false-denial rate (§6.12). We are precise about the claim: the trade-off itself *is*
named in the classic catalog, as `nist-p7`, "identify potential trade-offs between reducing risk
and increased costs." What the corpus records as absent is its *instrumentation at an agent
approval gate*. Three qualifications belong with it: the p95 and p99 are 53.5 and 76.3 ms, and a gate
too slow to use is a tail property the median does not speak to; the false-denial figure has an
effective sample size of three (§6.12); and the latency figures are one machine's, not a portable
constant.

Third, section `incident-response`, gap `ms-risk-8`: "No verification that quarantined agents remain
inert; cutting an agent off from the network is not the same as confirming it has stopped acting."
§5 and family F9 address this directly on the BEAM, where a killed worker is a terminated process
rather than an unreachable one, and §5 bounds the claim: work the worker already enqueued on the
durable job runtime survives the kill and is unmeasured here.

### 9.1 Trusted computing base: minimizing trusted elements, measured (`nist-p25`)

Nine mechanisms plus a layered policy stack plus a seven-predicate verifier looks like a
large trusted base, in apparent tension with *minimize the system elements to be trusted* (NIST SP 800-27 `nist-p25`, [14]), and with economy of mechanism [2]. The tension resolves once "number of mechanisms" and
"size of the trusted computing base" are kept distinct. We draw that distinction and then
measure it: each ablatable element is removed in turn, the full catalog is driven against it, and
the admitted effects are broken out by channel. Below we state which elements that covers and which
it does not.

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
The spend policy was missing from every earlier statement of that list, and it was the case most in
need of a test: it denied 13 of F4's 27 attack trials (§6.7), 48% of the kernel family, while
carrying no family and no ablation row. It has since been ablated on its own, as mechanism
`policies.spend` over the full catalog, and it admits **0** unauthorized effects and
**0** provider-call effects (§6.5), over 73 trials with 41 provider-call trials live. Read against
the compound ablation, that settles its
position by measurement rather than by assertion: the 13 trials the spend policy denied are held by
the approval-binding join once the spend policy is gone, and are held by the spend policy once the
join is gone, which is why all 27 convert only when *both* fail. Neither layer is individually
necessary for those 13. That is defense in depth, and it puts the spend policy outside the kernel.

**Break the boundary out by effect channel** (`--tcb`). We ablate each element,
re-run the **full 73-trial catalog** against it, and report the admitted effects by channel. A
surface reducer's failure should admit effects only in its own gate channel and *zero*
provider-call (external) effects; only a kernel element's failure should admit a provider-call
effect. That is the pattern in the data:

| Ablated element | Role | Effects admitted | Channel | Provider-call (external) |
|---|---|---:|---|---:|
| Content firewall (F1) | surface reducer | 10 | content_gate | **0** |
| Runtime sentinel (F2) | surface reducer | 5 | runtime_gate | **0** |
| Skill auditor (F3) | surface reducer | 5 | skill_gate | **0** |
| Spend policy | redundant layer | 0 | — | **0** |
| Approval-binding join (F4) | **kernel** | 14 | provider_call | **14** |

Removing a surface reducer admits tainted input but produces no unauthorized external effect;
removing the spend policy admits nothing at all; removing the kernel element produces fourteen.

**What that table establishes, and what it does not.** The four ablations in
`artifacts/tcb-full-catalog.jsonl` each drove the **full 73-trial catalog** — 292 per-trial records,
73 per probe, all nine families present under every ablation — so **41 provider-call trials were
live under each** (35 of them attack trials; the other six are F4's two known-good controls and F7's
four replays). That is what makes the last column a measurement rather than a consequence of trial
selection: a surface reducer whose removal admitted even one external effect would have recorded it
there, and none did. Every admitted effect landed in the ablated mechanism's own gate channel — 10
`content_gate`, 5 `runtime_gate`, 5 `skill_gate` — and `provider_call` unauthorized effects were
zero in all four probes. The kernel row is measured on a separate basis and always was: removing the
approval-binding join admits fourteen unauthorized external effects, all on the `provider_call`
channel (`artifacts/ablation/tcb-F4.jsonl`, 29 provider-call trials live). That row cannot be
manufactured by trial selection in any case, since selection can suppress an external effect but
never create one.

An earlier revision of this paper stated this counterfactual against a per-family probe run that
could not support it, and a subsequent revision withdrew it for that reason. The run described here
is the full-catalog one; the per-family probes are preserved separately as
`artifacts/ablation/tcb-per-family-probes.jsonl`, and their own caveat records why they were
insufficient.

We state the scope exactly. This establishes that these **three** surface reducers, removed
**singly**, admit no external effect. It establishes nothing about **combinations** — no run
disables two of them at once — and nothing about mechanisms with **no runtime toggle**: F6's
boundary guard, F7's reconciliation, and F9's process supervision are never ablated, and **the
mediation membrane and the durable authority store have no ablation row at all**. Those two are
named as trusted-base elements on the §3 invariant's structure, not by a run that removed them.
Auditability is now uniform across the table: the four full-catalog probes recompute from
`artifacts/tcb-full-catalog.jsonl` and the kernel row from `artifacts/ablation/`.

So `nist-p25` here is *measured* for every element the harness can ablate: the trusted
base is small (three or four elements), and the other mechanisms buy defense in depth at the cost of
code, not trust. The classification of the surface reducers was this argument's weakest joint and is
now the part with a falsifying run behind it. What remains argued is composition and coverage: the
mediation membrane and the durable authority store carry no ablation row of their own, and no run
removes two elements of the same class together. It also resolves an intra-catalog tension: layered security with no single point of
vulnerability (`nist-p16`) pulls against minimizing the system elements to be trusted
(`nist-p25`), and both are classic principles; the resolution is that layers
*outside* the kernel do not enlarge the TCB. The economy-of-mechanism half is that the kernel's
fence is small enough to be checked by a **CI-enforced structural check over the source tree**
(§5), not upheld by convention.

### 9.2 Candidate contributions to the principles corpus

Beyond the three catalog gaps above, we flag four principles this work either names or
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
 tamper-proofness, a gap §7 states directly. The seven properties instantiate Saltzer and Schroeder's complete mediation,
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
reconstruction, the family table as data, and the per-trial records for the ablation, no-control,
compound, TCB-channel, overhead, false-denial, measurement-integrity and blind runs. This makes the
*results* auditable (every number in the paper follows mechanically from the JSONL) and the
*method* inspectable.

**What is not yet released, and what that costs reproducibility.** The **system under test**
(the Trinity control plane itself: the membrane, the verifier internals, the policy stack)
is **not** open-sourced at this time. The harness therefore references code that is not public,
so a third party **cannot re-execute the campaign end-to-end today**; reproduction is
*partial*, results-verifiable and method-inspectable now, fully re-executable when the system
is released (tied to the filing schedule). We state this plainly rather than imply a
completeness the artifact does not yet have.

**Held pending counsel:** the system under test itself (for now); and, on the eventual
release, these internals remain redacted: invariant registry identifiers, versions, and
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

**Fixture release (pre-committed, `spec/SPEC.md` §11):** release fixtures for families that expose
no internals (approval binding, coapproval, posture, process lifecycle, membrane-bypass
positive control); hold the content, runtime, and skill fixtures, whose release would leak
firewall patterns, sentinel patterns, and audit heuristics; publish the taxonomy and results
for all nine and name which fixtures are held and why.

## 12. Conclusion and future work

Under adversarial load, an agent governed by an authority-bound control plane was induced to
propose violating actions in the large majority of trials while zero unauthorized external
effects occurred across 61 attack trials (95% CI ≤ ~6%). The result is credible not because it
is clean but because the ablation and no-control baselines show the trusted kernel does the work and the surrounding layers independent (51 of 63 trials produce an unauthorized effect with the membrane
off, against 0 governed), the one effect the benchmark ever leaked was
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
 synthesized from 41 sources (2019–2026) across 22 sections, with a published `gap_index`.
 `https://aisharedresponsibility.com/data/ai-agentic-principles.json`. (Source of the three
 `gap_index` entries quoted in §9.)
14. Coalition for Secure AI (CoSAI). *Classic security principles catalog*, 87 entries
 normalized from Saltzer and Schroeder, NIST SP 800-27, ISO 27001, and CIS Controls.
 `https://aisharedresponsibility.com/data/security-principles.json`. (Source of the
 `nist-p16` and `nist-p25` identifiers used in §9.1.)
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

## Appendix A: Reproduction (two tiers)

**Tier 1, verify the results now, from the public artifact (no system under test needed).**
The reported numbers are recomputable from the committed JSONL alone: `artifacts/family-table.json` is
the §6.3 table as data, and the campaign / v1-prefix JSONL carry every per-trial record the
tables aggregate. A reader can re-derive the family table, the confidence intervals, the
calibration decomposition, and the effect-channel split of §6.4 without running any of Trinity.
Every other table in the paper also comes from a separate run, and those runs' per-trial records now
ship as well: the per-mechanism ablations in `artifacts/ablation/tcb-F*.jsonl` and, both arms
together, in `ablation-study.jsonl`; the no-control ceiling in `baseline.jsonl`; the compound
ablation in `compound.jsonl`; the §9.1 channel probes in `tcb-full-catalog.jsonl`; the
governed-latency iterations in `overhead.jsonl`; the false-denial actions in `false-denials.jsonl`;
the F10 controls in `measurement-integrity.jsonl`; and the blind red team in `blind.jsonl`. Each
carries a `_meta` line stating how to recompute the figure it backs, and several carry a `caveat`
that bounds what the run can support. **Every table in the paper now recomputes from a committed
artifact**, including the §9.1 channel table and the `policies.spend` row, which are the four
full-catalog probes in `tcb-full-catalog.jsonl`. What remains outside the artifact is scope, not
arithmetic: the limits §9.1 states (single removals only, no combinations, no ablation of F6/F7/F9,
none of the membrane or the durable store) are properties of which runs exist, and no file closes
them.

**Tier 2, re-execute end-to-end (requires the system under test, not yet public).** The
commands below drive the real membrane and therefore need the Trinity control plane, which is
held for now (§11); they become runnable when the system is released.

```bash
MIX_ENV=test mix holytrinity.run --run-id paper --all --require-clean # 73 trials (clean tree)
MIX_ENV=test mix holytrinity.run --run-id paper --report # family table + CIs + calibration
MIX_ENV=test mix holytrinity.run --run-id abl --ablation-study # per-mechanism necessity
MIX_ENV=test mix holytrinity.run --run-id abl --compound # F4 join + spend (0->14->27)
MIX_ENV=test mix holytrinity.run --run-id base --baseline # no-control ceiling (51/63)
MIX_ENV=test mix holytrinity.run --run-id tcb --tcb # TCB boundary by effect channel (§9.1)
MIX_ENV=test mix holytrinity.run --run-id spend --all --ablate policies.spend # spend row (0->0, full catalog)
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
