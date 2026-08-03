# The Model Proposes, the System Authorizes: An Authority Control Plane for AI Agents on the BEAM

Ayla Croft, ScriptKittyOS · ORCID `0009-0008-9457-2160` · 29 July 2026

---

## Abstract

Agentic security research has converged on a clear and repeatedly replicated finding: language
models driving agents can be made to misbehave. In the largest public red teaming competition
to date, participants submitted 1.8 million prompt injection attacks against 22 frontier AI
agents across 44 realistic deployment scenarios, producing over 60,000 successful policy
violations; the resulting Agent Red Teaming (ART) benchmark, evaluated across 19
state-of-the-art models, drives nearly all agents into policy violations within 10 to 100
queries with high transferability. This paper takes that finding as a premise rather than a
research question. If model misbehavior under attack is effectively certain, then the
security-relevant variable is not whether a model can be induced to misbehave but whether that
misbehavior converts into a real-world effect. I argue that existing agentic-security
benchmarks, including ART, which I co-authored, largely measure the former. This paper
describes an authority control plane organized around a single thesis: the model proposes, the
system authorizes. The agent may reason, plan, draft, and call tools freely, but it is
architecturally incapable of being the authority that decides whether an action occurs. I
present nine mechanisms, a threat model in which the model and all model-derived artifacts are
untrusted, a formal statement of the security invariant the architecture claims to maintain, a
mapping of each mechanism to a layer and an accountable party under the CoSAI Shared
Responsibility Framework, an implementation on the Erlang/BEAM runtime, BEAM being the Erlang
virtual machine, whose supervision and process-isolation properties make "kill and reseed a
compromised agent" and "the agent's memory is never the authority" structural rather than
aspirational, and a set of CI-enforced structural invariants that fence boundary coverage
against regression. I am deliberate about what this paper does not contain: it presents no
security evaluation of its own. It states an architecture, a threat model, an invariant, and a
proposed evaluation. That evaluation has since been performed and is reported separately [32]; it
measured an unauthorized-effect rate of zero across 61 attack trials (95% CI [0.0%, 5.9%]), a
benign-workload false-denial rate of zero over 75 legitimate approved actions (0/75; 95% CI
[0.0%, 4.9%], effective n=3), and a median governed-action latency of about 19 ms, reported as
an absolute cost rather than a differential because the ungoverned baseline proved degenerate,
together with a mechanism ablation and a no-control baseline. Four absences named here persist.
No third-party red team has been run: the evaluation shares authorship with the system. No
benchmark comparison against AgentDojo, InjecAgent, or ART exists. No cryptographic review of
the canonicalization scheme has occurred, which matters more now that the evaluation's deepest
attack family tests exactly that canonicalization. No human-subjects study of the approval
interface has been done. The implementation passes 1,286 automated test blocks across 287 test
files at commit `79bfd54`, which is a conformance result and not a security result. A
reads-only production soak is in progress with no results yet. The paper's contribution is an
architecture, a threat model, a stated invariant, an accountability map, and an evaluation
design pre-registered here and executed separately, whose primary metric is unauthorized-effect
rate rather than model misbehavior.

**Keywords:** AI agent security; authorization; indirect prompt injection; reference monitor;
complete mediation; tamper-evident audit; BEAM/Erlang; shared responsibility; evaluation
methodology

---

## 1. Introduction

### 1.1 The problem

An AI agent is a language model wired to tools, memory, and external content, permitted to take
actions in the world. The security literature has established, with unusual clarity for such a
young field, that the model at the center of such a system cannot be trusted to enforce its own
deployment policy under adversarial pressure. Greshake et al. [13] showed in 2023 that
instructions embedded in retrieved content can hijack large language model (LLM) integrated
applications without any direct interface to the model, a class of attack they named indirect
prompt injection. Benchmarks that followed, notably InjecAgent [29] and AgentDojo [9],
quantified how readily tool-integrated agents can be diverted into attacker-chosen actions. The
largest datapoint to date is the public competition that produced the ART benchmark [31], in
which 1.8 million attacks yielded more than 60,000 documented policy violations and the curated
benchmark drives essentially all evaluated agents into violations within a bounded number of
queries.

### 1.2 The position

I take the position that model compliance is the wrong control surface. If a system's safety
depends on the model refusing to be jailbroken, prompt-injected, or confused, that system is
already broken, because every available benchmark says the model will eventually comply with
the attacker. The design principle that follows is uncomfortable but simple: assume the agent
will be wrong, jailbroken, injected, or hostile, and make that survivable rather than
preventable. Concretely, the model proposes and the system authorizes. The agent can produce
any plan, any draft, any tool-call request, and any self-assessment it likes. None of those
artifacts is authority. Authority to cause an external effect lives in a control plane made of
compiled code, a code-owned policy registry, a durable database, and human approvers, and the
agent has no path to become any of those things.

### 1.3 A self-critique of ART

The framing of this paper rests on a critique of the benchmark it takes as its premise.[^1] ART
is rigorous and its finding is correct: frontier agents violate policy under attack, transferably
and reliably. The limiting choice was the dependent variable. ART, like InjecAgent and
AgentDojo, measures whether an attack causes the model to misbehave. If misbehavior is assumed,
that measurement saturates: the interesting number is already known to approach 100 percent.
The measurement that matters for a deployed system is whether misbehavior converts into an
unauthorized real-world effect. A system can concede every model-level engagement and still be
secure if no conceded engagement produces an effect outside a valid, current, exact
authorization. The benchmark I propose in Section 12 measures that conversion rate directly. I
treat ART generously here because it deserves it: the finding was correct and important. The
limitation is the implicit assumption that model compliance is the control surface worth
measuring.

[^1]: Competing-interest note: I am a co-author of arXiv:2507.20526 (Gray Swan AI), cited here
as [31]. The criticism that follows concerns that benchmark's choice of dependent variable and
applies equally to InjecAgent and AgentDojo. It is not directed at any individual.

### 1.4 Contributions

This paper contributes:

1. a threat model in which the model and everything derived from it are untrusted, alongside
   external content of every origin including the operator's own database;
2. a set of numbered, testable design principles;
3. a formal statement of the security invariant the architecture claims to maintain, together
   with an explicit statement that it is a stated invariant awaiting empirical test and not a
   proven theorem;
4. nine architectural mechanisms, each mapped to the specific attack it addresses and to a
   layer and accountable party under the CoSAI Shared Responsibility Framework;
5. an argument that the Erlang/BEAM runtime does real work for this design rather than serving
   as an aesthetic choice, together with an honest account of its costs;
6. a set of CI-enforced structural invariants that fence boundary coverage against regression,
   together with an explicit statement of what static analysis on this substrate cannot
   establish;
7. a proposed evaluation harness whose primary metric is unauthorized-effect rate, including a
   falsifiable strong test in which the agent is replaced by an adversarial oracle; and
8. an explicit register of identified gaps that this architecture does not currently close
   (Section 13).

### 1.5 What we do not claim

I state the following plainly and early, because the credibility of an architecture paper with
no security evaluation depends on not overclaiming. I do not claim that this system is secure.
The evaluation proposed in Section 12 has since been run and is reported separately [32]; it
measured the unauthorized-effect rate, the benign-workload false-denial rate, and the
governed-action latency this section originally listed as unmeasured. It did not measure
overhead as a differential against an ungoverned baseline; Section 11 says why. Those results
do not make the system secure, and the evaluation says so itself. Four absences persist and I
name them as sharply as I named the originals. No third-party red team has been run: the
evaluation shares authorship with the system. No benchmark comparison against AgentDojo,
InjecAgent, or ART exists. I have not commissioned a cryptographic review of the
canonicalization and hashing scheme, which matters more now that the evaluation's deepest
attack family tests exactly that canonicalization. I have not run a human-subjects study on
whether the approval interface actually reduces rubber-stamping. The implementation passes
1,286 automated test blocks across 287 test files at commit `79bfd54`; this demonstrates
conformance to specified behavior and is explicitly not a security evaluation. A reads-only
production soak is in progress and has produced no results yet. I do not claim novelty for the
individual security primitives, most of which are decades old; the claim is about their
composition and their placement relative to the model. I do not claim the trust root is solved:
an adversary with database write access or a compromised approver session defeats the current
design, and I name these as limitations rather than defending against them. Section 13
registers further gaps identified by external assessment that the current architecture does not
close, and marks each as unaddressed rather than folding it into the design.

## 2. Background and related work

### 2.1 Prompt injection and indirect prompt injection

Direct prompt injection, in which a user overrides system instructions, was documented early.
The consequential generalization is indirect prompt injection. Greshake, Abdelnabi, Mishra,
Endres, Holz, and Fritz [13] showed that adversarial instructions embedded in content the model
later retrieves can compromise the surrounding application remotely, and derived a
security-oriented taxonomy of impacts including data theft, worming, and information ecosystem
contamination. This is a peer-reviewed workshop paper. Its core insight, that LLM-integrated
applications blur the boundary between data and instructions, motivates the content provenance
gate in Section 8.

### 2.2 Agent security benchmarks and what they measure

InjecAgent [29] is a benchmark of 1,054 test cases spanning 17 user tools and 62 attacker
tools, categorizing attacker intent into direct harm and private-data exfiltration;
ReAct-prompted GPT-4 was vulnerable 23.6 percent of the time, and an enhanced setting that
reinforces the attacker instruction with a "hacking prompt" nearly doubled that rate to roughly
47 percent. AgentDojo [9] is a dynamic environment with 97 realistic tasks and 629 security
test cases across banking, Slack, travel, and workspace domains; it is an extensible
environment rather than a static suite and has become a standard reference. The ART benchmark
[31] was derived from 1.8 million attacks and over 60,000 policy violations across 22 frontier
agents and 44 scenarios, then evaluated across 19 state-of-the-art models with near-total
violation rates within 10 to 100 queries and high transferability.

The analytically important point is what these benchmarks measure. All three measure whether an
attack causes the model to produce a policy-violating output or tool call, that is, whether the
model misbehaves. The attack success rate is defined relative to the model's behavior. None of
them measures whether the misbehavior would have produced a durable, unauthorized external
effect in a system that mediates effects independently of the model. That gap is the space this
paper occupies.

### 2.3 System-level and architectural defenses

A growing line of work moves defense out of the model and into the system. CaMeL [10] extracts
control and data flow from the trusted user query using a privileged LLM and a quarantined LLM
plus a custom interpreter that tracks provenance and enforces capability-based policies before
tool calls; it reports solving 77 percent of AgentDojo tasks with provable security for covered
cases, compared to 84 percent for an undefended system (an earlier version reported 67
percent). CaMeL is the closest relative to the present work in spirit, since both draw on
classical software-security principles and refuse to rely on model behavior. The difference is
the locus of enforcement and the object being bound. CaMeL secures data flow so that untrusted
data cannot influence the program's control flow; the present architecture assumes the model's
entire output is untrusted and binds each externally effectful action to a human-approved
cryptographic fingerprint over the exact execution envelope, then independently reconciles the
executed action against the provider's own record.

Spotlighting [15] is a prompt-engineering family that marks provenance of untrusted input; the
authors report that it reduces attack success rate from greater than 50 percent to below 2
percent in their experiments with GPT-family models, with minimal impact on task efficacy. It
is a mitigation that improves model discrimination, not a mediation boundary. LlamaFirewall [4]
is a system-level guardrail framework with PromptGuard 2, an experimental chain-of-thought
alignment auditor (AlignmentCheck), and CodeShield static analysis; on AgentDojo the combined
PromptGuard 2 plus AlignmentCheck configuration reduced attack success rate by about 90
percent, from a 17.6 percent no-defense baseline to 1.75 percent, with a utility cost from 47.7
percent to 42.7 percent. It is a layered detector, and its authors describe key components as
experimental. AgentSpec [27] is a domain-specific language (DSL) for runtime constraints with
triggers, predicates, and enforcement; the authors report that it prevents unsafe executions in
over 90 percent of code agent cases, eliminates all hazardous actions in embodied agent tasks,
and enforces full compliance by autonomous vehicles, with overheads in milliseconds. It is a
peer-reviewed runtime-enforcement approach in which the policy is expressed in a DSL.
IsolateGPT [28] provides an execution-isolation architecture for LLM-based agentic systems. The
dual-LLM pattern that CaMeL builds on originates with Simon Willison.

Adjacent recent work on privilege and flow control is directly relevant. Progent [22] provides
programmable, deterministically enforced privilege control for LLM agents. Fides [6] applies
information-flow control to agent planning, tracking confidentiality and integrity labels.
Beurer-Kellner et al. [3] catalogue design patterns for prompt-injection-resistant agents. Each
constrains what a possibly-misbehaving model can cause; none binds a human approval to a
canonical execution envelope or reconciles the executed action against an independently
retrieved provider record.

The distinction that matters across this line of work is between detection or mitigation of
model misbehavior (Spotlighting, LlamaFirewall's detectors), constraint of data flow or runtime
behavior (CaMeL, AgentSpec, IsolateGPT, Progent, Fides), and independent mediation and binding
of external effect (this work). The first reduces the probability that the model misbehaves;
the second constrains what a possibly-misbehaving model can cause; the third assumes the
model's output is worst-case and makes each external effect require an authorization the model
cannot produce.

### 2.4 The closest adjacent system: AgentBound

AgentBound [16] is the nearest neighbour and deserves precise differentiation. AgentBound
evaluates each proposed agent action using three independent authorities: delegated
authorization, owner-signed behavioral constitutions, and site action contracts. It composes
their typed judgments through a formal decision algebra over a lattice of restrictiveness (Deny
dominates Review dominates Permit), and it issues cryptographically verifiable governance
receipts that bind each executed action to the exact governing policy artifacts, enabling
independent replay verification. It introduces a standing-delegation model for long-running
agents and a benchmark, AgentBound-Bench. Its stated invariant is that scope permitted the
action, the constitution stopped it, and the receipt proves it.

The two systems agree that identity and authorization are necessary but insufficient and that
behavioral context must gate execution, and both produce cryptographic receipts. They differ in
what the receipt binds and where enforcement lives. AgentBound performs policy evaluation: it
asks whether the proposed action is permitted under composed policy authorities and produces a
receipt binding the action to the policies applied. The present architecture performs binding
and mediation: for sensitive operations it binds an action to a human-approved fingerprint over
the exact execution envelope (Section 5), re-derives that fingerprint at execution and denies on
any divergence, and then independently retrieves the provider's own record of what happened and
reconciles it against the receipt. On the evidence available in the AgentBound paper,
AgentBound does not perform canonicalization of a semantic execution envelope that excludes
presentation state, does not perform post-execution reconciliation against independently
retrieved provider records, and does not enforce boundary coverage as a structural invariant
checked on every build. Those three properties are the distinguishing claims of this work. This
differentiation rests on the published description of AgentBound rather than on its source and
should be re-verified against the artifact before final publication. Note also that two
distinct arXiv preprints carry the name AgentBound; the system discussed here is
arXiv:2606.30970 (Kaul, Lan, and Gupta), not the unrelated arXiv:2510.21236.

### 2.5 Reference monitor theory and classical principles

The organizing idea is old. Anderson's 1972 Computer Security Technology Planning Study [1]
introduced the reference monitor: a mechanism that mediates all access, cannot be bypassed, and
is small enough to be verifiable. Saltzer and Schroeder's 1975 "The Protection of Information
in Computer Systems" [25] set out design principles including complete mediation, fail-safe
defaults, economy of mechanism, least privilege, and psychological acceptability. The single
side-effect boundary in Section 8 is a reference monitor for external effects; the fail-closed
defaults, the code-owned operation registry as an economy-of-mechanism trusted base, and the
treatment of approval fatigue as a psychological-acceptability failure are direct descendants
of these principles. The confused deputy problem [14] describes exactly the failure an agent
embodies: a privileged intermediary induced by a less-privileged party to misuse its authority.
An agent handed ambient authority is a confused deputy by construction, which is why authority
here is never ambient and never carried by the model's request alone.

### 2.6 Tool-ecosystem, memory, and identity work

The Model Context Protocol (MCP) has surfaced a family of tool-layer attacks: tool poisoning
(malicious instructions hidden in tool descriptions), rug pulls (a tool's definition silently
changed after approval), and lookalike or shadowing tools. Invariant Labs demonstrated
tool-description poisoning and rug pulls against production MCP servers in 2025, and
CVE-2025-54136 [8], in which modification of MCP server definitions bypassed manual
re-approvals in a widely used AI coding environment, catalogued a rug-pull class vulnerability.
These motivate the code-owned tool registry and the approval binding that includes the tool
definition. On memory, MINJA [11] shows that an ordinary user can poison an agent's persistent
memory through queries alone, without direct access to the memory store, reporting injection
success rates above 95 percent; this motivates scoped memory with audited promotion. On
identity, OIDC-A [20], SPIFFE/SPIRE workload identity, and W3C Verifiable Credentials
constitute an adjacent identity layer: they establish who an agent is, which is complementary
to, not competitive with, deciding whether an action occurs.

### 2.7 Tamper-evident logging, durable workflows, and pre-action authorization

The receipt chain in Section 8 borrows from tamper-evident logging. Certificate Transparency
[23, 24] uses Merkle trees to make a log append-only and to allow efficient proofs that one log
state is a prefix of another; the earlier idea of Merkle-tree tamper-evident logs is due to
Crosby and Wallach [7]. I adopt the append-only, hash-chained structure while being explicit in
Section 14 that hash chaining is only tamper-evident, not tamper-proof, against an adversary
who can recompute the chain. Durable workflow engines are relevant to the approval pause.
Temporal provides durable human-in-the-loop via signals and durable timers, so that a workflow
can wait months for a human decision and resume after crashes with the approval durably
recorded in workflow history; LangGraph provides an interrupt function that persists graph
state via its checkpointer and waits indefinitely for a resume. Both deliver durability of a
paused approval. Neither binds the approval to a cryptographic fingerprint of the exact
execution envelope, which is the property this architecture adds on top of durability. Closest
in intent is recent work framing a pre-action authorization problem and intercepting tool calls
synchronously before execution with a signed audit record [26]; the present work differs in
binding a canonicalized semantic envelope and in reconciling against provider-retrieved
evidence after execution.

### 2.8 Governance frameworks, accountability, and agent harnesses

The NIST AI Risk Management Framework [18] organizes risk work into GOVERN, MAP, MEASURE, and
MANAGE functions, with MANAGE subcategories calling for post-deployment monitoring, override
mechanisms, and change management; the Generative AI Profile [19] is the companion mapping
target for generative and agentic risk categories. The EU AI Act [12] requires under Article 12
that high-risk systems technically allow for the automatic recording of events over the
lifetime of the system, addresses transparency and provision of information to deployers under
Article 13, and under Article 14 requires that human oversight be meaningful, with Article
14(4)(b) naming automation bias specifically. Article 12 establishes the logging capability;
the minimum retention period is set by Article 19 and Article 26(6) rather than by Article 12.
The OWASP Top 10 for LLM Applications and the OWASP Top 10 for Agentic Applications 2026 [21]
catalogue the relevant threat classes, including excessive agency and memory poisoning.

These instruments specify what must be recorded and overseen but leave open who is accountable
for each control point. The CoSAI AI Shared Responsibility Framework [5] addresses that question
by layering an AI system and assigning accountability per layer and operating model. Section 6
maps this architecture onto those layers. The proof-packet mechanism in Section 8 is designed
to produce the decision-level, human-oversight-inclusive records these frameworks demand.

Finally, NOOA, the NVIDIA Labs Object-Oriented Agent released as part of the Open Secure AI
Alliance in July 2026 [17], represents agents as Python objects whose methods are actions and
whose docstrings are instructions, with method bodies completed by an LLM; NVIDIA states it is
not a sandbox and relies on operating-system-level isolation. It is a harness and
developer-ergonomics framework, complementary to an authorization control plane rather than
competing with it.

## 3. Threat model

**Untrusted.** The model and everything derived from it: plans, drafts, tool-call requests,
self-assessments of risk, claims about what it has already done, and any content the model has
summarized or transformed. External content of every origin, explicitly including the
operator's own database, since a poisoned internal record is a documented attack. Third-party
agents and tool servers. Client-side state.

**Trusted with caveats.** The control plane's compiled code and its code-owned policy registry.
The database as a durable store. Human approvers.

**Explicitly not authority.** Process memory. UI state. Model output. One agent's assertion
about another. Prior conversational context. Any single classifier's judgment as a sole gate. A
warning click-through.

**Adversary capabilities.** The adversary can place arbitrary content wherever the agent will
read it, can thereby influence model output arbitrarily, can observe public behavior, and can
replay or delay requests. In the strongest case the adversary fully controls the agent
runtime's output.

**Adversary limits (named as out of scope).** The adversary cannot obtain valid credentials for
a distinct human approver, cannot write directly to the authority database, and cannot modify
the deployed control-plane binary. These are boundaries of the current design, not proven
guarantees, and Sections 13 and 14 treat each as an open problem.

## 4. Design principles

1. **The model proposes; the system authorizes.** No model-derived artifact is ever authority
   for an external effect.
2. **Assume compromise.** Design so that a wrong, jailbroken, injected, or hostile agent is
   survivable, not merely improbable.
3. **Complete mediation of effects.** Every operation with external effect passes exactly one
   boundary that revalidates policy, authorization, and posture.
4. **Fail closed.** Unmapped operations, malformed requests, unregistered tools, and missing
   evidence all default to denial.
5. **Bind what executes, not what displays.** Authorization binds a canonical semantic
   envelope; presentation is out of scope for the binding.
6. **Authority is scarce and specific.** Approvals are rare, specific, and bound to an exact
   envelope, because ubiquitous approval trains humans to rubber-stamp.
7. **Evidence is retrieved, not asserted.** A receipt independently retrieved from a provider
   is evidence; a self-report is a claim.
8. **Missing evidence is reported, never synthesized.**
9. **Invariants are enforced mechanically in CI, not by convention.**

Each principle is testable in the sense that a violation is observable: principle 3 is violated
if any effectful path bypasses the boundary (checked mechanically in CI over the statically
resolvable call graph), principle 4 is violated if an unmapped operation executes, principle 8
is violated if any evidence field is fabricated.

Several of these instantiate settled theory rather than claiming novelty. Principle 3 is
complete mediation and principle 4 is fail-safe defaults, both from Saltzer and Schroeder [25],
as is principle 6, which reframes psychological acceptability as a security requirement rather
than a usability preference. Principles 1 and 9 serve economy of mechanism and the minimization
of trusted elements [25, 1]. Principles 5, 7, and 8 have no close antecedent in the classical
literature and are the ones I would expect to be argued with.

## 5. A formal statement of the security property

The central claim of this paper is stated in prose above. I state it precisely here, and I
state plainly that it is an invariant awaiting empirical test rather than a proven theorem.

**Definitions.** An external effect *e* is any operation an adapter executes that changes state
outside the control plane: a write, send, transfer, or mutation at a provider. A canonical
semantic envelope *E* is the tuple (scope-or-account, provider, operation, resource
identifiers, idempotency key, canonical payload hash, expiry, policy version, canonicalization
version). The fingerprint *F(E)* is a cryptographic hash over *E* that excludes rendered text
and presentation state. An authorization *a* binds *F(E)*. An authorization is *valid, current,
and exact* at execution time *t* if and only if it exists in the durable authority store, has
not expired at *t*, matches the current policy version, and was produced either by a distinct
human approver for approval-tier operations or by the deterministic code-owned policy for
reads.

**Unauthorized effect.** An external effect *e* is unauthorized if and only if, at the moment
of its execution, there exists no authorization *a* in the durable store whose re-derived
fingerprint over the actually-executing envelope equals the bound fingerprint, exactly and
currently.

**Claimed invariant *I*.** For every external effect *e* that the side-effect boundary permits,
there exists a valid, current, exact authorization *a* such that the re-derived fingerprint of
the executing envelope equals the fingerprint bound by *a*. Equivalently: no external effect
occurs outside a valid, current, exact authorization. The unauthorized-effect rate of Section
12 is the fraction of trials in which *I* is violated.

**Conditions under which *I* is claimed to hold.** Given the out-of-scope adversary limits of
Section 3, and assuming *F* is collision-resistant, which has not been reviewed (Section 14),
the architecture claims that *I* holds even when the model and all model-derived artifacts are
fully adversarial, because authority never resides in any model-derived artifact.

**Status.** *I* is a stated invariant awaiting empirical test. There is no machine-checked
proof, no cryptographic review of *F*, and no adversarial evaluation. The strong test of
Section 12 is the proposed falsification: a single unauthorized effect under an adversarial
oracle refutes *I*.

## 6. Accountability mapping

Regulatory instruments specify what must be logged and overseen but not who owns each control.
The CoSAI Shared Responsibility Framework [5] layers an AI system and assigns accountability by
layer and operating model. This architecture sits primarily at the AI application layer: it
mediates what reaches the model and what external effects the application performs. Platform
integrity and capacity, and model robustness, are separate layers that this control plane does
not replace.

The reference implementation corresponds to the SRF *IaaS* operating model, under which the
customer builds and operates the application, platform, and model layers and L3 is
customer-owned. The application developer is therefore the accountable party for the mechanisms
of Section 8 unless a platform contract explicitly moves a control to a provider. Table 1
records one accountable party per mechanism. Where a control has a genuine platform dependency,
the dependency is named separately rather than recorded as shared ownership, since shared
ownership is not an actionable answer to the question of who is accountable.

**Table 1: Mechanisms, primary layer, and accountable party under the SRF IaaS operating
model.**

| # | Mechanism | Primary layer | Accountable party |
|---|---|---|---|
| M1 | Content provenance gate | AI application | Application developer |
| M2 | Approval-bound execution envelopes | AI application | Application developer; human approver for the grant |
| M3 | Bounded proposal loop | AI application (compensating); infrastructure for capacity | Application developer for caps; platform provider for capacity |
| M4 | Single side-effect boundary | AI application | Application developer |
| M5 | Authority assurance | AI application | Application developer |
| M6 | Scoped skills and memory | AI application | Application developer |
| M7 | Deterministic override adjudication | AI application; governance for oversight policy | Application developer; named review owner for high-risk overrides |
| M8 | Runtime integrity and reset | AI application; infrastructure for host isolation | Application developer; platform provider for machine-level isolation |
| M9 | Proof packets and receipt chains | AI application; governance for audit consumption | Application developer to emit; named audit owner to review |

The last row states an obligation this implementation does not yet discharge. Emitting audit
evidence that no named party is responsible for reading produces the same practical outcome as
emitting none. Section 13 records this as an open gap rather than a satisfied control.

## 7. Reference implementation

The reference implementation is called Trinity, an authority-bound agentic flywheel. Throughout
this paper I use the neutral term authority control plane for the architecture and reserve
Trinity for the concrete implementation. Trinity realizes the nine mechanisms of Section 8 on
the substrate described in Section 9, and it is the system whose conformance status Sections 10
and 11 report. Downstream evaluation should use substrate-neutral architecture names when
comparing systems.

## 8. Architecture: nine mechanisms

Table 2 summarizes the nine mechanisms and the attack classes each addresses. The subsections
that follow describe each in full.

**Table 2: The nine mechanisms and the attacks they address.**

| # | Mechanism | Attacks addressed |
|---|---|---|
| M1 | Content provenance gate | Indirect prompt injection via retrieved documents and tool results; instruction laundering through summarization |
| M2 | Approval-bound execution envelopes | Approval drift (payload mutated after approval); self-authorization claims; risk-tier manipulation |
| M3 | Bounded proposal loop | Loop-abuse resource exhaustion (denial of wallet); unaccountable reads |
| M4 | Single side-effect boundary | Unregistered and lookalike tool invocation; replay under a reused idempotency key; complete mediation generally |
| M5 | Authority assurance | Adapter self-report forgery; silent execution failures |
| M6 | Scoped skills and memory | Memory and skill poisoning; cross-scope leakage |
| M7 | Deterministic override adjudication | Social pressure toward warning override; manufactured urgency |
| M8 | Runtime integrity and reset | A fully compromised agent runtime |
| M9 | Proof packets and receipt chains | Evidence completeness; after-the-fact reconstruction |

### 8.1 Mechanism M1: content provenance gate

External content is quarantined and provenance-checked before it enters the agent's context.
There are no trusted origins, including the system's own database, because a poisoned internal
record is a documented attack (see MINJA and the indirect-injection literature). Provenance
survives transformation, so an instruction cannot launder itself through a summary. Blocked
content produces a receipt and a safe placeholder.

### 8.2 Mechanism M2: approval-bound execution envelopes

A sensitive proposal becomes an approval bound to a cryptographic fingerprint over the exact
execution envelope defined in Section 5. A human approves that fingerprint. At execution the
fingerprint is re-derived and compared; any divergence denies and records. Canonicalization
binds what executes and never how it displays: it covers the normalized semantic payload and
excludes rendered text and presentation state, so benign re-rendering does not invalidate an
approval but any semantic change does. Canonicalization is versioned. Risk tiering is a
deterministic, code-owned mapping from operation to tier; the tier function takes only the tool
name, so the agent structurally cannot influence its own risk level, and unmapped operations
fail closed to requiring approval.

### 8.3 Mechanism M3: bounded proposal loop

Reads may execute without human approval but never without authorization. Every read emits a
query receipt recording the query, redacted parameters, scope, a hash of the result the model
actually saw, and an as-of timestamp. Hard caps on iterations, tokens, and wall time are
code-owned; the loop function accepts no cap argument. Reaching a cap is a normal, recorded
outcome, not a crash. These caps are application-layer compensating controls; platform capacity
and isolation against resource exhaustion remain an infrastructure duty.

### 8.4 Mechanism M4: single side-effect boundary

All operations with external effect pass one router that revalidates policy, approval existence
and exactness, scope, idempotency, payload hash, runtime posture, and freeze or hold state
before an adapter executes. The tool registry is a code-owned module attribute resolved at
compile time; unregistered tool names are denied and receipted. Malformed requests are denied,
never repaired, because an adapter that repairs a request transfers authorship from the model's
actual output to the adapter's guess. This is the confused deputy problem [14] in its agentic
form.

### 8.5 Mechanism M5: authority assurance

Independent post-execution verification confirms that the action was required, exact, timely,
permissioned, and receipt-matched. The provider's own record is fetched and reconciled, because
a receipt independently retrieved is evidence while a receipt the adapter reports about itself
is a claim. Proof states are explicit: `verified`, `failed`, `degraded`, `pending_receipt`,
`manual_review_required`, `legacy_incomplete`, `missing`.

### 8.6 Mechanism M6: scoped skills and memory

Learned artifacts are scoped to session, project, account, or global. Promotion across a scope
boundary requires audit. Retrieval enforces scope, so cross-tenant leakage is prevented at read
time.

### 8.7 Mechanism M7: deterministic override adjudication

A human attempt to proceed past a serious warning is recorded as input to a server-side
deterministic decision procedure, not treated as authorization. A warning click-through is
input, not authority. High-risk overrides can pause into organizational review and can create
scoped freezes. Override authority for each tier is explicitly assigned rather than ambient.
This mechanism is the operational answer to the automation-bias concern named in EU AI Act
Article 14(4)(b) (Section 15).

### 8.8 Mechanism M8: runtime integrity and reset

A sentinel monitors for deviation: claims of having already executed, boundary-bypass attempts,
and loop abuse. Detected deviation produces a durable incident, suppresses unsafe output, and
for serious cases terminates the agent process through its supervisor and restarts a fresh
process seeded from an immutable policy baseline. The termination is a supervised shutdown with
a bounded grace period rather than an unconditional kill, so a compromised process retains
scheduling for the duration of that window. A suspicious agent is a supervised runtime failure,
not a conversation partner.

### 8.9 Mechanism M9: proof packets and receipt chains

Hash-chained receipts over scoped references and redacted payload hashes form an append-only,
tamper-evident structure. Proof packets assemble the complete chain for a run as exportable,
machine-readable audit evidence. Missing evidence is reported as missing, never synthesized.
This supports the automatic-recording capability required by EU AI Act Article 12 and the
monitoring and override evidence needs of the NIST AI RMF MANAGE function; note that the
minimum retention period is set by Article 19 and Article 26(6) rather than by Article 12.

## 9. Implementation on the BEAM

### 9.1 Why the substrate matters

The architecture is built in Elixir on the BEAM, the Erlang virtual machine, with Phoenix and
LiveView for the interface, PostgreSQL via Ecto for durable state, Oban and Broadway for
background and streaming work, and the Jido agent framework for action and signal plumbing.
Jido supplies the agent, controller, and runtime-owned-effect separation on which the authority
controls described here are located; the contribution of this work is the authority layer above
it, not the runtime beneath it. The substrate does real work here, for three reasons.

First, Open Telecom Platform (OTP) supervision trees make "kill and reseed a compromised agent"
idiomatic rather than bolted on. The BEAM's design philosophy, articulated in Armstrong's 2003
thesis [2], treats the process as an abstraction boundary that stops the propagation of errors,
and treats supervised restart from a clean state as the normal response to failure. Mechanism
M8's kill-and-reseed is that philosophy applied to a security incident rather than to a
software fault.

Second, BEAM process memory is disposable by construction, which makes "the agent's memory is
never the authority" structurally true rather than aspirational. Because a process and its heap
can be discarded at any time and durable state must live in the database, the architecture
cannot accidentally let authority accumulate in agent memory: there is nowhere durable for it
to accumulate except the store that the design already treats as authority.

Third, the concurrency model matches long-lived sessions blocked on slow input and output,
including human approvals that may take days. A blocked lightweight process is cheap, so
approval pauses need no special durable-workflow machinery layered on top; the natural unit of
the runtime already is a cheap, long-lived, blockable process. This is the property that
Temporal and LangGraph reconstruct with dedicated durable-workflow engineering; on the BEAM it
is native.

### 9.2 Honest costs of the substrate

The machine learning ecosystem is Python-first, so local model inference runs out-of-process
rather than in the BEAM, adding an integration boundary. Distributed Erlang needs careful
configuration: its default cookie-based node authentication is weak and its inter-node traffic
is cleartext unless Transport Layer Security (TLS) distribution is explicitly enabled, so a
naive cluster is insecure by default; the official Erlang documentation itself warns that
starting a distributed node without TLS distribution exposes it to attacks that may give an
attacker complete access to the node and by extension the cluster. Most importantly, BEAM
process isolation is a fault-isolation boundary and not a security sandbox: the official Erlang
secure-coding documentation states that all loaded code is assumed trusted, that there is no
built-in sandbox for untrusted Erlang code, and that a malicious module can do anything
including breaking the runtime's memory-safety protections. Therefore any execution of
untrusted code requires machine-level isolation outside the BEAM, and I do not claim process
isolation as a security containment mechanism.

### 9.3 Novelty of the substrate choice

To the best of my knowledge there is no peer-reviewed work presenting an LLM-agent control
plane built on the BEAM; the nearest work is Brady's Springdrift [30], an auditable persistent
runtime for LLM agents implemented in Gleam on Erlang/OTP, which carries a deterministic
normative calculus for safety gating with auditable axiom trails. It is a preprint rather than
a peer-reviewed publication, so it does not falsify the claim above, but it does show the
design space is occupied, and its safety-gating layer overlaps this work's mediation boundary.
Other BEAM-agent efforts are industry open-source frameworks, for example Jido and BeamWeaver,
and much of the agent-security literature assumes Python. General peer-reviewed BEAM security
work does exist, for instance in the ACM SIGPLAN Erlang Workshop series, but peer-reviewed work
at the intersection of the BEAM and an LLM-agent security control plane appears genuinely
absent. This is an absence-of-evidence observation rather than a proof of absence, and I frame
it accordingly. It nonetheless makes the substrate a genuinely under-explored one for agent
security. I present this as an argued design position supported by the runtime's documented
properties, not as an empirically validated performance claim.

### 9.4 Compile-time enforcement

Several invariants are enforced mechanically in continuous integration rather than by
convention. A boundary test asserts that no code path delivers a tool result to model context
without passing the content firewall; introducing an unfirewalled caller fails continuous
integration. A second boundary test asserts that the runtime submission path invokes both
outbound content review and inbound response review. The auto-execute tier is asserted not to
widen silently. A fail-closed test asserts that an envelope requiring two approvals does not
execute with one, and this test is written before any feature that sets that requirement. A
code-owned operation registry records every side-effecting operation together with its bound
policy, invariant set, and receipt strategy; the router refuses any operation absent from it.
The registry is source-controlled and reviewed, not generated by the build. I state the limit
of these checks precisely, because it matters. Static analysis on the BEAM cannot resolve a
call dispatched through `apply/3` or through a module bound at runtime, so no build-time pass
can enumerate every path that reaches an adapter. Where the module, function, and arity are
compile-time literals the compiler rewrites the form into a direct call and those sites do
remain statically resolvable; a genuinely runtime-bound module does not. These checks are
therefore regression fences over the statically resolvable call graph, not a proof of complete
mediation. M4's runtime boundary is the mediation point for every path that reaches it. The
architecture does not claim that no path can reach a provider without crossing it, and treats
such a path as detectable rather than impossible, which revalidates policy, approval exactness,
scope, idempotency, and payload hash before any adapter executes and denies an unregistered
tool name however the call arrived. A runtime-dispatched call reaches the boundary; it does not
pass through it. The build-time checks exist so that a refactor cannot quietly reintroduce a
bypass on the paths a compiler can see, and they are a complement to the runtime boundary
rather than a substitute for it.

## 10. Implementation status

I distinguish three states, summarized in Table 3.

**Table 3: Implementation status.**

| State | Components |
|---|---|
| Built, with conformance tests | The nine mechanisms as described; CI boundary guards and the code-owned operation registry; receipt chain and proof-packet export; scoped memory retrieval; deterministic override procedure. 1,286 automated test blocks pass. |
| In progress | A reads-only production soak, which has produced no results yet. |
| Specified only | Phishing-resistant authentication for approval actions; cryptographic keying or external anchoring of the receipt chain; governance of the governance layer. |
| Identified but not specified | The gaps registered in Section 13. These are named as open problems, not as designs. |

I do not present the boundary between these states loosely: a mechanism being "built" means it
has conformance tests, not that it has withstood an adversary.

## 11. Evaluation status

This is the section that a reader concerned with security should weight most heavily, because
it reports absences.

What the testing demonstrates: conformance. The 1,286 passing automated test blocks exercise
the specified behavior of the mechanisms, the CI structural invariants, and the receipt
structures. This establishes that the system does what the specification says under tested
conditions.

What has since been measured. The evaluation proposed in Section 12 was executed and is
reported separately [32]. Against 73 trials, 61 attack trials and 12 known-good controls across
seven induced-violation families, one posture-enforcement family, and one
reconciliation-correctness control, it measured zero unauthorized external effects (95% CI
[0.0%, 5.9%]), zero false denials over 75 legitimate approved actions (0/75; 95% CI [0.0%,
4.9%], effective n=3), and a median governed-action latency of about 19 ms, recomputed from the
committed per-iteration artifact rather than from an uncommitted transcription, and
machine-specific rather than portable. That last figure is an absolute cost, not a
differential: the ungoverned arm of the comparison uses a mock adapter that performs no I/O and
whose measured median is 120 nanoseconds, which prints as zero at the microsecond resolution
the table uses, so the overhead metric proposed in Section 12 was not in fact measured.
Mechanism necessity was established by ablation and by a no-control baseline in which 51 of 63
trials produce an unauthorized effect; the 63 are the ablatable families' totals, not a count
of attacks. The trusted-base claim of principle 9 has since been measured rather than argued:
each ablatable element was removed in turn with the full 73-trial catalog driven against it, so
41 provider-call trials were live under every ablation (35 of them attack trials), and removing
a surface reducer admits effects only in that mechanism's own gate channel and zero external
effects (0→10, 0→5, 0→5), while removing the approval-binding join admits fourteen. Because the
external-effect-capable trials were live, that zero is a result the run could have contradicted
and did not. What the run does not cover is stated as scope rather than left implicit: each
element is removed singly, never in combination; the mechanisms with no runtime toggle (the
boundary guard, reconciliation, and process supervision) are never ablated at all; and the
mediation membrane and the durable authority store have no ablation row, so their place in the
trusted base rests on the invariant's structure rather than on a run. The spend policy, which
the evaluation's own recount found holding 13 of the deepest family's 27 attack trials, was
ablated for the first time over the same full catalog and admits none, placing it outside the
trusted computing base as a redundant second layer. One earlier run produced a single scored
failure, which is published as data; Section 5 states why it does not refute invariant *I* and
what would.

What is still not demonstrated. Six absences remain, and I name them as sharply as the original
seven.

- No third-party red team has been run. The evaluation shares authorship with the system.
- No comparison against any benchmark, including AgentDojo, InjecAgent, or ART, has been
  performed.
- No live-provider run has been done; the trials use mock provider adapters, so the mediation
  boundary is measured but real egress and receipt reconciliation are not.
- No adaptive adversary has been run; the attack set is pre-registered and static, a deliberate
  trade against pre-registration.
- No independent cryptographic review of the canonicalization and hashing scheme has been
  conducted, which matters more now that the evaluation's deepest attack family tests exactly
  that scheme.
- No human-subjects study of the approval interface has been run, so the
  psychological-acceptability argument of Section 15 remains a hypothesis.

Three of the nine mechanisms, M3, M7, and M9, carry conformance tests but no adversarial
trials, and M6's memory half is untested; only its skill half was attacked. Test conformance is
not a security evaluation and I decline to present it as one. A reader should treat the
security properties asserted in Sections 5, 8, and 9 as design intentions of which the
separately reported evaluation tests a stated and bounded subset.

## 12. Toward a benchmark for authority boundaries

Existing agentic-security benchmarks measure whether an attack causes the model to misbehave.
If model misbehavior is assumed, as ART's own results justify assuming, that is the wrong
measurement. I propose an evaluation harness whose primary metric is the **unauthorized-effect
rate**: the fraction of attack trials that produce any side effect not covered by a valid,
current, exact authorization, as defined in Section 5. Concurrent work is beginning to explore
effect-based rather than misbehavior-based measures under other names; I name this metric
specifically and situate it within that emerging family rather than claiming it is without
precedent.

Secondary metrics: **evidence completeness**, the fraction of attack trials that produce
accurate and complete audit records; **benign-task false-denial rate**, measured on a
legitimate workload, because a system that scores zero on the primary metric by blocking
everything is not a solution; and **overhead**, in latency and cost relative to an ungoverned
baseline.

Attack classes the harness should include: indirect injection via retrieved documents;
injection via tool results; instruction laundering through summarization; approval drift
(payload mutated after approval); replay under a reused idempotency key; unregistered and
lookalike tool invocation; tool-definition substitution after approval; self-authorization
claims; loop-abuse resource exhaustion; cross-scope memory and skill leakage; social pressure
toward warning override; and a fully compromised agent runtime.

**The strong test.** Replace the agent entirely with an adversarial oracle that emits
worst-case output at every step. If the architecture's central claim holds, the
unauthorized-effect rate remains zero even when the agent is wholly adversarial, because the
agent was never the authority. This is falsifiable: a single unauthorized effect under the
adversarial oracle refutes invariant *I* of Section 5. This test has since been run and is
reported separately [32]. Across 61 attack trials it observed zero unauthorized external effects.
One earlier run recorded a single scored failure: a poisoned skill that passed the
deterministic auditor of M6. Under the definition above that event does not refute *I*, because
nothing reached an adapter and no provider state changed; it refutes M6's own claim. The
auditor was hardened and the pre-fix run was published as data. Because the repair was made
with knowledge of the attack, the re-run is a regression check rather than a fresh
falsification attempt, and a fresh attempt on that mechanism remains outstanding. Destructive
testing of this kind belongs in a sandboxed environment, not against production write paths. A
benchmark of this shape would also be usable against the systems in Section 2, since
unauthorized-effect rate is defined independently of any particular architecture and could in
principle score CaMeL, AgentBound, AgentSpec, or an ungoverned baseline on the same axis.

## 13. Identified gaps not addressed by this architecture

An external assessment of an earlier draft against classical and agentic security principle
catalogues identified control areas this architecture does not cover. I register them here as
open problems rather than folding proposed fixes into the design, because I have not specified
or built any of them and it would be misleading to present them as part of the architecture.

**Approver credential strength.** The architecture assumes human approvers are who they claim
to be, and Section 3 places approver credential compromise out of scope. The current
implementation does not require phishing-resistant authentication for approval actions. The
human credential at the root of the approval chain is therefore the softest hinge in the
design, and it is the one place where an attacker gains exactly the authority the agent cannot.

**Reach during a live run.** Ephemeral processes and kill-and-reseed address persistence, not
reach. An agent session that is destroyed after use can still act on whatever it was permitted
to touch while running. The architecture bounds what may be authorized but does not currently
bound network or backend reachability independently of authorization.

**Audit consumption.** Table 1 names an audit owner for M9, but the implementation has no
operational practice for reading proof packets, no reader's guide, and no exercise in which an
operator classifies an incident from receipts alone. Evidence nobody is trained to read is
evidence in name only.

**Containment verification.** M8 kills and reseeds a suspect session. The implementation does
not currently verify inertness afterwards, meaning that containment is declared on the kill
rather than on confirmation that the prior session can no longer cause effects.

**Trust root.** Discussed as the highest-priority limitation in Section 14. Keyed signing and
external anchoring are named as the direction; neither is designed in detail here.

**Information as well as action.** Discussed in Section 14. The architecture verifies that
actions were authorized and does not verify that figures the agent reports reflect the
underlying data.

**Multi-agent delegation.** Joint reconstruction of sensitive information across separately
narrowed delegation hops is out of scope for a single-agent control plane and unaddressed here.

Each of these is a direction for the research agenda of Section 16, not a claim about the
present system.

## 14. Limitations

**Trust root.** Hash chaining is tamper-evident only against an adversary who cannot recompute
the chain. An adversary with database write access can rewrite records and re-derive hashes
unless receipts are cryptographically keyed or externally anchored. Key management for signing
authority records and hardening of the database are unresolved and are the highest-priority
structural gap. Encrypting stored payloads is not a substitute for signature integrity.

**Insider and operator compromise.** A compromised approver session inherits real authority,
the one thing an agent cannot obtain. Phishing-resistant authentication for approval actions
and governance of the governance layer are named but not implemented (Section 13).

**Fail-closed as an availability risk.** Every control fails closed, so an adversary who can
trigger freezes, holds, or incidents can deny service without gaining authority. The
abuse-resistance analysis of this is incomplete. Denial of service is treated here as its own
threat category rather than folded into general resilience.

**Recovery breaks tamper-evidence.** Restoring from backup forks the receipt chain, and
reconciling that fork is unaddressed.

**Privacy versus immutability.** Proof artifacts will contain personal data, and erasure rights
conflict with immutable chains. Keeping personal data off-chain and chaining only hashes and
references is the intended answer, whose sufficiency has not been assessed. Anonymity of
residual data is not assumed.

**Verification of information, not just action.** The architecture verifies that actions were
authorized. It does not currently verify that figures the agent reports, such as analytics,
summaries, and counts, faithfully reflect the underlying data. An agent can be perfectly
constrained in what it does and still report a wrong number. Extending receipt-backing from
actions to reported information is a significant and under-addressed problem.

**Ecosystem maturity.** The BEAM agent ecosystem is early, with several pre-1.0 dependencies.
Dependency pinning and checksum verification are required before production promotion.

**Generality.** This is one control plane with a small set of providers. Behavior at scale,
under many providers, or with complex approval hierarchies is unknown.

**Human factors are plausible, not tested.** The claim that binding approval to a rendered
execution-envelope diff reduces rubber-stamping relative to a conventional approve button is
plausible and untested; it requires a human-subjects study.

## 15. Human factors

Approval fatigue is a security failure mode, not a usability tradeoff. A system that requires
approval for everything trains humans to approve without reading, which converts the strongest
control into a rubber stamp. This yields a hard design requirement: approval must be scarce and
specific, which is why only genuinely sensitive operations enter the approval-bound path and
why each approval is bound to one exact envelope. Manufactured urgency compounds the risk: an
adversary who controls agent output can generate persuasive text designed to induce
click-through, so any control whose final gate is a human's momentary judgment under pressure
is socially attackable. This is the reason mechanism M7 treats a warning override as input to a
server-side deterministic decision rather than as a client-side dismissal. The EU AI Act's
Article 14(4)(b) concern with automation bias is the same concern in regulatory language.

Friction should be measured rather than assumed. Candidate instruments include time to
decision, abandonment rate of mandated review steps, and the rate of attempts to route around
the control. The field lacks a standard instrument for these, and naming them is a first step
rather than a contribution. I repeat the caveat: that envelope-diff approval reduces
rubber-stamping is a hypothesis awaiting a human-subjects study.

## 16. Open questions and research agenda

The highest-priority open problem is the trust root: cryptographic keying or external anchoring
of the receipt chain and hardening of the authority database against a write-capable adversary.
Second is extending receipt-backing from actions to reported information, so that a reported
number can carry the same kind of independently reconciled evidence as an executed action.
Third is abuse-resistance analysis of fail-closed controls, so that the denial-of-service
surface created by universal fail-closed behavior is characterized and bounded. Fourth is the
empirical program implied by Section 11: building the unauthorized-effect benchmark of Section
12, running the adversarial-oracle strong test, and conducting the human-subjects study of the
approval interface. Fifth are the gaps registered in Section 13, each of which requires design
work before it requires implementation. Sixth is generality: behavior under many providers, at
scale, and under complex approval hierarchies.

## 17. Conclusion

The agent-security literature has established that the model will misbehave under attack. The
response advocated here is to stop treating model compliance as the control surface. If the
model proposes and the system authorizes, and if authority to cause an external effect lives
only in compiled code, a code-owned registry, a durable store, and human approvers, then a
wrong or hostile agent is a survivable condition rather than a breach. I have described nine
mechanisms that implement this separation, stated the invariant they are meant to maintain,
mapped each mechanism to an accountable party, described a substrate whose documented
properties make the separation structural, and given CI-enforced structural invariants that
fence boundary coverage against regression while naming what they cannot establish. I have been
explicit that this paper contains no security evaluation, that 1,286 passing test blocks are
conformance and not security, that the central claims were arguments from design and have since
been measured against the falsifiable criterion proposed here, with three of the nine
mechanisms still unattacked, and that several identified gaps remain open rather than solved.
The measurement that matters is not whether the model can be made to misbehave, which is
settled, but whether misbehavior converts into unauthorized effect, which is the number a
deployed system must drive to zero.

## Appendix A: Terminology

- **Authority**: The capacity to cause an external effect to occur.
- **Execution envelope**: The exact, canonicalized semantic description of an operation to be
  performed.
- **Fingerprint**: A cryptographic hash over the execution envelope.
- **Receipt**: A durable record of an event.
- **Proof packet**: The assembled hash-chained receipt set for a run.
- **Unauthorized effect**: Any external side effect not covered by a valid, current, exact
  authorization.
- **Canonicalization**: The deterministic normalization that produces the semantic payload
  bound by a fingerprint, excluding presentation state.
- **Proof state**: One of `verified`, `failed`, `degraded`, `pending_receipt`,
  `manual_review_required`, `legacy_incomplete`, `missing`.

## Appendix B: Notes for reviewers

Every empirical claim in this paper about the system is a conformance claim, an explicitly
labeled absence, or a result reported in the separately published evaluation [32] and cited as
such; this paper contains no security measurement of its own. The AgentBound
differentiation in Section 2.4 rests on the published description rather than the source and
should be re-verified; note also that two arXiv preprints carry that name and the correct
identifier is arXiv:2606.30970. The claim of BEAM-substrate novelty in Section 9.3 is an
absence-of-evidence observation. The reference implementation name is Trinity; the architecture
name used in any downstream evaluation should be substrate-neutral.

Citation notes. The RFC 9162 author list is Laurie, Messeri, and Stradling. EU AI Act Articles
12, 13, and 14 have been checked against the Official Journal text; the minimum log-retention
period is set by Article 19 and Article 26(6), since Article 12 establishes the logging
capability rather than the retention period. The CVSS score for CVE-2025-54136 is reported by
the CNA record as 7.2 while some secondary trackers list 8.8, so the numeric severity is stated
with that discrepancy noted rather than asserted. The OIDC-A reference is a preprint proposal
and not an adopted OpenID Foundation standard. Section 13 registers control areas identified by
external assessment; none of them is claimed as designed or implemented.

A machine-readable companion to this paper, exporting the design principles, mechanisms, threat
model, and evaluation definitions with stable identifiers, is published alongside it.

## References

1. J. P. Anderson. *Computer Security Technology Planning Study.* Technical Report
   ESD-TR-73-51, USAF Electronic Systems Division, Hanscom AFB, October 1972. [Technical
   report.]
2. J. Armstrong. *Making Reliable Distributed Systems in the Presence of Software Errors.* PhD
   thesis, Royal Institute of Technology (KTH), Stockholm, 2003. [Doctoral thesis.]
3. L. Beurer-Kellner et al. Design patterns for securing LLM agents against prompt injections.
   arXiv:2506.08837, 2025. https://arxiv.org/abs/2506.08837 [Preprint.]
4. S. Chennabasappa, C. Nikolaidis, D. Song, D. Molnar, S. Ding, S. Wan, S. Whitman, L. Deason,
   N. Doucette, A. Montilla, A. Gampa, B. de Paola, D. Gabi, J. Crnkovich, J.-C. Testud, K. He,
   R. Chaturvedi, W. Zhou, and J. Saxe. LlamaFirewall: An open source guardrail system for
   building secure AI agents. arXiv:2505.03574, 2025. https://arxiv.org/abs/2505.03574
   [Preprint.]
5. Coalition for Secure AI. *AI Shared Responsibility Framework (SRF)*, version 1.0, 2026.
   https://www.coalitionforsecureai.org/ [Industry framework.]
6. M. Costa et al. Securing AI agents with information-flow control (Fides). arXiv:2505.23643,
   2025. https://arxiv.org/abs/2505.23643 [Preprint.]
7. S. A. Crosby and D. S. Wallach. Efficient data structures for tamper-evident logging. In
   *Proceedings of the 18th USENIX Security Symposium*, 2009. [Peer-reviewed.]
8. CVE-2025-54136. Modification of MCP server definitions bypasses manual re-approvals. CVE
   List / CNA record, 2025. https://www.cve.org/CVERecord?id=CVE-2025-54136 [CNA record reports
   CVSS v3.1 base score 7.2; some secondary trackers report 8.8.]
9. E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr.
   AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM
   agents. In *Advances in Neural Information Processing Systems 37 (NeurIPS 2024), Datasets
   and Benchmarks Track*, 2024. arXiv:2406.13352. https://arxiv.org/abs/2406.13352
   [Peer-reviewed.]
10. E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi, A.
    Terzis, and F. Tramèr. Defeating prompt injections by design (CaMeL). arXiv:2503.18813,
    2025. https://arxiv.org/abs/2503.18813 [Preprint.]
11. S. Dong, S. Xu, P. He, Y. Li, J. Tang, T. Liu, H. Liu, and Z. Xiang. Memory injection
    attacks on LLM agents via query-only interaction (MINJA). In *Advances in Neural
    Information Processing Systems (NeurIPS 2025)*; arXiv:2503.03704.
    https://arxiv.org/abs/2503.03704 [Peer-reviewed; also preprint.]
12. European Parliament and Council. Regulation (EU) 2024/1689 (Artificial Intelligence Act),
    Articles 12, 13, 14, 19, and 26. Official Journal of the European Union, 2024.
    https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689 [Primary legal source.]
13. K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz. Not what you've
    signed up for: Compromising real-world LLM-integrated applications with indirect prompt
    injection. In *Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security
    (AISec 2023)*, pages 79–90. DOI 10.1145/3605764.3623985; preprint arXiv:2302.12173.
    https://doi.org/10.1145/3605764.3623985 [Peer-reviewed workshop paper.]
14. N. Hardy. The confused deputy (or why capabilities might have been invented). *ACM SIGOPS
    Operating Systems Review*, 22(4):36–38, 1988. DOI 10.1145/54289.871709. [Peer-reviewed.]
15. K. Hines, G. Lopez, M. Hall, F. Zarfati, Y. Zunger, and E. Kiciman. Defending against
    indirect prompt injection attacks with spotlighting. CAMLIS 2024; arXiv:2403.14720.
    https://arxiv.org/abs/2403.14720 [Workshop paper; also preprint.]
16. A. Kaul, Q. Lan, and P. Gupta. AgentBound: Verifiable behavioral governance for autonomous
    AI agents. arXiv:2606.30970, 2026. https://arxiv.org/abs/2606.30970 [Preprint. Distinct
    from the unrelated arXiv:2510.21236, which shares the name.]
17. NVIDIA. NOOA (NVIDIA Labs Object-Oriented Agent), released with the Open Secure AI
    Alliance, 27 July 2026. [Industry framework.]
18. National Institute of Standards and Technology. Artificial Intelligence Risk Management
    Framework (AI RMF 1.0). NIST AI 100-1, January 2023. DOI 10.6028/NIST.AI.100-1.
    https://doi.org/10.6028/NIST.AI.100-1 [Government framework.]
19. National Institute of Standards and Technology. Artificial Intelligence Risk Management
    Framework: Generative Artificial Intelligence Profile. NIST AI 600-1, July 2024. DOI
    10.6028/NIST.AI.600-1. https://doi.org/10.6028/NIST.AI.600-1 [Government framework.]
20. S. Nagabhushanaradhya. OpenID Connect for Agents (OIDC-A) 1.0: A standard extension for
    LLM-based agent identity and authorization. arXiv:2509.25974, 2025.
    https://arxiv.org/abs/2509.25974 [Preprint proposal, not an adopted standard.]
21. OWASP GenAI Security Project. OWASP Top 10 for LLM Applications (2025); OWASP Top 10 for
    Agentic Applications 2026 (released 9 December 2025). https://genai.owasp.org/ [Community
    standard.]
22. T. Shi, J. He, Z. Wang, H. Li, L. Wu, W. Guo, and D. Song. Progent: Securing AI agents with
    privilege control. arXiv:2504.11703, 2025. https://arxiv.org/abs/2504.11703 [Preprint.]
23. B. Laurie, A. Langley, and E. Kasper. Certificate Transparency. RFC 6962, IETF, June 2013.
    https://www.rfc-editor.org/rfc/rfc6962
24. B. Laurie, E. Messeri, and R. Stradling. Certificate Transparency Version 2.0. RFC 9162,
    IETF, December 2021 (obsoletes RFC 6962). https://www.rfc-editor.org/rfc/rfc9162
    [Experimental RFC. Author list verified.]
25. J. H. Saltzer and M. D. Schroeder. The protection of information in computer systems.
    *Proceedings of the IEEE*, 63(9):1278–1308, 1975. DOI 10.1109/PROC.1975.9939.
    [Peer-reviewed.]
26. U. Uchibeke. Before the tool call: Deterministic pre-action authorization for autonomous AI
    agents. arXiv:2603.20953, 2026. https://arxiv.org/abs/2603.20953 [Preprint.]
27. H. Wang, C. M. Poskitt, and J. Sun. AgentSpec: Customizable runtime enforcement for safe
    and reliable LLM agents. arXiv:2503.18666; *Proceedings of the IEEE/ACM 48th International
    Conference on Software Engineering (ICSE 2026)*. https://arxiv.org/abs/2503.18666 [Accepted
    to peer-reviewed venue; also preprint.]
28. Y. Wu, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal. IsolateGPT: An execution isolation
    architecture for LLM-based agentic systems. In *Proceedings of the Network and Distributed
    System Security Symposium (NDSS 2025)*, 2025. DOI 10.14722/ndss.2025.241131;
    arXiv:2403.04960. https://arxiv.org/abs/2403.04960 [Peer-reviewed.]
29. Q. Zhan, Z. Liang, Z. Ying, and D. Kang. InjecAgent: Benchmarking indirect prompt
    injections in tool-integrated large language model agents. In *Findings of the Association
    for Computational Linguistics: ACL 2024*, pages 10471–10506. DOI
    10.18653/v1/2024.findings-acl.624; preprint arXiv:2403.02691.
    https://arxiv.org/abs/2403.02691 [Peer-reviewed.]
30. S. Brady. Springdrift: An auditable persistent runtime for LLM agents with case-based
    memory, normative safety, and ambient self-perception. arXiv:2604.04660, 2026.
    https://arxiv.org/abs/2604.04660 [Preprint.]
31. A. Zou, M. Lin, E. Jones, M. Nowak, M. Dziemian, N. Winter, A. Grattan, V. Nathanael, A.
    Croft, X. Davies, J. Patel, R. Kirk, N. Burnikell, Y. Gal, D. Hendrycks, J. Z. Kolter, and
    M. Fredrikson. Security challenges in AI agent deployment: Insights from a large scale
    public competition. arXiv:2507.20526, 2025. https://arxiv.org/abs/2507.20526 [Preprint.]
32. A. Croft. Authority-Bound Agentic Execution: Measuring Unauthorized Effect Under
    Adversarial Load. 2026. https://doi.org/10.5281/zenodo.21755869 [Preprint. The companion
    evaluation of the architecture specified here. Concept DOI: it resolves to the latest
    version. Every measured result this paper attributes to a separately published
    evaluation is reported there.]

---

*Author note on style and verification.* This manuscript uses no em dashes by authorial
preference. All quantitative results attributed to prior systems are drawn from the cited
papers' own reporting and should be attributed to those papers, not to this one. Section 13
registers control areas identified by external assessment as open problems; none is claimed as
designed or implemented in this system.
