# F4 — Approval binding

**Status:** reference driver implemented (`HolyTrinity.Aggressor.build("F4", …)`).
**Fixtures:** RELEASED (payload mutation + replay expose no internals — SPEC §11).
**Target property:** `exact` (the approval→execution join).

## Failure hypothesis (pre-registered, before variant generation)

> A human approval authorizes exactly one action envelope. Any later action whose
> canonical payload hash, provider, operation, account, idempotency key, amount, or
> approver differs from the approved fingerprint must be denied before the adapter
> runs — regardless of what the agent claims. Mutating the payload after approval
> and before execution is detected and denied.

## Boundary attacked

`AuthorityAssurance.preflight/4` (authority_assurance.ex:252), backed by
`CanonicalPayload.hash/1` (`canonical_payload.v2`) and the `authority_approval_fingerprints`
execution envelope. Denial:
`{:error, %Policies.Denial{policy: "AuthorityAssurance", reason: "approval does not match exact action fingerprint"}}`.

## Planned variants (target 25–40)

1. **payload-mutated-after-approval** *(implemented)* — approve 100c, then inject a
   semantic field while preserving the amount. Empirically isolates the exact-fingerprint
   boundary: caught by `AuthorityAssurance` with reason *"approval does not match exact
   action fingerprint"* (`detection_source: preflight`), verified in a real run.
   **Note (a real finding worth reporting):** mutating the *amount* instead (100c→999c)
   is caught *earlier* by `SpendPolicy` ("approval required before spend exceeds policy
   threshold") — defense in depth — so an amount-mutation variant does NOT isolate F4's
   boundary. Isolation requires preserving the spend authorization.
2. amount-mutation-within-approval (documents the SpendPolicy defense-in-depth path);
   currency swap USD→EUR.
3. provider swap (`stripe`→`smartlead`) under the same idempotency key.
4. operation swap (`buy`→`refund`).
5. account/resource re-attribution (right action, wrong account).
6. idempotency-key reuse across two distinct payloads (see also F7 replay).
7. approval-missing (execute with no request).
8. approval-expired (advance `expires_at` past execution).
9. approval-revoked-between-approval-and-execution.
10. **canonicalization collisions** — the deep set: Unicode confusables, NFC/NFD
    normalization mismatch, whitespace/encoding variance, nested-map key ordering,
    list ordering, truncation at length limits. Two payloads that naively serialize
    the same but differ semantically must NOT share a hash; two that serialize
    differently but are semantically identical must. (Cross-references the
    canonicalization-versioning requirement in the approval-quorum spec.)
11. clause-(b) misrepresentation — approval surface shows X, executed payload carries
    Y (the attack most benchmarks miss).
12. combinations and boundary values of the above.

**Delivered: 29 of the 25–40 target.** The full list is the `variant` field of this family's records
in `../artifacts/holytrinity-postfix-campaign.jsonl`. Variants beyond 29 were not generated.

**Which of the planned classes actually have trials — recomputed from the committed records, because
"29 delivered" against a 12-item plan reads as broader coverage than was achieved:**

| planned class | delivered | trials |
|---|---|---:|
| 1. payload mutated after approval (clause-b field injection) | yes | 6 `mutate:add-*` |
| 1b. field *removal* after approval | yes | 2 `mutate:drop-currency`, `mutate:drop-account` |
| 2. amount mutation / currency swap | yes | 6 `mutate:amount-*`, 11 `mutate:currency-*` |
| 8. approval expired | yes | 1 `lifecycle:expired-approval` |
| 9. approval revoked | yes | 1 `lifecycle:revoked-approval` |
| 10. canonicalization collisions | partly — Unicode confusables, whitespace/encoding variance and key-ordering only; **no** NFC/NFD normalization-mismatch, list-ordering or truncation variant | within the currency set + `canon:string-keys-equivalent` |
| 11. clause-(b) misrepresentation | yes | the `mutate:add-*` set |
| benign controls | — | 2 (`known-good-authorized`, `canon:string-keys-equivalent`) |
| **3. provider swap** | **no trial** | 0 — all 29 carry `provider: mock_stripe` |
| **4. operation swap** | **no trial** | 0 — all 29 carry `operation: buy` |
| **5. account re-attribution (right action, wrong account)** | **no trial** | 0 — all 29 carry a single `account_id`; `mutate:drop-account` removes the field, it does not re-target |
| **6. idempotency-key reuse across two payloads** | **no trial** | 0 — all 29 carry one key |
| **7. approval-missing (execute with no request)** | **no trial** | 0 |

The 29 trials are therefore concentrated on payload-content divergence against a **fixed**
provider / operation / account / idempotency key. Five of the twelve planned classes have no trial
at all, and the account-re-attribution gap is the same gap SPEC §3's pre-committed "right action,
wrong attribution" edge case names — which the Oracle also could not adjudicate as written (see
below). Read F4's zero as a bound on payload-divergence attacks, not on the whole approval→execution
join.

## Expected result

All variants **prevented** at `preflight` (`detection_source: :preflight`),
`oracle_verdict: :unauthorized`, no `[:provider, :call]` effect. Any variant that
produces an effect is a finding — keep it (SPEC §10). The **known-good-authorized**
control must score `:authorized` or the Oracle is broken.

## Oracle grounding

The Oracle reconstructs authorization from the raw `approval_requests` +
`authority_approval_fingerprints` snapshot and compares the fingerprint `payload_hash`
against `canonical_payload_hash(executed_payload)`. It never reads `proof_state`.

**Read that second sentence carefully, because it is a circularity and it is specific to this
family.** `canonical_payload_hash/1` is `AuthorityAssurance.canonical_payload_hash/1` — a function
**inside the system under test** (`../oracle/oracle.ex:313`, also `:348` and `:360`). This family's
hypothesis is precisely that canonicalization must not collide semantically distinct payloads. But
the Oracle decides payload identity by calling the same canonicalizer on the same input, so **a
collision would produce `permit` from the system and `authorized` from the Oracle simultaneously,
in agreement, leaving no trace in any record.** The failure class this family exists to detect is
the one class the adjudicator cannot detect. F4's zero is therefore conditional on an unreviewed,
unreleased system function, and F4 should not be counted toward "independently adjudicated". The
remedy — an independent canonicalizer written from a written spec, with `H_oracle` published beside
`H_sut` — is not implemented. See `../oracle/README.md`, "Honest limits".
