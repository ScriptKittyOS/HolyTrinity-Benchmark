defmodule HolyTrinity.Trial do
  @moduledoc """
  The HolyTrinity Bench trial record — one JSON object per attack trial.

  Schema is frozen in `spec/SPEC.md` §7. This struct is the in-memory
  form; `to_map/1` produces the exact JSON shape appended to `results/<run_id>.jsonl`.

  A trial record is only ever produced by the `HolyTrinity.Runner`, which composes
  the `HolyTrinity.Aggressor` (attack) with the `HolyTrinity.Oracle` (independent
  verdict). The `system_proof_state` field is Trinity's own claim — recorded as a
  MEASURED output for the confusion matrix, never consulted to decide the verdict.
  """

  @spec_version "holytrinity.v1"
  @invariant_set_version "authority_assurance.v1"

  @enforce_keys [:run_id, :trial_id, :family, :variant]
  defstruct spec_version: @spec_version,
            run_id: nil,
            trial_id: nil,
            family: nil,
            mechanism_id: nil,
            variant: nil,
            description: nil,
            attack_target: nil,
            timestamp_start: nil,
            timestamp_end: nil,
            proposed_action: %{},
            agent_proposed_violation: nil,
            effects_observed: [],
            authorization_snapshot_ref: nil,
            oracle_verdict: nil,
            oracle_rationale: nil,
            outcome: nil,
            detection_source: nil,
            detection_latency_ms: nil,
            system_proof_state: nil,
            oracle_system_agreement: nil,
            # --- canonicalization cross-check (SPEC §7 additive extension) ---
            #
            # F4's disclosed circularity: the Oracle decided payload identity with
            # `AuthorityAssurance.canonical_payload_hash/1`, a function inside the system
            # under test, so a semantic collision would make the system permit the mutated
            # payload and the Oracle score it `authorized` — in agreement, leaving no trace.
            # These fields publish the comparison. `HolyTrinity.Oracle.Canonical` hashes the
            # same payload under an independently-specified scheme, and
            # `Oracle.canonical_cross_check/2` fills this map in.
            #
            # The VERDICT above is still computed from the system's hash, unchanged. These
            # are measured outputs, exactly like `system_proof_state`: recorded, never an
            # input to `oracle_verdict`.
            #
            # Shape (see `Oracle.canonical_cross_check/2` for the full contract):
            #   oracle_canonical_version, system_canonical_version — the two schemes; the
            #     two digests are NOT comparable to each other, only the relations they assert
            #   system_canonical_hash, oracle_canonical_hash — H_sut / H_oracle of the
            #     EXECUTED payload
            #   approved_payload_hash — H_sut of the approved envelope, from the raw fingerprint
            #   system_matches_approved — the system's "same payload?" answer (verdict input)
            #   oracle_matches_approved — the independent answer, or null when the approved
            #     payload is not recoverable
            #   canonical_hash_agrees — whether the two answers agree. NULL when uncomputable,
            #     never `true`; an uncomputable check must not read as a passing one.
            #   approval_record_fields_match — clause (b) read straight off the raw
            #     approval_requests columns, with no canonicalizer on either side
            #   status — :compared | :approved_payload_not_persisted | :no_payload
            #
            # SPEC §7 DEPARTURE (additive): §7's record shape does not list these fields.
            # They are added, not substituted; every §7 field keeps its meaning and its
            # value. Recorded in spec/PACKAGING-NOTES.md alongside the `outcome` extensions
            # rather than by editing the frozen spec.
            canonical_cross_check: nil,
            scorer: "auto",
            notes: nil,
            commit_sha: nil,
            config_hash: nil,
            invariant_set_version: @invariant_set_version

  @type verdict :: :authorized | :unauthorized | :undecidable
  # SPEC §7 enumerates prevented | detected | undetected. The harness also emits `allowed`
  # (a correctly authorized effect on a known-good control), `harness_error` (a crashed
  # trial), and `undecidable` (the outcome-level counterpart of the §2.3 verdict, excluded
  # from both numerator and denominator and reported as its own count). Recorded in
  # spec/PACKAGING-NOTES.md rather than by editing the frozen spec.
  @type outcome ::
          :prevented | :detected | :undetected | :allowed | :harness_error | :undecidable

  @type t :: %__MODULE__{}

  def spec_version, do: @spec_version

  @doc """
  A trial record for a harness error (a trial that crashed). Recorded so a failure is
  visible in the results rather than silently dropped (SPEC §10).
  """
  def harness_error(run_id, family, variant, message) do
    now = DateTime.utc_now()

    %__MODULE__{
      run_id: run_id,
      trial_id: "#{family}-#{variant}-error-#{System.unique_integer([:positive])}",
      family: family,
      variant: variant,
      description: "harness error",
      timestamp_start: now,
      timestamp_end: now,
      agent_proposed_violation: nil,
      oracle_verdict: :undecidable,
      oracle_rationale: "trial did not complete",
      outcome: :harness_error,
      detection_source: :none,
      system_proof_state: "not_applicable",
      scorer: "auto",
      notes: "HARNESS ERROR: #{message}"
    }
  end

  @doc "Serialize to the frozen SPEC §7 JSON shape."
  def to_map(%__MODULE__{} = t) do
    t
    |> Map.from_struct()
    |> Map.new(fn {k, v} -> {Atom.to_string(k), jsonable(v)} end)
  end

  @doc "Encode one trial as a single JSONL line."
  def to_jsonl(%__MODULE__{} = t), do: Jason.encode!(to_map(t))

  defp jsonable(v) when is_atom(v) and not is_boolean(v) and not is_nil(v), do: Atom.to_string(v)
  defp jsonable(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp jsonable(list) when is_list(list), do: Enum.map(list, &jsonable/1)

  defp jsonable(map) when is_map(map) and not is_struct(map),
    do: Map.new(map, fn {k, v} -> {to_string(k), jsonable(v)} end)

  defp jsonable(v), do: v
end
