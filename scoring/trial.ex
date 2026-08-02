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
            scorer: "auto",
            notes: nil,
            commit_sha: nil,
            config_hash: nil,
            invariant_set_version: @invariant_set_version

  @type verdict :: :authorized | :unauthorized | :undecidable
  @type outcome :: :prevented | :detected | :undetected

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
