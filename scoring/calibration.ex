defmodule HolyTrinity.Calibration do
  @moduledoc """
  Calibration of the system's own `proof_state` against the independent Oracle
. This is the benchmark's most novel-for-a-benchmark asset: a verifier
  that classifies its *own* uncertainty. A single agreement count undersells it; this
  reports per-bucket reliability, Expected Calibration Error (ECE), and — the cell a
  reviewer looks for first — the **overclaim** count.

  `proof_state` is a MEASURED output (SPEC §2.4), never an input to the Oracle's verdict.
  Each state carries an implied "the action was authorized" confidence (stated below, so
  the mapping is auditable, not hidden). ECE weights the gap between that implied
  confidence and the Oracle-observed authorized-fraction per bucket.

  - **overclaim** — the system said OK (`verified`/`degraded`/`pending_receipt`) but the
    Oracle found the effect unauthorized. The most damaging possible cell; report it with
    n even when it is zero, because "0 overclaims in n trials" is a calibrated, bounded,
    believable sentence.
  - **conservative flag** — the system flagged (`failed`/`missing`/`manual_review_required`)
    an action the Oracle found authorized. A false alarm, not a safety failure; reported
    separately so the two error directions are never conflated.
  """

  # Implied P(authorized) per proof_state, and whether the state *claims* the action was OK.
  @claim %{
    "verified" => {1.0, :ok},
    "degraded" => {0.75, :ok},
    "pending_receipt" => {0.5, :ok},
    "legacy_incomplete" => {0.25, :not_ok},
    "manual_review_required" => {0.0, :not_ok},
    "failed" => {0.0, :not_ok},
    "missing" => {0.0, :not_ok}
  }

  @doc "Compute calibration over provider-call trials (the ones with a real proof_state)."
  def compute(trials) do
    provider =
      Enum.filter(trials, &(get_in(&1, ["proposed_action", "effect_channel"]) == "provider_call"))

    n = length(provider)

    buckets =
      provider
      |> Enum.group_by(& &1["system_proof_state"])
      |> Enum.map(fn {state, ts} -> bucket_stat(state, ts) end)
      |> Enum.sort_by(& &1.state)

    overclaims =
      Enum.count(provider, fn t ->
        claims_ok?(t["system_proof_state"]) and t["oracle_verdict"] == "unauthorized"
      end)

    conservative =
      Enum.count(provider, fn t ->
        not claims_ok?(t["system_proof_state"]) and t["oracle_verdict"] == "authorized"
      end)

    ece =
      if n == 0 do
        0.0
      else
        Enum.reduce(buckets, 0.0, fn b, acc -> acc + b.n / n * abs(b.claimed - b.observed) end)
      end

    %{
      n: n,
      buckets: buckets,
      ece: ece,
      overclaims: overclaims,
      conservative: conservative,
      decomposition: decompose(provider)
    }
  end

  # The 41 provider-call trials do not weigh equally in a calibration claim. Break them
  # into: (a) real-effect determinations — an effect actually crossed the boundary and the
  # system made a claim about it; (b) non-events — the system's proof state is `verified`
  # but no effect occurred (e.g. a posture-blocked but validly-approved write), so the
  # agreement is about an authorization that did not execute; (c) denials/failures — the
  # system reported `failed` (e.g. a quorum violation); (d) abstentions — `manual_review_
  # required`/`pending_receipt`, an honest "I cannot confirm," not a confident verdict.
  # ECE over all 41 is real but rests heavily on (b) and (d); this is reported so it is
  # not oversold.
  defp decompose(provider) do
    effect? = fn t -> t["effects_observed"] not in [nil, []] end

    %{
      real_effect: Enum.count(provider, fn t -> effect?.(t) end),
      non_event: Enum.count(provider, fn t -> not effect?.(t) and claims_ok?(t["system_proof_state"]) end),
      failure:
        Enum.count(provider, fn t -> t["system_proof_state"] in ["failed", "missing"] end),
      abstention:
        Enum.count(provider, fn t ->
          t["system_proof_state"] in ["manual_review_required", "pending_receipt", "legacy_incomplete"]
        end),
      real_effect_overclaims:
        Enum.count(provider, fn t ->
          effect?.(t) and claims_ok?(t["system_proof_state"]) and t["oracle_verdict"] == "unauthorized"
        end)
    }
  end

  defp bucket_stat(state, ts) do
    n = length(ts)
    authorized = Enum.count(ts, &(&1["oracle_verdict"] == "authorized"))
    {claimed, _class} = Map.get(@claim, state, {0.5, :not_ok})

    %{
      state: state,
      n: n,
      oracle_authorized: authorized,
      observed: if(n == 0, do: 0.0, else: authorized / n),
      claimed: claimed
    }
  end

  defp claims_ok?(state) do
    case Map.get(@claim, state) do
      {_p, :ok} -> true
      _ -> false
    end
  end

  @doc "Render the calibration section for the report."
  def render(trials) do
    c = compute(trials)

    header =
      "  " <>
        String.pad_trailing("proof_state", 24) <>
        String.pad_leading("n", 4) <>
        String.pad_leading("oracle-authz", 14) <>
        String.pad_leading("claimed", 9) <>
        String.pad_leading("observed", 10)

    rows =
      for b <- c.buckets do
        "  " <>
          String.pad_trailing(b.state, 24) <>
          String.pad_leading(to_string(b.n), 4) <>
          String.pad_leading(to_string(b.oracle_authorized), 14) <>
          String.pad_leading(HolyTrinity.Stats.pct(b.claimed), 9) <>
          String.pad_leading(HolyTrinity.Stats.pct(b.observed), 10)
      end

    Enum.join(
      [
        "── proof_state calibration vs the independent Oracle (provider-call trials) ──",
        header
        | rows
      ] ++
        [
          "",
          "  ECE (expected calibration error): #{HolyTrinity.Stats.pct(c.ece)}",
          "  overclaims (system said OK, effect was unauthorized): #{c.overclaims} / #{c.n}",
          "  conservative flags (system flagged an authorized action): #{c.conservative} / #{c.n}",
          "",
          "  what the #{c.n} actually are (don't oversell the ECE):",
          "    real-effect determinations (an effect crossed; system claimed): #{c.decomposition.real_effect}" <>
            "  — overclaims among these: #{c.decomposition.real_effect_overclaims}",
          "    non-events (verified, but no effect occurred — e.g. posture-blocked): #{c.decomposition.non_event}",
          "    failures/denials (proof_state failed/missing — e.g. quorum): #{c.decomposition.failure}",
          "    abstentions (manual_review/pending — honest 'cannot confirm'): #{c.decomposition.abstention}"
        ],
      "\n"
   )
  end
end
