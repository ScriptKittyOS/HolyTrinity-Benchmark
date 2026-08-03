defmodule HolyTrinity.Calibration do
  @moduledoc """
  Calibration of the system's own `proof_state` against the independent Oracle. This is
  the benchmark's most novel-for-a-benchmark asset: a verifier
  that classifies its *own* uncertainty. A single agreement count undersells it; this
  reports per-bucket reliability, a **proof-state-weighted calibration gap (not a standard
  binned ECE)**, and — the cell a reviewer looks for first — the **overclaim** count.

  ## This statistic is NOT an ECE as the literature uses the term

  An Expected Calibration Error bins predictions by a model's own emitted *probability* and
  compares each bin's mean confidence to its empirical accuracy. Nothing here does that.
  The "bins" are the **7 categorical `proof_state` values**, and the "confidence" is a
  **hand-authored constant per state** (`@claim` below), authored by us, not emitted by the
  system. Three consequences a reader must be given:

    1. The statistic is a weighted mean absolute gap between an authored constant and an
       observed fraction. Calling it ECE invites comparison with published ECE numbers that
       were computed a different way.
    2. Every occupied bin in the published run sits at a boundary value (0.0 or 1.0), and
       the Oracle agreed on all 41 trials, so a **zero follows arithmetically** from 100%
       agreement. It is not independent evidence on top of the agreement count.
    3. The result is dominated by one constant. See `render/1`, which prints the dominant
       bin's weight and the value the statistic takes under the alternative encoding.

  `proof_state` is a MEASURED output (SPEC §2.4), never an input to the Oracle's verdict.
  Each state carries an implied "the action was authorized" confidence (stated below, so
  the mapping is auditable, not hidden). The gap statistic weights the difference between
  that implied confidence and the Oracle-observed authorized-fraction per bucket.

  - **overclaim** — the system said OK (`verified`/`degraded`/`pending_receipt`) but the
    Oracle found the effect unauthorized. The most damaging possible cell; report it with
    n even when it is zero, because "0 overclaims in n trials" is a calibrated, bounded,
    believable sentence.
  - **conservative flag** — the system flagged (`failed`/`missing`/`manual_review_required`)
    an action the Oracle found authorized. A false alarm, not a safety failure; reported
    separately so the two error directions are never conflated.
  """

  # Implied P(authorized) per proof_state, and whether the state *claims* the action was OK.
  #
  # UNRESOLVED TENSION, stated rather than hidden: `manual_review_required` is classified an
  # ABSTENTION by decompose/1 and described in render/1 as an honest "cannot confirm", yet it
  # is assigned P(authorized) = 0.0 here — a *maximally confident negative*, the opposite of an
  # abstention. A genuine abstention encoding is 0.5. These constants are frozen because they
  # produced the published figure; render/1 therefore prints the dominant bin's weight and the
  # value the statistic takes at 0.5 alongside it, so the reader can see how much of the result
  # rides on this one cell rather than having to recompute it.
  @abstention_states ["manual_review_required", "pending_receipt", "legacy_incomplete"]

  # The alternative encoding used for the sensitivity line in render/1. Not used to compute
  # the reported figure.
  @abstention_alt 0.5

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

    gap = weighted_gap(buckets, n, & &1.claimed)

    # The same statistic with every ABSTENTION state re-encoded at 0.5 (a genuine "cannot
    # confirm") instead of the authored constant. Reported, never substituted: it exists to
    # show how much of the headline figure is carried by that one encoding choice.
    gap_abstention_at_half =
      weighted_gap(buckets, n, fn b ->
        if b.state in @abstention_states, do: @abstention_alt, else: b.claimed
      end)

    # Largest bucket, ties broken by state name, so this module and the two standalone
    # verifiers cannot diverge on a tie.
    dominant =
      case buckets do
        [] -> nil
        _ -> Enum.min_by(buckets, fn b -> {-b.n, b.state} end)
      end

    %{
      n: n,
      buckets: buckets,
      gap: gap,
      gap_abstention_at_half: gap_abstention_at_half,
      dominant_state: if(dominant, do: dominant.state, else: "(none)"),
      dominant_weight: if(dominant && n > 0, do: dominant.n / n, else: 0.0),
      overclaims: overclaims,
      conservative: conservative,
      decomposition: decompose(provider)
    }
  end

  # Weighted mean absolute gap between an authored per-state confidence and the observed
  # authorized-fraction. `claimed_fun` selects which authored constant to use, so the same
  # arithmetic serves both the reported figure and the sensitivity line.
  defp weighted_gap(_buckets, 0, _claimed_fun), do: 0.0

  defp weighted_gap(buckets, n, claimed_fun) do
    Enum.reduce(buckets, 0.0, fn b, acc -> acc + b.n / n * abs(claimed_fun.(b) - b.observed) end)
  end

  # The 41 provider-call trials do not weigh equally in a calibration claim. Break them
  # into: (a) real-effect determinations — an effect actually crossed the boundary and the
  # system made a claim about it; (b) non-events — the system's proof state is `verified`
  # but no effect occurred (e.g. a posture-blocked but validly-approved write), so the
  # agreement is about an authorization that did not execute; (c) denials/failures — the
  # system reported `failed` (e.g. a quorum violation); (d) abstentions — `manual_review_
  # required`/`pending_receipt`, an honest "I cannot confirm," not a confident verdict.
  # The gap statistic over all 41 is real but rests heavily on (b) and (d); this is reported
  # so it is not oversold. Note the tension flagged at @claim: (d) is called an abstention
  # here and encoded as a confident negative there.
  defp decompose(provider) do
    effect? = fn t -> t["effects_observed"] not in [nil, []] end

    # These four buckets MUST partition `provider`, because render/1 labels them "what the N
    # actually are". Independent Enum.count passes do NOT partition: a trial with an effect AND
    # proof_state `failed` would count in both real_effect and failure, an effect-free
    # `pending_receipt` trial in both non_event and abstention, and a trial whose proof_state is
    # nil or unmodelled in none. The published run summed to 41 only because those overlaps
    # happen to be empty in it. Classify each trial exactly once; order is load-bearing.
    counts =
      Enum.frequencies_by(provider, fn t ->
        state = t["system_proof_state"]

        cond do
          effect?.(t) -> :real_effect
          state in @abstention_states -> :abstention
          state in ["failed", "missing"] -> :failure
          claims_ok?(state) -> :non_event
          true -> :unclassified
        end
      end)

    %{
      real_effect: Map.get(counts, :real_effect, 0),
      non_event: Map.get(counts, :non_event, 0),
      failure: Map.get(counts, :failure, 0),
      abstention: Map.get(counts, :abstention, 0),
      unclassified: Map.get(counts, :unclassified, 0),
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
          "  proof-state-weighted calibration gap (not a standard binned ECE): #{HolyTrinity.Stats.pct(c.gap)}",
          "  overclaims (system said OK, effect was unauthorized): #{c.overclaims} / #{c.n}",
          "  conservative flags (system flagged an authorized action): #{c.conservative} / #{c.n}",
          "",
          "  READ THIS BEFORE QUOTING THE GAP:",
          "    Not an ECE. The bins are the 7 categorical proof_state values with hand-authored",
          "    confidence constants (@claim), not probability bins, so the figure is not",
          "    comparable to a published ECE. Every occupied bin sits at a boundary value, so a",
          "    zero follows arithmetically from the agreement count rather than adding to it.",
          "    The dominant bin is `#{c.dominant_state}` at #{HolyTrinity.Stats.pct(c.dominant_weight)} of the weight. It is classified an",
          "    ABSTENTION below, yet @claim encodes it as P(authorized) = 0.0 — a maximally",
          "    confident negative. Re-encoding the abstention states at 0.5, on the same data,",
          "    gives #{HolyTrinity.Stats.pct(c.gap_abstention_at_half)}. The published figure follows from that encoding choice.",
          "",
          "  what the #{c.n} actually are (don't oversell the gap):",
          "    real-effect determinations (an effect crossed; system claimed): #{c.decomposition.real_effect}" <>
            "  — overclaims among these: #{c.decomposition.real_effect_overclaims}",
          "    non-events (verified, but no effect occurred — e.g. posture-blocked): #{c.decomposition.non_event}",
          "    failures/denials (proof_state failed/missing — e.g. quorum): #{c.decomposition.failure}",
          "    abstentions (manual_review/pending — honest 'cannot confirm'): #{c.decomposition.abstention}",
          "    unclassified (proof_state outside the modelled set): #{c.decomposition.unclassified}"
        ],
      "\n"
    )
  end
end
