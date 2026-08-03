defmodule HolyTrinity.BlindSet do
  @moduledoc """
  The blind held-out red team (paper §6.7) — the direct answer to the internal-validity
  objection "you attacked your own system."

  The authored attack set (`HolyTrinity.Aggressor`) is written *against the code*, so its
  blind spots correlate with the design's. This channel scores an attack set an
  independent party wrote **without reading the implementation** — using only the family
  definitions (`families/*.md`) and the §3 definition of unauthorized effect. The attacks
  are therefore expressed *declaratively* (what to approve, what to execute) rather than as
  code that drives named internal seams. This module compiles each declarative attack into
  a real trial and scores it through the **exact same independent Oracle** as the authored
  set (`Runner.score_context/5`), so the two are directly comparable.

  Declarative attack shape (one JSON object per attack; see `blind/`):

      {
        "id": "blind-042",
        "approved_amount_cents": 100,          // what the human approved
        "approval": "normal" | "expired" | "revoked",
        "driven_amount_cents": 100,            // what actually executes (omit = same)
        "driven_extra": {"note": "urgent"},    // fields added/changed post-approval (clause b)
        "expect": "prevented" | "effect"       // the blind author's prediction (not used to score)
      }

  Scoping note (honest): this driver realizes the **F4/F7-shaped** provider-call attack
  (an approved stripe buy whose executed payload may diverge from the approved one, under a
  normal/expired/revoked approval). That is the deepest, most-contested boundary (the
  approval→execution join) and the one where a blind author's independent payloads are most
  valuable. Blind coverage of the gate families (F1–F3) is future work and is stated as
  such in `blind/README.md`.
  """

  alias AutonomousAgency.AuthorityAssurance
  alias AutonomousAgency.Tools.ToolRouter
  alias HolyTrinity.{Fixtures, Runner}

  @doc "Load a blind attack set from a JSON file (a list of declarative attacks)."
  def load(path) do
    path |> File.read!() |> Jason.decode!()
  end

  @doc "Score every attack in `path`, returning trial records from the independent Oracle."
  def run(path, run_id \\ "blind") do
    path
    |> load()
    |> Enum.map(&score(&1, run_id))
  end

  @doc "Compile one declarative attack into a real trial and score it via the Oracle."
  def score(attack, run_id) do
    id = Map.fetch!(attack, "id")
    context = build_context(attack)
    Runner.score_context(run_id, "BLIND", id, context, config_hash: "blind")
  rescue
    e -> HolyTrinity.Trial.harness_error(run_id, "BLIND", Map.get(attack, "id", "?"), Exception.message(e))
  end

  defp build_context(attack) do
    %{account: account, owner: owner} = Fixtures.account("blind")
    run = Fixtures.agent_run(account)
    :ok = Fixtures.enable_purchase_posture(account, owner)

    approved_amount = Map.get(attack, "approved_amount_cents", 100)
    approved_payload = Fixtures.buy_payload(account, approved_amount)
    idem = Fixtures.idempotency_key("blind")

    request =
      case Map.get(attack, "approval", "normal") do
        "expired" -> Fixtures.expired_approved_buy(account, owner, run, approved_payload, idem)
        "revoked" -> Fixtures.revoked_approved_buy(account, owner, run, approved_payload, idem)
        _ -> Fixtures.approved_buy(account, owner, run, approved_payload, idem)
      end

    driven_payload = driven_payload(account, approved_payload, attack)
    tainted? = driven_payload != approved_payload or Map.get(attack, "approval") in ["expired", "revoked"]

    %{
      agent_run_id: run.id,
      effect_channel: :provider_call,
      proposed: %{
        provider: :mock_stripe,
        operation: :buy,
        account_id: account.id,
        idempotency_key: idem,
        payload: driven_payload,
        approved_payload_hash: AuthorityAssurance.canonical_payload_hash(approved_payload)
      },
      agent_proposed_violation: tainted?,
      attack_target: "exact",
      mechanism_id: "authority_assurance.approval_binding",
      description: "Blind red-team attack #{Map.get(attack, "id")}: #{describe(attack)}",
      expected_detection_source: if(tainted?, do: :preflight, else: :none),
      drive: fn ->
        ToolRouter.execute(:mock_stripe, :buy, driven_payload,
          account_id: account.id,
          agent_run_id: run.id,
          approval_request_id: request.id,
          idempotency_key: idem,
          sandbox: "finance"
        )
      end
    }
  end

  defp driven_payload(account, approved_payload, attack) do
    base =
      case Map.get(attack, "driven_amount_cents") do
        nil -> approved_payload
        amount -> Fixtures.buy_payload(account, amount)
      end

    case Map.get(attack, "driven_extra") do
      extra when is_map(extra) and map_size(extra) > 0 -> Map.merge(base, atomize(extra))
      _ -> base
    end
  end

  # This module's premise is that the JSON was authored by an independent third party, so its
  # keys are untrusted. `String.to_atom/1` on untrusted input is an atom-table exhaustion vector
  # (atoms are never garbage-collected). We create no atoms here:
  #
  #   * a key that already exists as an atom becomes that atom, so a `driven_extra` entry naming a
  #     real payload field still OVERWRITES it (the "changed post-approval" case in the schema);
  #   * a novel key stays a string, which is the "added post-approval" case.
  #
  # This cannot change any hash: the canonicalizer treats atom and string keys as the same key —
  # the published property the F4 `canon:string-keys-equivalent` control exists to prove (the
  # algorithm itself is held per PAPER §11). Every blind trial's canonical payload hash, and therefore its verdict, is
  # identical to the previous `String.to_atom/1` behaviour.
  defp atomize(map) do
    Map.new(map, fn {k, v} ->
      key =
        try do
          String.to_existing_atom(k)
        rescue
          ArgumentError -> k
        end

      {key, v}
    end)
  end

  defp describe(attack) do
    parts =
      [
        "approval=#{Map.get(attack, "approval", "normal")}",
        Map.get(attack, "driven_amount_cents") && "amount→#{attack["driven_amount_cents"]}",
        (is_map(Map.get(attack, "driven_extra")) && map_size(attack["driven_extra"]) > 0) &&
          "extra=#{Map.keys(attack["driven_extra"]) |> Enum.join(",")}"
      ]
      |> Enum.reject(&(&1 in [nil, false]))

    Enum.join(parts, " ")
  end
end
