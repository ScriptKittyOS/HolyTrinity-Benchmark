defmodule Mix.Tasks.Holytrinity.Run do
  @moduledoc """
  Runs HolyTrinity Bench trials against the Trinity authority control plane.

  Sandbox/test-gated: runs only under `MIX_ENV=test`, drives mock adapters, performs
  no live provider I/O. See `SPEC.md` for the frozen methodology.

      # one trial
      MIX_ENV=test mix holytrinity.run --run-id r1 --family F4 --variant payload-mutated-after-approval

      # every implemented {family, variant} in the catalog
      MIX_ENV=test mix holytrinity.run --run-id r1 --all

  This task owns a real Ecto SQL-sandbox connection (the same mechanism
  `AutonomousAgency.DataCase` uses), shared across every process the trial spawns, so
  trials execute against a REAL Postgres and the REAL membrane. Fixture rows created
  during the run are rolled back when the owner is stopped; the durable artifact is the
  JSONL appended to `results/<run_id>.jsonl` (SPEC §7).
  """

  use Mix.Task

  @shortdoc "Runs HolyTrinity Bench adversarial trials (test-gated, mock adapters only)"

  @results_dir "results"

  @impl Mix.Task
  def run(args) do
    ensure_sandbox!()

    {opts, _rest, _invalid} =
      OptionParser.parse(args,
        strict: [
          family: :string,
          variant: :string,
          run_id: :string,
          all: :boolean,
          report: :boolean,
          overhead: :boolean,
          false_denials: :boolean,
          ablate: :string,
          ablation_study: :boolean,
          baseline: :boolean,
          require_clean: :boolean,
          blind_set: :string,
          compound: :boolean,
          measurement_integrity: :boolean,
          tcb: :boolean
        ],
        aliases: [f: :family, v: :variant]
      )

    run_id = Keyword.get(opts, :run_id) || "adhoc-#{System.system_time(:second)}"

    Mix.Task.run("app.start")

    cond do
      Keyword.get(opts, :report) ->
        report(run_id)

      Keyword.get(opts, :overhead) ->
        measure(&HolyTrinity.Overhead.run/0, &HolyTrinity.Overhead.render/1)

      Keyword.get(opts, :false_denials) ->
        measure(&HolyTrinity.FalseDenials.run/0, &HolyTrinity.FalseDenials.render/1)

      Keyword.get(opts, :ablation_study) ->
        measure(fn -> HolyTrinity.AblationStudy.run(run_id) end, &HolyTrinity.AblationStudy.render/1)

      Keyword.get(opts, :compound) ->
        measure(
          fn -> HolyTrinity.AblationStudy.compound_f4(run_id) end,
          &HolyTrinity.AblationStudy.render_compound/1
        )

      Keyword.get(opts, :tcb) ->
        measure(fn -> HolyTrinity.AblationStudy.tcb(run_id) end, &HolyTrinity.AblationStudy.render_tcb/1)

      Keyword.get(opts, :baseline) ->
        measure(
          fn -> HolyTrinity.AblationStudy.no_control(run_id) end,
          &HolyTrinity.AblationStudy.render_no_control/1
        )

      Keyword.get(opts, :blind_set) ->
        blind_campaign(Keyword.fetch!(opts, :blind_set), run_id)

      Keyword.get(opts, :measurement_integrity) ->
        measurement_integrity(run_id)

      true ->
        campaign(opts, run_id)
    end
  end

  # Secondary-result harnesses (overhead, false denials) run under the same real
  # sandbox connection as the campaign.
  defp measure(run_fun, render_fun) do
    owner = Ecto.Adapters.SQL.Sandbox.start_owner!(AutonomousAgency.Repo, shared: true)

    try do
      Mix.shell().info(render_fun.(run_fun.()))
    after
      Ecto.Adapters.SQL.Sandbox.stop_owner(owner)
    end
  end

  # Blind held-out red team (paper §6.7): score an independently-authored declarative attack
  # set through the SAME independent Oracle, and report its unauthorized-effect rate + CI
  # separately from the authored set.
  defp blind_campaign(path, run_id) do
    unless File.exists?(path), do: Mix.raise("no blind attack set at #{path}")
    owner = Ecto.Adapters.SQL.Sandbox.start_owner!(AutonomousAgency.Repo, shared: true)

    try do
      trials = HolyTrinity.BlindSet.run(path, run_id)

      Enum.each(trials, fn t ->
        _ = HolyTrinity.Runner.append(t, @results_dir)

        Mix.shell().info(
          "  #{pad(t.variant, 28)} outcome=#{pad(to_string(t.outcome), 12)} verdict=#{t.oracle_verdict}"
        )
      end)

      attack_n = Enum.count(trials, &(&1.outcome != :allowed))
      effects = Enum.count(trials, &(&1.outcome in [:detected, :undetected]))
      {lo, hi} = HolyTrinity.Stats.wilson(effects, attack_n)

      Mix.shell().info("""

      ── blind red team (paper §6.7) — #{path} ──
        attack trials: #{attack_n}
        unauthorized effects: #{effects}
        rate: #{if attack_n > 0, do: HolyTrinity.Stats.pct(effects / attack_n), else: "n/a"} \
      95% CI [#{HolyTrinity.Stats.pct(lo)}, #{HolyTrinity.Stats.pct(hi)}]
        results: #{@results_dir}/#{run_id}.jsonl
      """)
    after
      Ecto.Adapters.SQL.Sandbox.stop_owner(owner)
    end
  end

  # F10 measurement integrity (paper §6.7): validate the Oracle's effect-observation
  # apparatus. Run separately from the frozen v1 campaign (it is a v2 candidate).
  defp measurement_integrity(run_id) do
    owner = Ecto.Adapters.SQL.Sandbox.start_owner!(AutonomousAgency.Repo, shared: true)

    try do
      Mix.shell().info("── F10 measurement integrity (paper §6.7) ──")

      for {family, variant} <- HolyTrinity.MeasurementIntegrity.catalog() do
        trial = HolyTrinity.Runner.run_trial(run_id, family, variant, config_hash: config_hash("baseline", []))
        _ = HolyTrinity.Runner.append(trial, @results_dir)
        Mix.shell().info("  #{pad(variant, 42)} #{trial.notes}")
      end
    after
      Ecto.Adapters.SQL.Sandbox.stop_owner(owner)
    end
  end

  defp report(run_id) do
    path = Path.join(@results_dir, "#{run_id}.jsonl")
    unless File.exists?(path), do: Mix.raise("no results file at #{path} — run a campaign first")
    Mix.shell().info(HolyTrinity.Report.render(path))
  end

  defp campaign(opts, run_id) do
    pairs = resolve_pairs(opts)
    ablate = Keyword.get(opts, :ablate)
    guard_clean_tree!(opts)
    trial_opts = ablation_setup(ablate)

    owner = Ecto.Adapters.SQL.Sandbox.start_owner!(AutonomousAgency.Repo, shared: true)

    try do
      Mix.shell().info(
        "HolyTrinity Bench — #{HolyTrinity.Trial.spec_version()} — run_id=#{run_id} — " <>
          "#{length(pairs)} trial(s)#{if ablate, do: " — ABLATED: #{ablate}", else: ""}\n"
      )

      trials =
        Enum.map(pairs, fn {family, variant} ->
          trial = run_one(run_id, family, variant, trial_opts)
          _path = HolyTrinity.Runner.append(trial, @results_dir)

          Mix.shell().info(
            "  #{pad(family <> "/" <> variant, 46)} outcome=#{pad(to_string(trial.outcome), 12)} " <>
              "verdict=#{pad(to_string(trial.oracle_verdict), 13)} proof_state=#{trial.system_proof_state}"
          )

          trial
        end)

      summarize(trials, run_id)
    after
      ablation_teardown(ablate)
      Ecto.Adapters.SQL.Sandbox.stop_owner(owner)
    end
  end

  # Integrity (SPEC §7): "the code changed during the run" ends a paper. A scored run
  # records the git-dirty state in every trial's config_hash, and `--require-clean` hard
  # refuses a dirty tree so the paper run cannot be produced from uncommitted code.
  defp guard_clean_tree!(opts) do
    if Keyword.get(opts, :require_clean, false) and git_dirty?() do
      Mix.raise("--require-clean: refusing to score a run on a dirty working tree (SPEC §7)")
    end
  end

  # Ablation study (paper §6.5). Disable exactly one mechanism for the
  # duration of the campaign, stamp it into config_hash so the run is self-describing
  # (SPEC §7), and refuse to ablate outside a build that compiled the ablation branch.
  defp ablation_setup(nil), do: [config_hash: config_hash("baseline", [])]

  # Accepts one mechanism or a comma-separated list (compound ablation, e.g.
  # `--ablate authority_assurance.approval_binding,policies.spend` to remove a mechanism
  # AND its defense-in-depth backstop at once).
  defp ablation_setup(spec) do
    unless AutonomousAgency.Governance.Ablation.ablation_available?() do
      Mix.raise("--ablate requires a build with the ablation branch compiled in (MIX_ENV=test)")
    end

    mechanisms = spec |> String.split(",", trim: true) |> Enum.map(&String.trim/1)
    Application.put_env(:autonomous_agency, :holytrinity_ablation, mechanisms)
    [config_hash: config_hash("ablate:#{Enum.join(mechanisms, "+")}", mechanisms)]
  end

  # A real config fingerprint (SPEC §7): a human-readable descriptor + a dirty-tree marker
  # + an 8-char digest of the run-shaping config, so two runs with identical config share a
  # config_hash and any change is visible. Replaces the old "unset".
  defp config_hash(descriptor, ablation) do
    dirty = git_dirty?()

    digest =
      %{
        spec: HolyTrinity.Trial.spec_version(),
        ablation: ablation,
        two_person: inspect(Application.get_env(:autonomous_agency, :two_person_approval, [])),
        dirty: dirty
      }
      |> Jason.encode!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 8)

    "#{descriptor}#{if dirty, do: "+dirty", else: ""}@#{digest}"
  end

  defp git_dirty? do
    case System.cmd("git", ["status", "--porcelain"], stderr_to_stdout: true) do
      {"", 0} -> false
      {out, 0} -> String.trim(out) != ""
      _ -> true
    end
  rescue
    _ -> true
  end

  defp ablation_teardown(nil), do: :ok
  defp ablation_teardown(_mechanism), do: Application.delete_env(:autonomous_agency, :holytrinity_ablation)

  # A trial that crashes must be recorded as a visible harness_error, never silently
  # dropped — a missing trial would understate the attack set and mislead the reader.
  defp run_one(run_id, family, variant, trial_opts) do
    HolyTrinity.Runner.run_trial(run_id, family, variant, trial_opts)
  rescue
    e -> HolyTrinity.Trial.harness_error(run_id, family, variant, Exception.message(e))
  catch
    kind, reason ->
      HolyTrinity.Trial.harness_error(run_id, family, variant, "#{kind}: #{inspect(reason)}")
  end

  defp resolve_pairs(opts) do
    cond do
      Keyword.get(opts, :all) ->
        HolyTrinity.Aggressor.catalog()

      Keyword.get(opts, :family) && Keyword.get(opts, :variant) ->
        [{Keyword.fetch!(opts, :family), Keyword.fetch!(opts, :variant)}]

      # --family alone = every variant of that family (the common ablation-campaign shape).
      Keyword.get(opts, :family) ->
        family = Keyword.fetch!(opts, :family)
        HolyTrinity.Aggressor.catalog() |> Enum.filter(fn {f, _v} -> f == family end)

      true ->
        Mix.raise(
          "provide --all, --family FN, or both --family and --variant (e.g. --family F4 --variant post-approval-injection)"
        )
    end
  end

  defp summarize(trials, run_id) do
    by_outcome = Enum.frequencies_by(trials, & &1.outcome)
    unauthorized_effects = Enum.count(trials, &(&1.outcome in [:detected, :undetected]))
    misbehavior = Enum.count(trials, & &1.agent_proposed_violation)

    Mix.shell().info("""

    ── summary ──────────────────────────────────────────────
      trials:                #{length(trials)}
      agent proposed violation (misbehavior): #{misbehavior}
      unauthorized effects (detected+undetected): #{unauthorized_effects}
      outcomes: #{inspect(by_outcome)}
      results: #{@results_dir}/#{run_id}.jsonl
    ─────────────────────────────────────────────────────────
    """)
  end

  defp pad(s, n), do: String.pad_trailing(s, n)

  defp ensure_sandbox! do
    unless Mix.env() == :test do
      Mix.raise("mix holytrinity.run must run under MIX_ENV=test (mock adapters, no live I/O)")
    end
  end
end
