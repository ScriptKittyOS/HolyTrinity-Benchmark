defmodule HolyTrinity.Overhead do
  @moduledoc """
  Governed-path latency (SPEC §6): the **absolute** wall-time of a governed action — the full
  ToolRouter membrane (policies + `AuthorityAssurance.preflight` + receipt/invariant
  recording) — reported against a no-I/O adapter floor.

  ## Why this is not an "overhead" or "added latency" measurement

  It was originally written as a differential: governed minus the same action bypassing the
  membrane and calling the mock adapter directly. Two problems, both fatal to the difference
  and neither fatal to the absolute number:

    1. **The baseline is degenerate.** `MockStripe.execute/3` is a pure in-memory function
       costing roughly 211 ns at p50. Against a governed path in the tens of milliseconds it
       is on the order of 0.001% — so the "added" latency was numerically the governed
       latency, relabelled. (It also truncated to a literal 0 at p50, p95 *and* p99 while
       this module timed in microseconds; that is fixed below, and fixing it does not
       resurrect the difference.)
    2. **The subtraction was not paired.** The two arms are independent series. The old
       `pointwise_delta/2` sorted each arm and subtracted the k-th order statistic of one
       from the k-th of the other. A difference of order statistics is not a distribution of
       differences: no iteration of the governed arm is matched to any iteration of the
       bypassed arm, so the resulting percentiles do not estimate a per-call delta.

  The `added` row is therefore **not reported**. What is reported is the governed path's own
  p50/p95/p99, and the adapter floor beside it as context for how little of that time is the
  work being governed. A reader who wants an overhead ratio can form one and will see that it
  is ~1.0 by construction; that is the honest reading, and it is the reason the absolute
  number is the one worth publishing.

  Mock adapters are used so no network noise enters the measurement.

  ## Measured in nanoseconds, reported in microseconds

  `:timer.tc/1` resolves to whole microseconds, so the ~211 ns bypassed arm truncated to a
  literal `0` at p50, p95 *and* p99 — a measurement reporting its clock rather than the
  system. This module now times in **nanoseconds**, so the floor is a real number that a
  reader can inspect (`bypassed_ns` in the returned map, and the note under the table).

  The **table is still rendered in microseconds**, which is the unit of the published
  percentiles (16882 / 57811 / 81277 µs). Changing the reported unit would make the published
  block a transcription of something this code no longer prints, for no gain: the governed
  path is in the tens of milliseconds and microseconds are the right resolution for it. The
  bypassed row consequently still shows `0` µs — correctly, and the note says why.

  This is a measurement, not an attack: it runs a legitimate, fully-authorized buy.

  ## Per-iteration artifact

  This harness used to return four percentiles and discard the 2n durations behind them, so
  the published p50/p95/p99 could be read but not recomputed (`scoring/VERIFY.md`: "no timing
  artifact ships"). Pass `results_dir:` and `run/2` writes `<results_dir>/<run_id>.jsonl`: a
  leading `_meta` line followed by ONE RECORD PER ITERATION PER ARM, carrying the arm name,
  the iteration index in measurement order and the raw nanosecond duration. That makes the
  percentiles recomputable, and it is the only place a reader can see the bypassed arm's
  **real** distribution rather than the rounded `0 µs` the published table is forced to print.

  Instrumentation only: the file is written after both timing loops have finished, from the
  same lists the percentiles are computed from, so no timing and no reported value moves.
  """

  alias HolyTrinity.Fixtures
  alias AutonomousAgency.Tools.{MockStripe, ToolRouter}

  @doc """
  Run `n` governed + `n` bypassed iterations of an authorized buy and return the timing
  summary. Percentiles are returned in NANOseconds (`governed_ns`, `bypassed_ns`);
  `render/1` converts to microseconds for the table. Set up a fresh authorized
  account/run/approval once, then reuse a single idempotency namespace with distinct keys
  per iteration so each governed call executes rather than replays.

  Options: `:results_dir` (emit the per-iteration JSONL there; omitted = emit nothing) and
  `:run_id` (the artifact's basename, default `"overhead"`).
  """
  def run(n \\ 200, opts \\ []) do
    %{account: account, owner: owner} = Fixtures.account("overhead")
    run = Fixtures.agent_run(account)
    :ok = Fixtures.enable_purchase_posture(account, owner)
    payload = Fixtures.buy_payload(account, 100)

    governed =
      for _ <- 1..n do
        idem = Fixtures.idempotency_key("ovh-gov")
        _req = Fixtures.approved_buy(account, owner, run, payload, idem)

        time_ns(fn ->
          ToolRouter.execute(:mock_stripe, :buy, payload,
            account_id: account.id,
            agent_run_id: run.id,
            idempotency_key: idem,
            sandbox: "finance"
          )
        end)
      end

    bypassed =
      for _ <- 1..n do
        idem = Fixtures.idempotency_key("ovh-byp")
        time_ns(fn -> MockStripe.execute(:buy, payload, idempotency_key: idem) end)
      end

    summary = %{
      n: n,
      governed_ns: percentiles(governed),
      bypassed_ns: percentiles(bypassed),
      hardware: hardware()
    }

    _ = emit(opts, summary, governed, bypassed)

    summary
  end

  # --- per-iteration artifact emission ---------------------------------------------------
  #
  # INSTRUMENTATION ONLY, and deliberately AFTER both timing loops: nothing in this path
  # runs inside a `time_ns/1` call, so no duration is perturbed by it. `summary` is computed
  # above from the same two lists written here.
  #
  # The unit of work is not a `HolyTrinity.Trial` — there is no attack, no Oracle and no
  # verdict, only a duration — so this emits a minimal self-describing record instead of
  # forcing a trial shape onto a timing sample.
  defp emit(opts, summary, governed, bypassed) do
    case Keyword.get(opts, :results_dir) do
      nil ->
        nil

      dir ->
        run_id = Keyword.get(opts, :run_id) || "overhead"
        File.mkdir_p!(dir)
        path = Path.join(dir, "#{run_id}.jsonl")

        rows =
          Enum.flat_map([{"governed", governed}, {"bypassed", bypassed}], fn {arm, times} ->
            times
            |> Enum.with_index()
            |> Enum.map(fn {ns, i} ->
              %{
                "kind" => "overhead-iteration",
                "run_id" => run_id,
                "arm" => arm,
                "iteration" => i,
                "duration_ns" => ns
              }
            end)
          end)

        lines = for row <- [meta(run_id, summary) | rows], do: [Jason.encode!(row), "\n"]
        File.write!(path, lines)
        path
    end
  end

  defp meta(run_id, summary) do
    %{
      "_meta" => true,
      "kind" => "overhead-latency",
      "run_id" => run_id,
      "commit" => commit_sha(),
      "n" => summary.n,
      "arms" => ["governed", "bypassed"],
      "unit" => "nanosecond",
      "hardware" => summary.hardware,
      "percentiles_ns" => %{
        "governed" => summary.governed_ns,
        "bypassed" => summary.bypassed_ns
      },
      "note" =>
        "Governed-path latency (SPEC §6). One record per iteration per arm, #{summary.n} per " <>
          "arm. `iteration` is MEASUREMENT ORDER, not rank — the rows are unsorted. `governed` " <>
          "is a legitimate, fully-authorized mock_stripe buy driven through the entire " <>
          "ToolRouter membrane (policies + AuthorityAssurance.preflight + receipt/invariant " <>
          "recording); `bypassed` is the same buy calling the mock adapter directly. Durations " <>
          "are :timer.tc/2 nanoseconds. To recompute a published percentile: sort one arm " <>
          "ascending, take the 0-based index round(p/100 * (n-1)), then truncate to whole " <>
          "microseconds with div(ns, 1000) — the table is rendered in microseconds, which is " <>
          "the published unit. Mock adapters only: no network I/O enters the measurement.",
      "caveat" =>
        "NO added-latency and NO percentage-overhead figure is claimed, and none can honestly " <>
          "be recomputed from these rows as a per-call delta: the two arms are INDEPENDENT " <>
          "series that were never paired per call, so a percentile-wise difference between " <>
          "them is a difference of order statistics, not a distribution of per-call " <>
          "differences. The bypassed arm is a pure in-memory function — on the order of " <>
          "0.001% of the governed path and below the one-microsecond resolution the table is " <>
          "printed at, which is why the published table shows `0` µs for it; these records " <>
          "are the real nanosecond distribution behind that 0. This is a synthetic single-" <>
          "process loop on one machine (`hardware`), not a production latency profile."
    }
  end

  defp commit_sha do
    case System.cmd("git", ["rev-parse", "HEAD"], stderr_to_stdout: true) do
      {sha, 0} -> sha |> String.trim() |> String.slice(0, 7)
      _ -> "unknown"
    end
  rescue
    _ -> "unknown"
  end

  @doc """
  Render the latency summary as text for the report / paper. The table is in microseconds
  (the published unit); the note carries the nanosecond floor, which is the number the old
  microsecond table could not represent.
  """
  def render(summary) do
    g = summary.governed_ns
    b = summary.bypassed_ns

    """
    ── governed-path latency (SPEC §6; n=#{summary.n} per path; mock adapters; microseconds) ──
      path        p50        p95        p99
      governed  #{col(us(g.p50))} #{col(us(g.p95))} #{col(us(g.p99))}
      bypassed  #{col(us(b.p50))} #{col(us(b.p95))} #{col(us(b.p99))}
      hardware: #{summary.hardware}

      Read the governed row as ABSOLUTE governed latency. There is deliberately no `added`
      row: the bypassed arm is a pure in-memory call measuring #{b.p50} / #{b.p95} / #{b.p99} NANOseconds at
      p50/p95/p99 — about 0.001% of the governed path, and below the one-microsecond
      resolution this table is printed at, which is why it shows 0 µs. Subtracting it returns
      the governed column to within rounding. The two arms are also independent series that
      were never paired per call, so a percentile-wise difference between them is a difference
      of order statistics, not a distribution of per-call deltas. Neither an "added latency"
      nor a percentage overhead is claimed.
    """
  end

  # Whole microseconds, truncated — the same value `:timer.tc/1` would have reported, so the
  # published percentiles remain reproducible from this code.
  defp us(ns), do: div(ns, 1000)

  # Nanoseconds, not microseconds: the adapter floor is ~211 ns, which `:timer.tc/1`'s
  # microsecond resolution truncated to 0 at p50, p95 and p99 alike. A measurement that
  # reports its own baseline as an exact zero at every percentile is reporting its clock, not
  # the system.
  #
  # `:timer.tc/2` with a time unit requires OTP 26 or later (OTP 25 and earlier resolve
  # `tc/2`'s second argument as an argument LIST). The harness runs on OTP 28.
  defp time_ns(fun) do
    {ns, _} = :timer.tc(fun, :nanosecond)
    ns
  end

  defp percentiles(times) do
    sorted = Enum.sort(times)
    %{p50: pct(sorted, 50), p95: pct(sorted, 95), p99: pct(sorted, 99)}
  end

  defp pct(sorted, p) do
    idx = max(0, round(p / 100 * (length(sorted) - 1)))
    Enum.at(sorted, idx)
  end

  defp col(v), do: String.pad_leading(to_string(v), 10)

  defp hardware do
    schedulers = System.schedulers_online()
    otp = System.otp_release()
    "#{schedulers} schedulers, OTP #{otp}, ERTS #{:erlang.system_info(:version)}"
  end
end
