defmodule HolyTrinity.Overhead do
  @moduledoc """
  Overhead measurement (SPEC §6): the cost of the authority control plane, measured as
  the added wall-time of a governed action (the full ToolRouter membrane — policies +
  `AuthorityAssurance.preflight` + receipt/invariant recording) versus the same action
  bypassing the membrane (calling the mock adapter directly).

  Mock adapters are used so no network noise enters the measurement — what is measured
  is the governance overhead itself. Reports p50/p95/p99 of the governed path, the
  bypassed path, and the added latency, plus the added-latency distribution.

  This is a measurement, not an attack: it runs a legitimate, fully-authorized buy.
  """

  alias HolyTrinity.Fixtures
  alias AutonomousAgency.Tools.{MockStripe, ToolRouter}

  @doc """
  Run `n` governed + `n` bypassed iterations of an authorized buy and return the timing
  summary (microseconds). Set up a fresh authorized account/run/approval once, then
  reuse a single idempotency namespace with distinct keys per iteration so each governed
  call executes rather than replays.
  """
  def run(n \\ 200) do
    %{account: account, owner: owner} = Fixtures.account("overhead")
    run = Fixtures.agent_run(account)
    :ok = Fixtures.enable_purchase_posture(account, owner)
    payload = Fixtures.buy_payload(account, 100)

    governed =
      for _ <- 1..n do
        idem = Fixtures.idempotency_key("ovh-gov")
        _req = Fixtures.approved_buy(account, owner, run, payload, idem)

        time_us(fn ->
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
        time_us(fn -> MockStripe.execute(:buy, payload, idempotency_key: idem) end)
      end

    %{
      n: n,
      governed_us: percentiles(governed),
      bypassed_us: percentiles(bypassed),
      added_us: percentiles(pointwise_delta(governed, bypassed)),
      hardware: hardware()
    }
  end

  @doc "Render the overhead summary as text for the report / paper."
  def render(summary) do
    g = summary.governed_us
    b = summary.bypassed_us
    a = summary.added_us

    """
    ── overhead (SPEC §6; n=#{summary.n} per path; mock adapters; microseconds) ──
      path        p50        p95        p99
      governed  #{col(g.p50)} #{col(g.p95)} #{col(g.p99)}
      bypassed  #{col(b.p50)} #{col(b.p95)} #{col(b.p99)}
      added     #{col(a.p50)} #{col(a.p95)} #{col(a.p99)}
      hardware: #{summary.hardware}
    """
  end

  defp time_us(fun) do
    {us, _} = :timer.tc(fun)
    us
  end

  defp percentiles(times) do
    sorted = Enum.sort(times)
    %{p50: pct(sorted, 50), p95: pct(sorted, 95), p99: pct(sorted, 99)}
  end

  defp pct(sorted, p) do
    idx = max(0, round(p / 100 * (length(sorted) - 1)))
    Enum.at(sorted, idx)
  end

  # Governed and bypassed are independent runs; a pointwise delta of the sorted-order
  # pairs approximates the added-latency distribution well enough for p50/p95/p99.
  defp pointwise_delta(a, b) do
    Enum.zip(Enum.sort(a), Enum.sort(b)) |> Enum.map(fn {x, y} -> x - y end)
  end

  defp col(v), do: String.pad_leading(to_string(v), 10)

  defp hardware do
    schedulers = System.schedulers_online()
    otp = System.otp_release()
    "#{schedulers} schedulers, OTP #{otp}, ERTS #{:erlang.system_info(:version)}"
  end
end
