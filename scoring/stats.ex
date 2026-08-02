defmodule HolyTrinity.Stats do
  @moduledoc """
  Confidence intervals and power for the benchmark's rate metrics .

  A 0-effect result without an interval is not a result. These are closed-form,
  dependency-free estimators (no special functions), which is deliberate: a reviewer can
  reproduce every number with a calculator.

  * `wilson/3` — the Wilson score interval for a binomial proportion. Well-behaved at the
    boundaries (x=0 and x=n), which is exactly where this benchmark lives; preferred over
    the normal-approximation (Wald) interval, which is degenerate at 0.
  * `rule_of_three/1` — the standard 95% upper bound `3/n` for 0 events in n trials.
  * `n_for_upper_bound/1` — inverse power: trials needed to bound a true rate below `r`
    with 0 observed events (`ceil(3/r)`).
  """

  # Textbook 95% z (two-sided). We use 1.96 rather than the exact 1.95996 percentile so
  # every interval reproduces from the constant a reviewer will reach for; the difference
  # is <0.01% except at a rounding knife-edge (e.g. the n=3 upper bound at ~56.15%).
  @z95 1.96

  @doc "Wilson score 95% CI for `x` successes in `n` trials. Returns {low, high} in [0,1]."
  def wilson(x, n, z \\ @z95)
  def wilson(_x, 0, _z), do: {0.0, 1.0}

  def wilson(x, n, z) do
    p = x / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = z / denom * :math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    {max(0.0, center - half), min(1.0, center + half)}
  end

  @doc "The 95% upper bound for 0 events in `n` trials (rule of three)."
  def rule_of_three(0), do: 1.0
  def rule_of_three(n) when n > 0, do: 3.0 / n

  @doc "Trials needed to bound a true rate below `r` with 0 observed events."
  def n_for_upper_bound(r) when r > 0 and r < 1, do: ceil(3.0 / r)

  @doc "Format a proportion in [0,1] as a percentage string, e.g. 0.0879 -> \"8.8%\"."
  def pct(p) when is_number(p), do: :erlang.float_to_binary(p * 100, decimals: 1) <> "%"
end
