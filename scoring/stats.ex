defmodule HolyTrinity.Stats do
  @moduledoc """
  Confidence intervals and power for the benchmark's rate metrics.

  A 0-effect result without an interval is not a result. These are closed-form,
  dependency-free estimators (no special functions), which is deliberate: a reviewer can
  reproduce every number with a calculator.

  * `wilson/3` — the **two-sided** 95% Wilson score interval for a binomial proportion.
    Well-behaved at the boundaries (x=0 and x=n), which is exactly where this benchmark
    lives; preferred over the normal-approximation (Wald) interval, which is degenerate at 0.
  * `rule_of_three/1` — the standard **one-sided** 95% upper bound `3/n` for 0 events in n
    trials (clamped to 1.0; a probability cannot exceed 1).
  * `n_for_upper_bound/1` — inverse power: trials needed to bound a true rate strictly
    below `r` with 0 observed events, at the same one-sided 95% level. (The at-or-below
    sample size is `ceil(3/r)` = the n ≥ 3/r the paper's 30/60/300 figures cite; this
    returns the strictly-below n.)

  ## The two bounds do NOT carry the same coverage — never merge them into one column

  A two-sided 95% interval spends 2.5% in each tail, so its **upper limit is a one-sided
  97.5% bound**. `3/n` approximates the one-sided **95%** bound. At x=0 the rule-of-three
  number is therefore always the smaller of the two, and a reader who sees them side by side
  under a single "95% CI" heading will read the smaller number as the tighter result when it
  is in fact the *lower-confidence* claim. `report.ex` prints them in two separately labelled
  columns for exactly this reason, and callers should keep that separation.

  `rule_of_three/1` is valid **only at x = 0**. It is not an upper bound for a nonzero
  numerator and must never be emitted for one; `report.ex` and `false_denials.ex` both guard
  on `effects == 0` before printing it.
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

  @doc """
  The **one-sided** 95% upper bound for 0 events in `n` trials (rule of three); clamped to
  [0,1]. Valid only at x = 0 — see the moduledoc.
  """
  def rule_of_three(0), do: 1.0
  def rule_of_three(n) when n > 0, do: min(1.0, 3.0 / n)

  @doc "Smallest n whose one-sided 95% rule-of-three upper bound (3/n) is strictly below `r`."
  def n_for_upper_bound(r) when r > 0 and r < 1 do
    # ceil(3/r) is the at-or-below sample size (bound ≤ r); step up by one when the bound
    # lands exactly on r so the result is strictly below. Float-stable (checks 3/n, not 3/r).
    n = ceil(3.0 / r)
    if 3.0 / n < r, do: n, else: n + 1
  end

  @doc "Format a proportion in [0,1] as a percentage string, e.g. 0.0879 -> \"8.8%\"."
  def pct(p) when is_number(p), do: :erlang.float_to_binary(p * 100, decimals: 1) <> "%"
end
