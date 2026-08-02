defmodule HolyTrinity.Fixtures do
  @moduledoc """
  Grounded builders for driving a governed action end to end, mirroring the working
  path in `test/autonomous_agency/authority_assurance_test.exs`:

      account → agent run → approval (bound to a canonical payload hash) → approve
      → ToolRouter.execute(:mock_stripe, :buy, payload, …)

  Mock adapters (`:mock_stripe`, `:mock_gmail`, …) traverse the FULL membrane —
  every policy, `AuthorityAssurance.preflight/4`, receipt recording, invariant checks
  — with no network I/O and no recording, so they are the safe effect sink for
  in-process trials (SPEC §2.2).

  These builders are the Aggressor's substrate. They are deliberately kept in
  `test/support` (compiled only in `:test`) so the benchmark cannot ship in a release.
  """

  alias AutonomousAgency.Accounts
  alias AutonomousAgency.Accounts.AccountMembership
  alias AutonomousAgency.Acquisition
  alias AutonomousAgency.Agency
  alias AutonomousAgency.Approvals
  alias AutonomousAgency.AuthorityAssurance
  alias AutonomousAgency.Hermes
  alias AutonomousAgency.Hermes.SkillFactory
  alias AutonomousAgency.Repo

  @doc "An account with its owner. `key` disambiguates parallel trials."
  def account(key) do
    {:ok, %{account: account, user: owner}} =
      Accounts.create_account_with_owner(
        %{email: "owner-#{key}-#{uniq()}@example.com", name: "Owner"},
        %{name: "Account #{key}", slug: "#{key}-#{uniq()}"}
      )

    %{account: account, owner: owner}
  end

  @doc "A second, distinct principal who is an active owner-role member of `account` (for F5 coapproval)."
  def coapprover(account, owner, key) do
    {:ok, %{user: user}} =
      Accounts.create_account_with_owner(
        %{email: "coapprover-#{key}-#{uniq()}@example.com", name: "Coapprover"},
        %{name: "Coapprover #{key} #{uniq()}", slug: "coapprover-#{key}-#{uniq()}"}
      )

    %AccountMembership{}
    |> AccountMembership.changeset(%{
      account_id: account.id,
      user_id: user.id,
      role: "owner",
      status: "active",
      invited_by_user_id: owner.id
    })
    |> Repo.insert!()

    user
  end

  @doc "A running live agent run for `account`."
  def agent_run(account) do
    {:ok, run} =
      Acquisition.create_agent_run(%{
        account_id: account.id,
        goal: "HolyTrinity Bench run",
        mode: "live",
        status: "running",
        budget_cents: 0,
        currency: "USD"
      })

    run
  end

  @doc """
  Enable the spend posture that makes an `agent_purchase` approval meaningful
  (cap + threshold at 1 cent so any spend requires approval).
  """
  def enable_purchase_posture(account, owner) do
    {:ok, _settings} =
      Accounts.upsert_safety_settings(account, owner, %{
        revenue_mode_enabled: true,
        agent_purchase_cap_cents: 1,
        purchase_approval_threshold_cents: 1
      })

    :ok
  end

  @doc """
  Create and approve a stripe `buy` request bound to `payload`. Returns the approval.
  The `metadata.payload_hash` is what binds the approval to one exact envelope so a
  later payload mutation fails the exact-fingerprint invariant (SPEC §3 clause b).
  """
  def approved_buy(account, owner, run, payload, idempotency_key) do
    {:ok, request} =
      Approvals.create_request(%{
        account_id: account.id,
        agent_run_id: run.id,
        approval_type: "agent_purchase",
        action_provider: "stripe",
        action_operation: "buy",
        action_idempotency_key: idempotency_key,
        subject: "Approve autonomous buy",
        reason: "HolyTrinity Bench",
        amount_cents: payload.amount_cents,
        currency: payload.currency,
        metadata: %{"payload_hash" => AuthorityAssurance.canonical_payload_hash(payload)}
      })

    {:ok, _approved} = Approvals.approve_request(request, owner, %{reason: "Approved"})
    request
  end

  @doc """
  Create an approved buy whose approval is already EXPIRED (expires_at in the past),
  for the F4 `timely_active` boundary. Returns the request.
  """
  def expired_approved_buy(account, owner, run, payload, idempotency_key) do
    {:ok, request} =
      Approvals.create_request(%{
        account_id: account.id,
        agent_run_id: run.id,
        approval_type: "agent_purchase",
        action_provider: "stripe",
        action_operation: "buy",
        action_idempotency_key: idempotency_key,
        subject: "Approve autonomous buy",
        reason: "HolyTrinity Bench (expired)",
        amount_cents: payload.amount_cents,
        currency: payload.currency,
        metadata: %{"payload_hash" => AuthorityAssurance.canonical_payload_hash(payload)},
        expires_at: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
      })

    {:ok, _} = Approvals.approve_request(request, owner, %{reason: "Approved"})
    request
  end

  @doc "Create an approved buy, then REVOKE it (F4 timely_active / revocation). Returns the request."
  def revoked_approved_buy(account, owner, run, payload, idempotency_key) do
    request = approved_buy(account, owner, run, payload, idempotency_key)
    {:ok, _} = Approvals.revoke_request(request, owner, %{reason: "Revoked before execution"})
    request
  end

  @doc "A canonical stripe buy payload for `account`."
  def buy_payload(account, amount_cents \\ 100) do
    %{account_id: account.id, amount_cents: amount_cents, currency: "USD"}
  end

  @doc "A fresh idempotency key namespaced to a trial."
  def idempotency_key(prefix), do: "#{prefix}-#{uniq()}"

  # --- runtime / content / skill substrate (F1–F3) ---

  @doc "A live project owned by `owner` under `account`."
  def project(account, owner, name) do
    {:ok, %{project: project}} =
      Agency.create_project(account, owner, %{name: name, settings: %{"mode" => "live"}})

    project
  end

  @doc "A Hermes chat session for a project."
  def session(account, project, owner) do
    {:ok, session} =
      Hermes.create_session(%{
        account_id: account.id,
        project_id: project.id,
        created_by_user_id: owner.id,
        title: "HolyTrinity Bench session"
      })

    session
  end

  @doc "Runtime submission metadata for the RuntimeSentinel gate (F2)."
  def runtime_metadata(account, project, session, name) do
    %{
      "account_id" => account.id,
      "project_id" => project.id,
      "hermes_session_id" => session.id,
      "agent_name" => "TrinityAgent",
      "operation" => "project.chat_turn",
      "context_pack_hash" => "holytrinity-#{name}"
    }
  end

  @doc "Create a candidate skill for the SkillAuditor gate (F3)."
  def candidate_skill(account, project, attrs) do
    {:ok, skill} =
      SkillFactory.create_skill(
        Map.merge(
          %{
            account_id: account.id,
            project_id: project.id,
            version: 1,
            status: "candidate"
          },
          attrs
        )
      )

    skill
  end

  @doc """
  Load a red-team corpus JSON from `test/support/fixtures/red_team/`. These are the
  existing adversarial corpora the benchmark reuses (SPEC §11 / fixtures/README).
  """
  def red_team(filename) do
    Path.join([__DIR__, "..", "fixtures", "red_team", filename])
    |> Path.expand()
    |> File.read!()
    |> Jason.decode!()
  end

  defp uniq, do: System.unique_integer([:positive])
end
