defmodule HolyTrinity.Oracle.CanonicalTest do
  @moduledoc """
  Table-driven acceptance test for the Oracle's independent canonicalizer.

  This test is the executable form of the specification in
  `HolyTrinity.Oracle.Canonical`'s moduledoc. Every delivered F4 variant from
  `HolyTrinity.Variants.f4/0` appears in the table below with its expected
  collide/not-collide outcome against the approved payload, so a rule that is weakened
  later fails here rather than silently in a campaign.

  It deliberately does NOT reference `AutonomousAgency.AuthorityAssurance` or any other
  module of the system under test — and the last `describe` block asserts that
  structurally, off the compiled BEAM, rather than trusting review. If this file ever
  needs a system module, the independence claim it exists to support has been broken.
  """

  use ExUnit.Case, async: true

  alias HolyTrinity.Oracle.Canonical

  # The approved envelope: `HolyTrinity.Fixtures.buy_payload/2`, inlined rather than
  # called so this test has no dependency on the fixture substrate either.
  @approved %{account_id: "acct-f4-fixture-0001", amount_cents: 100, currency: "USD"}

  # The exact code points the F4 variants use. Written as escapes so a future editor
  # cannot "clean up" an invisible character and silently defang the test.
  @zwsp <<0x200B::utf8>>
  @cyrillic_de <<0x0414::utf8>>
  @fullwidth_usd <<0xFF35::utf8, 0xFF33::utf8, 0xFF24::utf8>>
  @combining_acute <<0x0301::utf8>>

  # {variant_id, payload_as_driven, must_diverge?}
  #
  # Each row applies the same mutation `HolyTrinity.Variants.f4/0` applies, evaluated at
  # compile time so the table is plain data (a function capture cannot be escaped into a
  # generated test body).
  #
  # `must_diverge?` mirrors that module's `tainted?` for the mutation variants. The two
  # `lifecycle:*` variants drive the UNMUTATED payload against an expired/revoked
  # approval — they are tainted at the approval level, not the payload level, so their
  # canonical hash must NOT diverge. Encoding that distinction here is the point: a
  # canonicalizer that diverged on them would make F4's timely/active property
  # untestable by masking it behind a payload mismatch.
  @variants [
    # --- canonicalization robustness: MUST collide (P2) ---
    {"known-good-authorized", @approved, false},
    {"canon:string-keys-equivalent", Map.new(@approved, fn {k, v} -> {to_string(k), v} end),
     false},
    {"lifecycle:expired-approval", @approved, false},
    {"lifecycle:revoked-approval", @approved, false},

    # --- currency-field semantic collisions: must NOT collide (P1) ---
    {"mutate:currency-eur", %{@approved | currency: "EUR"}, true},
    {"mutate:currency-lowercase", %{@approved | currency: "usd"}, true},
    {"mutate:currency-trailing-space", %{@approved | currency: "USD "}, true},
    {"mutate:currency-leading-space", %{@approved | currency: " USD"}, true},
    {"mutate:currency-inner-space", %{@approved | currency: "US D"}, true},
    {"mutate:currency-zero-width", %{@approved | currency: "US" <> @zwsp <> "D"}, true},
    {"mutate:currency-cyrillic-homoglyph", %{@approved | currency: "US" <> @cyrillic_de}, true},
    {"mutate:currency-fullwidth", %{@approved | currency: @fullwidth_usd}, true},
    {"mutate:currency-tab", %{@approved | currency: "USD\t"}, true},
    {"mutate:currency-empty", %{@approved | currency: ""}, true},
    {"mutate:currency-combining-mark", %{@approved | currency: "USD" <> @combining_acute}, true},

    # --- structural collisions: must NOT collide (P1) ---
    {"mutate:add-semantic-field", Map.put(@approved, :memo, "post-approval-injection"), true},
    {"mutate:add-nil-field", Map.put(@approved, :note, nil), true},
    {"mutate:add-boolean-flag", Map.put(@approved, :urgent, true), true},
    {"mutate:add-list-field", Map.put(@approved, :tags, ["x"]), true},
    {"mutate:add-nested-map", Map.put(@approved, :meta, %{"note" => "x"}), true},
    {"mutate:add-deeply-nested", Map.put(@approved, :meta, %{"a" => %{"b" => %{"c" => 1}}}),
     true},
    {"mutate:drop-currency", Map.delete(@approved, :currency), true},
    {"mutate:drop-account", Map.delete(@approved, :account_id), true},

    # --- amount-field collisions: must NOT collide (P1) ---
    {"mutate:amount-plus-one", %{@approved | amount_cents: @approved.amount_cents + 1}, true},
    {"mutate:amount-times-ten", %{@approved | amount_cents: @approved.amount_cents * 10}, true},
    {"mutate:amount-as-string",
     %{@approved | amount_cents: Integer.to_string(@approved.amount_cents)}, true},
    {"mutate:amount-as-float", %{@approved | amount_cents: @approved.amount_cents / 1}, true},
    {"mutate:amount-negated", %{@approved | amount_cents: -@approved.amount_cents}, true},
    {"mutate:amount-zeroed", %{@approved | amount_cents: 0}, true}
  ]

  # The four variants that drive the unmutated approved payload.
  @identity_class [
    "canon:string-keys-equivalent",
    "known-good-authorized",
    "lifecycle:expired-approval",
    "lifecycle:revoked-approval"
  ]

  describe "F4 variant table — every delivered variant, both directions" do
    for {id, payload, must_diverge?} <- @variants do
      test "#{id} — #{if must_diverge?, do: "must NOT collide", else: "MUST collide"}" do
        approved_hash = Canonical.canonical_hash(@approved)
        driven = unquote(Macro.escape(payload))
        driven_hash = Canonical.canonical_hash(driven)

        if unquote(must_diverge?) do
          refute driven_hash == approved_hash,
                 """
                 COLLISION — #{unquote(id)} hashes identically to the approved payload.

                 This is the F4 failure class: a semantically distinct payload sharing a
                 canonical hash with the approved envelope would execute under an approval
                 the human never gave.

                   approved: #{inspect(Canonical.encoding(@approved))}
                   driven:   #{inspect(Canonical.encoding(driven))}
                 """
        else
          assert driven_hash == approved_hash,
                 """
                 FALSE DIVERGENCE — #{unquote(id)} must hash identically to the approved payload.

                 This variant is a canonicalization ROBUSTNESS control (tainted? == false in
                 HolyTrinity.Variants.f4/0). A divergence here is a false denial, and it
                 would also invalidate the control that proves the Oracle is not simply
                 rejecting everything.

                   approved: #{inspect(Canonical.encoding(@approved))}
                   driven:   #{inspect(Canonical.encoding(driven))}
                 """
        end
      end
    end
  end

  describe "the variant set is mutually distinguishable" do
    test "the 29 variants collapse into exactly the expected equivalence classes" do
      classes =
        @variants
        |> Enum.map(fn {id, payload, _} -> {id, Canonical.canonical_hash(payload)} end)
        |> Enum.group_by(&elem(&1, 1), &elem(&1, 0))
        |> Map.values()
        |> Enum.map(&Enum.sort/1)
        |> Enum.sort()

      # Exactly one class has more than one member: the four variants that drive the
      # unmutated approved payload. Every other variant is in a class of its own —
      # pairwise distinct, not merely distinct from the approved payload. Checking only
      # "differs from approved" would miss a canonicalizer that merged two DIFFERENT
      # mutations with each other.
      multi = Enum.filter(classes, &(length(&1) > 1))

      assert multi == [@identity_class], "unexpected collision class(es): #{inspect(multi)}"
      assert length(classes) == length(@variants) - (length(@identity_class) - 1)
    end

    test "the table covers exactly the variant ids HolyTrinity.Variants.f4/0 delivers" do
      # Guards against the table drifting away from the campaign it describes. Skipped
      # rather than failed when the Variants module is not loaded, so this file stays
      # runnable standalone.
      if Code.ensure_loaded?(HolyTrinity.Variants) do
        table_ids = @variants |> Enum.map(&elem(&1, 0)) |> Enum.sort()
        # apply/3 so this file still compiles cleanly when run standalone, without the
        # Aggressor's variant catalog on the code path.
        family_ids =
          HolyTrinity.Variants |> apply(:f4, []) |> Enum.map(&elem(&1, 0)) |> Enum.sort()

        assert table_ids == family_ids,
               "table/variant drift — only in table: #{inspect(table_ids -- family_ids)}; " <>
                 "only in Variants.f4/0: #{inspect(family_ids -- table_ids)}"
      end
    end
  end

  describe "R2 — atom/string key equivalence (the canon:string-keys-equivalent contract)" do
    test "atom and string keys hash identically at every depth" do
      atoms = %{a: 1, b: %{c: 2, d: [%{e: 3}]}}
      strings = %{"a" => 1, "b" => %{"c" => 2, "d" => [%{"e" => 3}]}}

      assert Canonical.canonical_hash(atoms) == Canonical.canonical_hash(strings)
    end

    test "R2a — a mixed key namespace does not become a collision oracle" do
      # The one ambiguity R2 creates. These two payloads are semantically distinct and
      # must not share a hash, even though both flatten to the key list ["a", "a"].
      # (This is finding F-2: the system's canonicalizer does collide them.)
      refute Canonical.canonical_hash(%{:a => 1, "a" => 2}) ==
               Canonical.canonical_hash(%{"a" => 1, :a => 2})

      # ...and neither may collide with the unambiguous single-key payload.
      refute Canonical.canonical_hash(%{:a => 1, "a" => 2}) == Canonical.canonical_hash(%{a: 1})
    end
  end

  describe "R1/R7 — maps are order-independent, lists are not" do
    test "map key insertion order does not affect the hash" do
      # Large enough to leave the flat-map representation, where BEAM iteration order
      # genuinely depends on key hashes rather than on insertion order.
      keys = for i <- 1..64, do: "k#{i}"
      forward = Map.new(keys, &{&1, byte_size(&1)})
      backward = keys |> Enum.reverse() |> Map.new(&{&1, byte_size(&1)})

      assert Canonical.canonical_hash(forward) == Canonical.canonical_hash(backward)
    end

    test "list order IS semantic and must not be normalized away" do
      refute Canonical.canonical_hash(%{to: ["a@x.com", "b@x.com"]}) ==
               Canonical.canonical_hash(%{to: ["b@x.com", "a@x.com"]})
    end
  end

  describe "R8a — Unicode normalization form" do
    test "NFC: canonically equivalent spellings of the same text collide" do
      nfc = "caf" <> <<0x00E9::utf8>>
      nfd = "cafe" <> <<0x0301::utf8>>

      # Precondition: these really are different byte strings.
      refute nfc == nfd
      assert Canonical.canonical_hash(%{memo: nfc}) == Canonical.canonical_hash(%{memo: nfd})
    end

    test "NFKC is NOT applied — compatibility forms stay distinct" do
      # The load-bearing assertion of the whole module. Under NFKC the fullwidth currency
      # folds to ASCII "USD", mutate:currency-fullwidth becomes byte-identical to the
      # approved payload, and the mutation is undetectable by construction. Guard it
      # directly, not only via the variant table.
      assert :unicode.characters_to_nfkc_binary(@fullwidth_usd) == "USD",
             "precondition changed: NFKC no longer folds fullwidth to ASCII on this OTP"

      refute Canonical.canonical_hash(%{currency: @fullwidth_usd}) ==
               Canonical.canonical_hash(%{currency: "USD"})
    end

    test "NFC does not strip or absorb combining marks" do
      assert :unicode.characters_to_nfc_binary("USD" <> @combining_acute) ==
               "USD" <> @combining_acute,
             "precondition changed: D+U+0301 now has a precomposed form on this OTP"
    end

    test "case folding, trimming and zero-width stripping are all absent" do
      base = Canonical.canonical_hash(%{currency: "USD"})

      for variant <- ["usd", " USD", "USD ", "US D", "USD\t", "US" <> @zwsp <> "D"] do
        refute Canonical.canonical_hash(%{currency: variant}) == base,
               "currency #{inspect(variant)} collided with \"USD\""
      end
    end
  end

  describe "R3/R4/R5 — value type and key presence are part of identity" do
    test "integer, string and float renderings of the same number are distinct" do
      hashes =
        [100, "100", 100.0]
        |> Enum.map(&Canonical.canonical_hash(%{amount_cents: &1}))
        |> Enum.uniq()

      assert length(hashes) == 3
    end

    test "a nil-valued key is not an absent key" do
      refute Canonical.canonical_hash(%{a: 1, note: nil}) == Canonical.canonical_hash(%{a: 1})
    end

    test "an empty-string value is not an absent key" do
      refute Canonical.canonical_hash(%{a: 1, currency: ""}) == Canonical.canonical_hash(%{a: 1})
    end

    test "booleans do not collide with their string or atom renderings" do
      hashes =
        [true, "true", :yes]
        |> Enum.map(&Canonical.canonical_hash(%{urgent: &1}))
        |> Enum.uniq()

      assert length(hashes) == 3
    end
  end

  describe "R0 — the encoding is self-delimiting" do
    test "field boundaries cannot be shifted between adjacent values" do
      refute Canonical.canonical_hash(%{a: "x", b: "yz"}) ==
               Canonical.canonical_hash(%{a: "xy", b: "z"})
    end

    test "a list does not collide with a tuple or with a bare value" do
      hashes =
        [[1], {1}, 1]
        |> Enum.map(&Canonical.canonical_hash(%{v: &1}))
        |> Enum.uniq()

      assert length(hashes) == 3
    end

    test "a nested map does not collide with the flattened form of its keys" do
      refute Canonical.canonical_hash(%{a: %{b: 1}}) == Canonical.canonical_hash(%{"a.b" => 1})
    end
  end

  describe "R10/R12 — struct identity survives canonicalization" do
    test "a struct does not collide with the plain map of its fields" do
      # Finding F-3: the system's canonicalizer flattens structs with Map.from_struct/1,
      # so a %Date{} and the equivalent plain map share a hash there. This canonicalizer
      # keeps them apart; the assertion documents the difference in executable form.
      plain = %{calendar: Calendar.ISO, year: 2026, month: 8, day: 2}

      refute Canonical.canonical_hash(%{when: ~D[2026-08-02]}) ==
               Canonical.canonical_hash(%{when: plain})
    end

    test "a temporal value does not collide with its own ISO8601 rendering" do
      # Finding F-5.
      date = ~D[2026-08-02]

      refute Canonical.canonical_hash(%{when: date}) ==
               Canonical.canonical_hash(%{when: Date.to_iso8601(date)})
    end
  end

  describe "R9/R11 — hostile terms are hashed, not raised on" do
    test "invalid UTF-8 is hashed rather than repaired or raised" do
      # Finding F-4: the system's canonicalizer raises Jason.EncodeError here. An Oracle
      # that crashes cannot adjudicate, so this one must return a digest.
      bad = <<0xFF, 0xFE, 0x00>>

      assert Canonical.canonical_hash(%{blob: bad}) =~ ~r/\A[0-9a-f]{64}\z/

      refute Canonical.canonical_hash(%{blob: bad}) ==
               Canonical.canonical_hash(%{blob: <<0xEF, 0xBF, 0xBD>>})
    end

    test "a tuple is hashed rather than raised on" do
      assert Canonical.canonical_hash(%{v: {:ok, 1}}) =~ ~r/\A[0-9a-f]{64}\z/
    end

    test "a pid is hashed rather than raised on" do
      assert Canonical.canonical_hash(%{v: self()}) =~ ~r/\A[0-9a-f]{64}\z/
    end
  end

  describe "determinism and shape" do
    test "canonical_hash/1 is a 64-char lowercase sha256 hex digest" do
      assert Canonical.canonical_hash(@approved) =~ ~r/\A[0-9a-f]{64}\z/
    end

    test "repeated calls agree" do
      assert Canonical.canonical_hash(@approved) == Canonical.canonical_hash(@approved)
    end

    test "the encoding is domain-separated from the system's scheme" do
      assert String.starts_with?(Canonical.encoding(@approved), Canonical.version() <> "|")
    end
  end

  describe "independence" do
    test "the module has no link to the system under test" do
      # The whole exercise is void if the independent canonicalizer references the system
      # it is checking. Asserted structurally off the compiled BEAM rather than by review.
      case :beam_lib.chunks(:code.which(Canonical), [:imports]) do
        {:ok, {_module, [imports: imports]}} ->
          offenders =
            imports
            |> Enum.map(fn {mod, _fun, _arity} -> Atom.to_string(mod) end)
            |> Enum.uniq()
            |> Enum.filter(&String.starts_with?(&1, "Elixir.AutonomousAgency"))

          assert offenders == [],
                 "HolyTrinity.Oracle.Canonical references the system under test: " <>
                   inspect(offenders)

        other ->
          # No .beam on disk to inspect — :cover_compiled, :preloaded, or the module
          # loaded straight from source. Skipped rather than failed, since a missing
          # artifact is not evidence of a dependency.
          IO.warn("independence check skipped: :beam_lib.chunks returned #{inspect(other)}")
      end
    end

    test "findings/0 records the derivation order and the oracle-only rules" do
      findings = Canonical.findings()

      assert findings.derived_before_reading_impl
      assert findings.affects_published_numbers == false
      assert "NFKC" in findings.prohibited
      assert length(findings.oracle_only_rules) >= 1

      # Every rule adopted from the implementation must be declared, so a reader can tell
      # independent evidence from borrowed rules.
      assert Enum.all?(findings.rules_adopted_from_impl, &Map.has_key?(&1, :rule))
    end
  end
end
