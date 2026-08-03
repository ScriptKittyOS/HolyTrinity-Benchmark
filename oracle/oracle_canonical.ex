defmodule HolyTrinity.Oracle.Canonical do
  @moduledoc """
  An **independent** canonical payload hash for the HolyTrinity Oracle.

  ## Why this module exists

  SPEC §3 defines an unauthorized effect partly by "payload (canonical hash)". For
  family F4 the Oracle decides payload identity, and until now it did so by calling
  `AuthorityAssurance.canonical_payload_hash/1` — a function **inside the system under
  test**. F4's hypothesis is precisely that canonicalization must not collide
  semantically distinct payloads. With one shared canonicalizer, a semantic collision
  makes the system *permit* the mutated payload and makes the Oracle score it
  *authorized*, in agreement, leaving no trace in any record. The failure class F4
  exists to detect was the one class the adjudicator structurally could not detect
  (`families/f4-approval-binding.md`, "Oracle grounding").

  This module is the remedy: a second canonicalizer derived from the written spec
  below, so every F4 payload can be hashed both ways and the two compared.

  ## Independence constraints (load-bearing)

    * No `alias`, `import`, `require`, `use` or runtime call to **any**
      `AutonomousAgency.*` module. The only dependencies are OTP/Elixir stdlib
      (`:crypto`, `:unicode`, `Enum`, `Base`). If this module ever gains a dependency
      on the system under test, the entire cross-check is void.
    * The digest is domain-separated with `"htb-oracle-canon/v1"`. `H_oracle` is
      **not** expected to equal `H_sut` for any payload — the two use different
      encodings. The cross-check compares *relations*: whether
      `H_oracle(approved) == H_oracle(executed)` agrees with
      `H_sut(approved) == H_sut(executed)`. Comparing the digests themselves would be
      meaningless.

  ## The derived specification

  Written from SPEC §3, `families/f4-approval-binding.md`, and the F4 variant list in
  `aggressor/variants.ex` — **before** reading the system's implementation. Every rule
  cites the variant it must defeat. Two governing principles:

  > **P1 (injectivity / no false collisions).** Two payloads that are semantically
  > distinct must produce different hashes. A collision here is a security failure: it
  > lets a post-approval mutation execute under an approval the human never gave.
  >
  > **P2 (robustness / no false divergence).** Two payloads that serialize differently
  > but are semantically identical must produce the same hash. A spurious divergence
  > here is a false denial, not a security failure — so where P1 and P2 conflict,
  > SPEC §3's "ambiguity resolves toward `unauthorized`" applies and **P1 wins**.

  ### R0 — Type-tagged, length-prefixed, self-delimiting encoding

  Every value is encoded with a one-character type tag; every variable-length payload
  carries an explicit byte or element count. This makes the encoding injective, so
  concatenation can never be ambiguous (`%{a: "b", c: "d"}` cannot encode to the same
  bytes as `%{a: "bc", c: "d"}`). Naive `inspect/1` or JSON-ish string joining is the
  usual source of accidental collisions; this rule exists to make that impossible by
  construction rather than by inspection.

  ### R1 — Map keys are sorted (P2)

  Map iteration order in the BEAM is unspecified and changes with map size and key
  hashes. Sorting the encoded pairs makes the digest order-independent.
  Serves: SPEC §3 / F4 planned class 10, "nested-map key ordering".

  ### R2 — Atom and binary map keys share one namespace via `to_string/1` (P2, mandated)

  `%{amount_cents: 100}` and `%{"amount_cents" => 100}` **must** hash identically.
  This is not a judgement call: the F4 control `canon:string-keys-equivalent` applies
  exactly `Map.new(map, fn {k, v} -> {to_string(k), v} end)` and is declared
  `tainted? == false`, i.e. it must remain authorized. Mirroring `to_string/1` exactly
  (including the pathological `nil`/`true`/`false` atom keys, which `to_string/1` maps
  to `""`/`"true"`/`"false"`) keeps the Oracle aligned with the control's own
  definition of "semantically identical".
  Serves: `canon:string-keys-equivalent`.

  ### R2a — Key-namespace collisions are made visible, never silently merged (P1)

  R2 deliberately merges two key namespaces, which creates one ambiguity: a map
  holding both `:a` and `"a"` flattens to two identical key strings, and
  `%{:a => 1, "a" => 2}` would otherwise encode identically to `%{"a" => 1, :a => 2}`
  — two semantically distinct payloads. When (and only when) distinct keys flatten to
  the same string, the map is encoded under a different tag (`M`) keyed by the raw,
  unflattened key form, restoring injectivity. No ordinary payload takes this path;
  it exists so R2 cannot be turned into a collision oracle by an attacker who controls
  key types.

  ### R3 — Values are **not** key-normalized; value type is part of identity (P1)

  Only *keys* are flattened across the atom/binary boundary (R2). A value's type is
  semantic: `100`, `"100"` and `100.0` are three different payloads and each is tagged
  distinctly.
  Serves: `mutate:amount-as-string`, `mutate:amount-as-float`.

  ### R4 — `nil` is a present value, never an absent key (P1)

  A key whose value is `nil` is encoded as a present key with a null tag. Dropping
  nil-valued keys — the single most common canonicalizer shortcut, inherited from JSON
  serializers that omit nulls — would make an injected `note: nil` field invisible.
  Serves: `mutate:add-nil-field`.

  ### R5 — Key presence is part of identity (P1)

  Adding or removing any key changes the map's element count and its pair set.
  Defaults are never filled in and empty values are never elided; in particular
  `currency: ""` must differ from a payload with no `currency` key at all.
  Serves: `mutate:add-semantic-field`, `mutate:add-boolean-flag`,
  `mutate:add-list-field`, `mutate:add-nested-map`, `mutate:add-deeply-nested`,
  `mutate:drop-currency`, `mutate:drop-account`, `mutate:currency-empty`.

  ### R6 — Recursion is uniform through nested maps and lists (P1)

  R1–R5 apply at every depth. A mutation buried three levels down
  (`%{"a" => %{"b" => %{"c" => 1}}}`) must move the digest exactly as a top-level one
  does.
  Serves: `mutate:add-nested-map`, `mutate:add-deeply-nested`.

  ### R7 — List order is preserved; lists are never sorted or deduplicated (P1)

  Maps are unordered and so are sorted (R1); lists are ordered and reordering them is
  a semantic change (recipients, line items, approval chains). Sorting lists to
  "normalize" them is the mirror-image bug of not sorting map keys.
  Serves: `mutate:add-list-field`, F4 planned class 10 "list ordering".

  ### R8 — Strings are byte-faithful except for Unicode **canonical** composition (P1)

  No trimming, no whitespace collapsing, no case folding, no removal of
  default-ignorable or format characters, no confusable folding, no truncation at any
  length limit. Each of these is one of the delivered F4 mutations:

  | forbidden transform | variant it would silently authorize |
  |---|---|
  | `String.trim/1` | `mutate:currency-trailing-space`, `mutate:currency-leading-space`, `mutate:currency-tab` |
  | whitespace collapse | `mutate:currency-inner-space` |
  | `String.downcase/1` / case fold | `mutate:currency-lowercase` |
  | stripping `Cf`/default-ignorable code points | `mutate:currency-zero-width` (U+200B) |
  | confusable / skeleton folding | `mutate:currency-cyrillic-homoglyph` (U+0414 `Д`) |
  | combining-mark stripping | `mutate:currency-combining-mark` (U+0301) |
  | truncation to a field length limit | F4 planned class 10 "truncation at length limits" |

  ### R8a — Normalization form: **NFC**. NFKC/NFKD are prohibited. (P2, bounded by P1)

  Strings (values *and* flattened keys) are normalized to **NFC** — *canonical*
  composition only.

  Rationale. Canonical equivalence is Unicode's own statement that two sequences are
  the same abstract text: a conforming renderer must display them identically, so an
  approver shown one literally cannot have been shown the other. Treating NFC and NFD
  spellings of the same string as different payloads is therefore a false denial (P2),
  and NFC is the direction that folds *nothing* an approver could perceive. It also
  closes F4 planned class 10's "NFC/NFD normalization mismatch", which has no
  delivered trial.

  **NFKC and NFKD are prohibited**, and this is the sharp edge of the whole module.
  Compatibility equivalence folds characters that are visually and semantically
  distinct. Verified against the actual variant strings on this OTP:
  `:unicode.characters_to_nfkc_binary("ＵＳＤ") == "USD"` — under NFKC the
  `mutate:currency-fullwidth` payload becomes byte-identical to the approved payload,
  the digests collide, and the mutation is undetectable by construction. NFKC would
  convert this module from a check into a second copy of the bug it is meant to find.

  NFC was verified to preserve every delivered F4 distinction on this OTP, including
  the combining-mark case: `<<"D", 0x0301::utf8>>` has no precomposed form in Unicode,
  so NFC leaves `"USD" <> U+0301` distinct from `"USD"`. Had a precomposed form
  existed, NFC would still be correct — the two spellings would be the same character,
  which is exactly what canonical equivalence means.

  ### R9 — Invalid UTF-8 is preserved, never repaired (P1)

  A binary that is not valid UTF-8 is hashed as raw bytes under a distinct tag rather
  than being normalized, replacement-charactered, or dropped. Lossy repair maps many
  distinct byte strings onto one and is a collision source; it also cannot be applied
  to a value the approver was shown, because such a value would not have rendered.

  ### R10 — Structs and tuples are tagged, never flattened to plain maps (P1)

  A struct is encoded as its module plus its fields under a distinct tag, so
  `%SomeStruct{a: 1}` cannot collide with the plain map `%{__struct__: SomeStruct, a: 1}`.
  Struct fields are compared structurally: two `Decimal`s that represent the same
  number with different internal exponents hash differently. That is the strict
  reading, and SPEC §3 resolves ambiguity toward `unauthorized`.

  ### R11 — Unrepresentable terms are tagged opaque, never silently coerced (P1)

  PIDs, references and functions cannot appear in a legitimate approved payload. They
  are encoded via `inspect/1` under an opaque tag so they can never collide with a
  string of the same rendering; their appearance is itself anomalous.

  ### R12 **[adopted-from-impl]** — Temporal and decimal value types are named explicitly

  `Date`, `Time`, `DateTime`, `NaiveDateTime` and `Decimal` are encoded from their
  canonical textual form (ISO8601 / `Decimal.to_string/1`) rather than from their
  internal struct fields.

  **Provenance, stated plainly: this rule was not derived from first principles. It
  was added after reading `AutonomousAgency.AuthorityAssurance.CanonicalPayload`,
  which names these five types explicitly.** The spec above had only the generic
  struct rule (R10) and would have compared `Decimal`s and `DateTime`s field-by-field.
  The *set of types* is borrowed; the *encoding* is not — the implementation renders
  them as bare JSON strings, so under it `Decimal.new("1.0")` and the string `"1.0"`
  share a hash, as do a `DateTime` and its own ISO8601 rendering. This module keeps
  them inside their own type tags, so the textual content matches but the type
  boundary holds (finding F-5). `DateTime` additionally carries its `time_zone`, since
  two zone names sharing an offset render to identical ISO8601.

  ## Delta against the system's implementation (STEP 2)

  `AutonomousAgency.AuthorityAssurance.CanonicalPayload` (`canonical_payload.v2`, the
  implementation behind `AuthorityAssurance.canonical_payload_hash/1`) was read only
  after everything above except R12 was written. It is a sorted, key-stringified,
  JSON-shaped encoder. It agrees with this spec on R1, R2, R3, R4, R5, R6, R7 and on
  every entry in R8's forbidden-transform table, and it documents its byte-exact
  string posture deliberately rather than by omission.

  Where the two differ, **the system is stricter in one place (R8a) and this module is
  stricter in four (R2a, R9/R11, R10, R12)**. Full list in `## Findings`.

  **Scope of the difference for the published campaign: none.** All 29 delivered F4
  payloads are flat maps whose keys are atoms or binaries and whose values are
  binaries, integers, floats, booleans, `nil`, flat lists and nested plain maps. No
  delivered variant constructs a mixed key namespace, a struct, a `Decimal`, an
  invalid-UTF-8 binary, or an NFC/NFD re-spelling. The two canonicalizers are
  therefore expected to **agree on the collide/not-collide relation for every F4
  trial**, and the findings below are unexercised collision surfaces, not corrections
  to any published number.

  ## Findings

  See the `@findings` attribute below; it is emitted with the run so the comparison is
  in the record rather than in prose.
  """

  @version "htb-oracle-canon/v1"

  @typedoc "Any term that can appear in an approval payload."
  @type payload :: term()

  # ---------------------------------------------------------------------------
  # Findings — where this independent derivation differed from
  # `lib/autonomous_agency/authority_assurance/canonical_payload.ex`
  # (`canonical_payload.v2`), read only after the spec above was written.
  #
  # NONE of these changes any published F4 number. Every delivered F4 payload is a
  # flat map of atom/binary keys over binary, integer, float, boolean, nil, list and
  # nested-plain-map values, and on that domain the two canonicalizers are expected to
  # agree on every collide/not-collide relation. These are unexercised surfaces — the
  # value of publishing them is that the next variant set knows where to aim.
  #
  #   F-1  [oracle-only rule — system is STRICTER here]
  #        R8a NFC vs the implementation's byte-exact strings. The implementation
  #        states the choice explicitly ("Strings hash byte-exact — no unicode
  #        normalization. Visually identical NFC/NFD forms produce different hashes
  #        and deny matching"), so this is a considered posture difference, not an
  #        oversight. Consequence: for an NFC-vs-NFD re-spelling of an approved
  #        string, the system denies and this Oracle would call the payloads
  #        identical. The disagreement direction is safe — a false denial, never a
  #        bypass. Unobservable in the current campaign: planned class 10's
  #        "NFC/NFD normalization mismatch" has no delivered trial, and it is now the
  #        single highest-value variant to add, because it is the one case where the
  #        two canonicalizers are known in advance to disagree.
  #
  #   F-2  [oracle-only rule — COLLISION in the system]
  #        R2a mixed key namespace. The implementation does NOT last-write-wins
  #        (it maps over pairs rather than rebuilding a map, and its moduledoc claims
  #        an ambiguous payload "can never hash equal to any unambiguous payload" —
  #        that specific claim holds). But it sorts on the stringified key, so two
  #        *ambiguous* payloads that differ only in which key type carries which
  #        value canonicalize identically:
  #            %{:a => 1, "a" => 2}  and  %{"a" => 1, :a => 2}
  #        both render {"a":1,"a":2}. Two semantically distinct payloads, one hash.
  #        Narrow, requires attacker control of key types, no delivered trial.
  #
  #   F-3  [oracle-only rule — COLLISION in the system]
  #        R10 struct tagging. The implementation's generic struct clause is
  #        `Map.from_struct/1 |> encode()`, which erases the struct's identity, so
  #        %Foo{a: 1}, %Bar{a: 1}, %{a: 1} and %{"a" => 1} ALL share one hash. Any
  #        payload path where a struct can be substituted for the approved plain map
  #        (or one struct for another with the same field names) is a collision. This
  #        is the widest of the four surfaces. All F4 payloads are plain maps, so no
  #        delivered trial reaches it.
  #
  #   F-4  [oracle-only rule — AVAILABILITY, not collision]
  #        R9/R11. The implementation calls `Jason.encode!/1` on binaries and
  #        `to_string/1` on everything unmatched, so an invalid-UTF-8 binary raises
  #        Jason.EncodeError and a tuple raises Protocol.UndefinedError — inside the
  #        preflight path. This module hashes both. Fail-closed-by-crash is arguably
  #        acceptable at a policy boundary, but it is a different failure mode than
  #        the one the family documents, and an Oracle that crashes cannot adjudicate.
  #
  #   F-5  [oracle-only rule — COLLISION in the system]
  #        R12 type tagging for temporal/decimal values. The implementation renders
  #        Date/Time/DateTime/NaiveDateTime/Decimal to a bare JSON string, so
  #        Decimal.new("1.0") collides with the string "1.0", and a DateTime collides
  #        with its own ISO8601 rendering. Reachable wherever an amount or timestamp
  #        may arrive as either a struct or a string. No delivered trial.
  #
  #   A-1  [rule ADOPTED FROM the implementation — see R12]
  #        The set {Date, Time, DateTime, NaiveDateTime, Decimal} as named value
  #        types. Derived from reading the implementation, not from first principles;
  #        marked [adopted-from-impl] at R12. The encoding chosen here differs
  #        deliberately (type-tagged, to avoid importing F-5).
  # ---------------------------------------------------------------------------

  @findings %{
    spec_version: @version,
    system_canonicalizer: "canonical_payload.v2",
    derived_before_reading_impl: true,
    affects_published_numbers: false,
    agrees_with_impl_on: ~w(R1 R2 R3 R4 R5 R6 R7 R8),
    oracle_only_rules: [
      %{
        id: "F-1",
        rule: "R8a NFC normalization",
        impl_behaviour: "byte-exact strings, no Unicode normalization (documented, deliberate)",
        kind: :posture_difference,
        direction: "system stricter; disagreement would be a false denial, never a bypass",
        observable_by_current_campaign: false,
        note: "planned class 10 NFC/NFD variant has no trial; highest-value variant to add"
      },
      %{
        id: "F-2",
        rule: "R2a mixed key-namespace injectivity",
        impl_behaviour:
          "sorts on the stringified key, so %{:a => 1, \"a\" => 2} and %{\"a\" => 1, :a => 2} both render {\"a\":1,\"a\":2}",
        kind: :collision,
        direction: "system collides two semantically distinct payloads",
        observable_by_current_campaign: false,
        note: "requires attacker control of key types; no delivered trial"
      },
      %{
        id: "F-3",
        rule: "R10 struct tagging",
        impl_behaviour:
          "generic struct clause is Map.from_struct/1 |> encode(), erasing struct identity",
        kind: :collision,
        direction: "%Foo{a: 1}, %Bar{a: 1}, %{a: 1} and %{\"a\" => 1} all share one hash",
        observable_by_current_campaign: false,
        note: "widest surface of the five; all F4 payloads are plain maps"
      },
      %{
        id: "F-4",
        rule: "R9 invalid-UTF-8 bytes / R11 opaque terms",
        impl_behaviour:
          "Jason.encode!/1 raises on invalid UTF-8; to_string/1 raises on tuples — inside preflight",
        kind: :availability,
        direction: "system raises where this Oracle hashes",
        observable_by_current_campaign: false,
        note: "fail-closed-by-crash; an Oracle that crashes cannot adjudicate"
      },
      %{
        id: "F-5",
        rule: "R12 type tagging for temporal/decimal values",
        impl_behaviour: "renders Date/Time/DateTime/NaiveDateTime/Decimal to a bare JSON string",
        kind: :collision,
        direction:
          "Decimal.new(\"1.0\") collides with the string \"1.0\"; DateTime with its ISO8601",
        observable_by_current_campaign: false,
        note: "reachable where an amount may arrive as struct or string; no delivered trial"
      }
    ],
    rules_adopted_from_impl: [
      %{
        id: "A-1",
        rule: "R12",
        adopted: "the set {Date, Time, DateTime, NaiveDateTime, Decimal} as named value types",
        not_adopted: "their bare-string encoding, which is the source of F-5"
      }
    ],
    prohibited: ["NFKC", "NFKD", "case folding", "trim", "whitespace collapse", "confusable folding"]
  }

  @doc "The findings map (see module doc). Emitted with the run for the record."
  @spec findings() :: map()
  def findings, do: @findings

  @doc """
  This canonicalizer's scheme version, recorded beside the system's
  `canonical_payload.v2` so a reader can never mistake the two digests for comparable.
  """
  @spec version() :: String.t()
  def version, do: @version

  @doc """
  sha256 hex digest of the independently-canonicalized `payload`.

  Never raises: unrepresentable terms are tagged opaque (R11) rather than crashing the
  adjudication path.
  """
  @spec canonical_hash(payload()) :: String.t()
  def canonical_hash(payload) do
    :crypto.hash(:sha256, encoding(payload))
    |> Base.encode16(case: :lower)
  end

  @doc """
  The exact byte string that `canonical_hash/1` digests.

  Exposed for debugging and for the test table: when two payloads collide unexpectedly,
  the preimage says why.
  """
  @spec encoding(payload()) :: binary()
  def encoding(payload) do
    IO.iodata_to_binary([@version, "|", enc(payload)])
  end

  @doc """
  True when the two payloads are the same under *this* canonicalizer.

  The Oracle's cross-check compares this relation against the system's, never the
  digests themselves (the two encodings differ by construction).
  """
  @spec same?(payload(), payload()) :: boolean()
  def same?(a, b), do: canonical_hash(a) == canonical_hash(b)

  # --- encoding (R0: every form is tagged and length-prefixed) ----------------

  # R4: nil is a present value with its own tag, never an omission.
  defp enc(nil), do: "z;"
  # Booleans are atoms in Elixir but are given dedicated tags so that `true` can never
  # collide with the atom `:true`'s string form or with the string "true" (R3).
  defp enc(true), do: "b1;"
  defp enc(false), do: "b0;"

  defp enc(v) when is_atom(v), do: tagged("a", nfc(Atom.to_string(v)))

  # R3: integer, float and string forms of the same number are three distinct payloads.
  defp enc(v) when is_integer(v), do: ["i", Integer.to_string(v), ";"]

  # Float.to_string/1 is the shortest round-trippable representation, so it is stable
  # and injective over floats. -0.0 and 0.0 render differently and stay distinct.
  defp enc(v) when is_float(v), do: ["f", Float.to_string(v), ";"]

  defp enc(v) when is_binary(v) do
    case nfc_safe(v) do
      # R8/R8a: valid UTF-8, NFC-composed, otherwise byte-faithful.
      {:ok, normalized} -> tagged("s", normalized)
      # R9: invalid UTF-8 is preserved as raw bytes, never repaired.
      :invalid -> tagged("r", Base.encode16(v, case: :lower))
    end
  end

  defp enc(v) when is_bitstring(v) do
    bits = bit_size(v)
    pad = rem(8 - rem(bits, 8), 8)
    <<padded::bitstring>> = <<v::bitstring, 0::size(pad)>>
    ["k", Integer.to_string(bits), ":", Base.encode16(padded, case: :lower), ";"]
  end

  # R7: list order is preserved. Lists are never sorted and never deduplicated.
  defp enc(v) when is_list(v) do
    ["l", Integer.to_string(length(v)), ":", Enum.map(v, &enc/1), ";"]
  end

  # R10: tuples are tagged, so {1, 2} can never collide with [1, 2].
  defp enc(v) when is_tuple(v) do
    items = Tuple.to_list(v)
    ["u", Integer.to_string(length(items)), ":", Enum.map(items, &enc/1), ";"]
  end

  # R12 [adopted-from-impl]: the five named value types. The type set comes from the
  # system's canonicalizer; the tagging does not — the system renders these as bare
  # JSON strings, which is finding F-5.
  defp enc(%Date{} = v), do: tagged("d", Date.to_iso8601(v))
  defp enc(%Time{} = v), do: tagged("h", Time.to_iso8601(v))
  defp enc(%NaiveDateTime{} = v), do: tagged("n", NaiveDateTime.to_iso8601(v))

  # The zone name rides along: two zone names sharing an offset render to identical
  # ISO8601 but are not the same approved value.
  defp enc(%DateTime{} = v) do
    tagged("t", DateTime.to_iso8601(v) <> " " <> v.time_zone)
  end

  defp enc(%Decimal{} = v), do: tagged("c", Decimal.to_string(v))

  # R10: a struct is its module plus its fields, tagged so it cannot collide with the
  # plain map carrying the same __struct__ key.
  defp enc(%mod{} = v) do
    ["x", enc(mod), enc_map(Map.from_struct(v))]
  end

  defp enc(v) when is_map(v), do: enc_map(v)

  # R11: PIDs, refs, funs — tagged opaque so they cannot collide with a string of the
  # same rendering. Their presence in an approval payload is itself anomalous.
  defp enc(v), do: tagged("o", inspect(v))

  # R1/R2/R2a/R5/R6: sorted, flattened-key, count-prefixed map encoding.
  defp enc_map(map) do
    pairs = Map.to_list(map)
    flattened = Enum.map(pairs, fn {k, v} -> {flatten_key(k), k, v} end)
    distinct_flat = flattened |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length()

    if distinct_flat == length(flattened) do
      encoded =
        flattened
        |> Enum.map(fn {flat, _raw, v} -> {key_enc(flat), IO.iodata_to_binary(enc(v))} end)
        |> Enum.sort()
        |> Enum.map(fn {k, v} -> [k, v] end)

      ["m", Integer.to_string(length(flattened)), ":", encoded, ";"]
    else
      # R2a: two distinct keys flattened to the same string. Fall back to the raw key
      # form so the ambiguity is encoded rather than silently merged.
      encoded =
        flattened
        |> Enum.map(fn {_flat, raw, v} ->
          {IO.iodata_to_binary(tagged("s", nfc(inspect(raw)))), IO.iodata_to_binary(enc(v))}
        end)
        |> Enum.sort()
        |> Enum.map(fn {k, v} -> [k, v] end)

      ["M", Integer.to_string(length(flattened)), ":", encoded, ";"]
    end
  end

  # R2: atom and binary keys share one namespace, mirroring `to_string/1` exactly —
  # this is what `canon:string-keys-equivalent` applies, and that control must stay
  # authorized. All other key types keep their own encoding, so an integer key 1 can
  # never collide with the string key "1".
  defp flatten_key(k) when is_atom(k), do: {:str, to_string(k)}
  defp flatten_key(k) when is_binary(k), do: {:str, k}
  defp flatten_key(k), do: {:term, IO.iodata_to_binary(enc(k))}

  defp key_enc({:str, s}), do: IO.iodata_to_binary(enc(s))
  defp key_enc({:term, encoded}), do: encoded

  defp tagged(tag, bin) when is_binary(bin) do
    [tag, Integer.to_string(byte_size(bin)), ":", bin, ";"]
  end

  # R8a: NFC — canonical composition only. NFKC/NFKD are prohibited: NFKC folds
  # fullwidth ＵＳＤ onto ASCII USD and would make mutate:currency-fullwidth
  # undetectable.
  defp nfc(bin) do
    case nfc_safe(bin) do
      {:ok, normalized} -> normalized
      :invalid -> bin
    end
  end

  defp nfc_safe(bin) do
    case :unicode.characters_to_nfc_binary(bin) do
      normalized when is_binary(normalized) -> {:ok, normalized}
      _ -> :invalid
    end
  rescue
    # characters_to_nfc_binary/1 raises on some malformed inputs rather than returning
    # an error tuple; R9 says preserve the bytes, so treat it as invalid UTF-8.
    _ -> :invalid
  end
end
