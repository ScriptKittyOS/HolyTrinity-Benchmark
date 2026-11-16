#!/usr/bin/env elixir
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
#
# verify_receipt.exs — check a Trinity authority receipt's Ed25519 signature.
#
#   elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json
#       [--checkpoint NOTE --inclusion-proof PROOF.json --witness-policy POLICY
#        [--held-size N --held-root ROOT | --held-state FILE [--write-held-state]]
#        [--consistency-proof PROOF.json] [--key-transition RECORD.json]]
#
# LOG CHECKPOINTS. With --checkpoint, a receipt that VERIFIED is also checked against a checkpoint of the
# evaluation environment's transparency log (the module LogCheckpoint in verify_receipt_checkpoint.exs,
# beside this file, loaded only then; CHECKPOINTS.md states the checks, the inputs, every refusal and
# what is not checked).
#
# No Mix project, no hex packages, no network. Requires Elixir 1.17 / OTP 27 or later for the
# built-in `:json` module; verified on Elixir 1.19.2 / OTP 28.
#
# EXIT CODES AND EVERY VERDICT CASE ARE DEFINED IN ONE PLACE: VERDICTS.md, beside this file. It is
# the single source, it is parsed by the cross-check test, and this header cites it rather than
# restating it. Four copies of one rule is how the copies drift.
#
# The numbers are frozen at 0, 1, 2, 5, 6 and no others may be introduced; 0, 1, 2 and 6 are this
# project's proposal and are PROVISIONAL. The one distinction to
# carry in your head while reading: `1` accuses the receipt, `5` declines to judge it, and
# collapsing them tells an examiner a receipt was forged when it was merely unverifiable.
#
# PATTERN CREDIT — the default-distrust posture, the refusal when signer trust is not established
# from bundle-local key material, and the discipline of disclosing flaws unprompted are taken from:
#
#   Nathan Howard (Third Level IT / thirdlevel.ai)
#   VIRP verifier, v0.1.0
#   https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier
#
# THIS VERIFIER IS OUR ARTIFACT. An examiner who distrusts us has no reason to trust it either.
# It is short and dependency-free so it can be read in full, the signing scheme is specified in
# README.md so it can be reimplemented from scratch, and a second independent implementation ships
# beside it (verify_receipt.py, Python standard library only). Two implementations agreeing is a
# stronger basis than either alone. They share NO code, on purpose.

# BEGIN ed25519-strict
# The Ed25519 refusals this verifier makes BEFORE it hands the signature to OTP. OTP's
# `:crypto.verify/5` answers true for a public key of small order (the identity, 01 00 .. 00, makes
# every R = [S]B verify for every message), so the refusals are written out here. Plain integer
# arithmetic; nothing here signs and no secret is ever an input.
#
#   {:error, :ed25519_non_canonical}  A or R is not a canonical encoding (y >= p; x = 0 with the
#                                     sign bit set), or S >= L
#   {:error, :ed25519_not_on_curve}   A or R is not a point
#   {:error, :ed25519_small_order}    A or R is of small order: [8]P is the identity (decided by
#                                     arithmetic, never by a list of encodings)
#   {:error, :ed25519_mixed_order}    A is not in the prime-order subgroup: [L]A is not the identity
#                                     (A is a multiple of B plus a point of small order). Such a
#                                     key is refused because implementations that reduce h modulo
#                                     L and ones that do not can otherwise disagree about the same
#                                     signature, depending on h mod 8
#
# verify_receipt.py makes the same refusals, sharing no code.
defmodule Ed25519Strict do
  import Bitwise

  @p (1 <<< 255) - 19
  @l (1 <<< 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493

  def refusal(<<r::binary-size(32), s::little-256>>, <<_::binary-size(32)>> = a) do
    with {:ok, r_point} <- decode(r),
         {:ok, a_point} <- decode(a) do
      cond do
        small_order?(a_point) -> {:error, :ed25519_small_order}
        small_order?(r_point) -> {:error, :ed25519_small_order}
        not prime_order?(a_point) -> {:error, :ed25519_mixed_order}
        s >= @l -> {:error, :ed25519_non_canonical}
        true -> :ok
      end
    end
  end

  # a signature that is not 64 bytes or a key that is not 32: refused, never raised
  def refusal(_signature, _public_key), do: {:error, :ed25519_non_canonical}

  def verify(signature, message, public_key) do
    refusal(signature, public_key) == :ok and
      :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519]) == true
  end

  defp decode(<<raw::little-256>>) do
    sign = raw >>> 255
    y = raw &&& (1 <<< 255) - 1

    if y >= @p do
      {:error, :ed25519_non_canonical}
    else
      u = mod(y * y - 1)
      v = mod(d() * y * y + 1)
      candidate = mod(u * pow(v, 3) * pow(u * pow(v, 7), div(@p - 5, 8)))

      root =
        cond do
          mod(v * candidate * candidate) == u -> candidate
          mod(v * candidate * candidate) == mod(-u) -> mod(candidate * pow(2, div(@p - 1, 4)))
          true -> nil
        end

      cond do
        root == nil -> {:error, :ed25519_not_on_curve}
        root == 0 and sign == 1 -> {:error, :ed25519_non_canonical}
        (root &&& 1) != sign -> {:ok, {mod(-root), y}}
        true -> {:ok, {root, y}}
      end
    end
  end

  defp small_order?(point), do: identity?(multiply(8, point))

  defp prime_order?(point), do: identity?(multiply(@l, point))

  # extended coordinates (X, Y, Z, T): the addition law of RFC 8032 section 5.1.4 without an
  # inversion; the identity is X = 0 and Y = Z
  defp identity?({x, y, z, _t}), do: x == 0 and y == z

  # [k]P by double-and-add from the top bit
  defp multiply(k, {x, y}) do
    point = {x, y, 1, mod(x * y)}

    k
    |> Integer.digits(2)
    |> Enum.reduce({0, 1, 1, 0}, fn
      0, acc -> add(acc, acc)
      1, acc -> add(add(acc, acc), point)
    end)
  end

  defp add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    a = mod((y1 - x1) * (y2 - x2))
    b = mod((y1 + x1) * (y2 + x2))
    c = mod(2 * d() * t1 * t2)
    dd = mod(2 * z1 * z2)
    {e, f, g, h} = {b - a, dd - c, dd + c, b + a}
    {mod(e * f), mod(g * h), mod(f * g), mod(e * h)}
  end

  @d Integer.mod(-121_665 * :binary.decode_unsigned(:crypto.mod_pow(121_666, @p - 2, @p)), @p)
  defp d, do: @d
  defp mod(a), do: rem(rem(a, @p) + @p, @p)
  defp pow(base, exp), do: :binary.decode_unsigned(:crypto.mod_pow(mod(base), exp, @p))
end

# END ed25519-strict

defmodule VerifyReceipt do
  @exit_verified 0
  @exit_invalid 1
  @exit_usage 2
  @exit_no_trust 5
  @exit_compromised 6
  # The log checkpoint's refusals (CHECKPOINTS.md) exit 5 too, under their own name: their codes are the
  # checkpoint checks' own (checkpoint_...), not codes of the issuing system's denial taxonomy, whose :trust codes
  # are the @exit_no_trust sites below, one to one.
  @exit_checkpoint_refused 5

  # Every exit-1 and exit-5 message this file writes ends with a line `verdict_code: <code>`, a code
  # of class :trust or :signature in the issuing system's denial taxonomy (the rows of its code
  # table with those two classes), but for the log checkpoint's refusals, whose codes are their own
  # (CHECKPOINTS.md). Exits 0, 2 and 6 print no such line. VERDICTS.md governs the exit
  # codes above.
  #
  # NO INPUT ENDS IN A STACK TRACE. A runtime that dies on an uncaught exception exits 1, which
  # VERDICTS.md reserves for "the receipt is bad", and writes no code line. So every named member of
  # the receipt and of the registry is read through `member/2`, which answers nil for anything that
  # is not an object; every input file is read through `read_json/1`, which refuses (exit 2, "cannot
  # read input") what verify_receipt.py refuses; and the last lines of this file turn an exception
  # nobody foresaw into exit 2 with a one-line message, never into 0 or 1.

  # THE READING RULE. One rule, stated in VERDICTS.md ("how an input is read") and applied by this
  # file, by verify_receipt.py and by the issuing system: what one of them reads, all three read,
  # to the same value; what one refuses, all three refuse. The three numbers below are that rule's.
  #
  # The largest input file that is read, in bytes: a larger file is refused (exit 2) before it is
  # parsed, and no more than this many bytes plus one are ever taken into memory. The deepest
  # nesting of arrays and objects that is read. The longest integer that is read, in characters,
  # its sign included (the issuing system's JSON reader refuses a longer one).
  @max_input_bytes 1_048_576
  @max_depth 64
  @max_integer_characters 1024

  @statuses ~w(example active retired compromised)
  # LogCheckpoint.flags/0's list (verify_receipt_checkpoint.exs), which a test compares with this one
  @checkpoint_flags ~w(--checkpoint --inclusion-proof --witness-policy --held-size --held-root --consistency-proof --key-transition --held-state)
  @envelope ~w(signature key_id signed_payload receipt_hash)
  @ignored ~w(public_key _note)
  @timestamp ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/

  def main(argv) do
    case parse(argv, %{}) do
      {:ok, opts} -> run(opts)
      {:error, message} -> fail(@exit_usage, message)
      {:no_registry} -> fail(@exit_no_trust, :no_registry)
    end
  end

  # Scanned explicitly rather than chunked, so `--receipt` with no value after it is a USAGE error
  # and never a silently dropped flag that changes the verdict.
  defp parse([flag], _opts) when flag in ["--receipt", "--registry"],
    do: {:error, "usage: #{flag} requires a value"}

  defp parse([flag, value | rest], opts) when flag in ["--receipt", "--registry"],
    do: parse(rest, Map.put(opts, flag, value))

  # the log checkpoint's flags (CHECKPOINTS.md): each takes a value, but --write-held-state
  defp parse(["--write-held-state" | rest], opts), do: parse(rest, Map.put(opts, "--write-held-state", true))

  defp parse([flag], _opts) when flag in @checkpoint_flags,
    do: {:error, "usage: #{flag} requires a value"}

  defp parse([flag, value | rest], opts) when flag in @checkpoint_flags,
    do: parse(rest, Map.put(opts, flag, value))

  defp parse([_ignored | rest], opts), do: parse(rest, opts)

  defp parse([], opts) do
    cond do
      is_nil(opts["--receipt"]) ->
        {:error, "usage: verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json"}

      # DEFAULT DISTRUST. Absent an independently supplied registry there is no basis to judge the
      # receipt, and inventing one from the bundle is the failure this scheme exists to remove.
      is_nil(opts["--registry"]) ->
        {:no_registry}

      true ->
        {:ok, opts}
    end
  end

  defp run(opts) do
    with {:ok, receipt} <- read_json(opts["--receipt"]),
         {:ok, registry} <- read_json(opts["--registry"]) do
      # the log checkpoint's inputs (CHECKPOINTS.md), read now; judged only once the receipt verified
      checkpoint =
        if Enum.any?(["--write-held-state" | @checkpoint_flags], &Map.has_key?(opts, &1)) do
          # the checks live beside this file and are compiled only when asked for (CHECKPOINTS.md)
          Code.require_file("verify_receipt_checkpoint.exs", __DIR__)

          try do
            LogCheckpoint.inputs(opts, &read_json_or_absent/1, &read_text/1)
          catch
            {:usage, message} -> fail(@exit_usage, "usage: " <> message)
          end
        end

      verify(receipt, registry, checkpoint)
    else
      {:error, message} -> fail(@exit_usage, message)
    end
  end

  defp read_json_or_absent(path) do
    if File.exists?(path), do: read_json(path), else: {:absent}
  end

  defp read_text(path) do
    case read_bounded(path) do
      {:ok, raw} -> {:ok, raw}
      {:error, :larger_than_the_bound} -> {:error, "cannot read input: #{path} is larger than #{@max_input_bytes} bytes"}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp verify(receipt, registry, checkpoint) when is_map(receipt) do
    payload = member(receipt, "signed_payload")
    signature = member(receipt, "signature")
    key_id = member(receipt, "key_id")

    if not (is_binary(payload) and is_binary(signature) and is_binary(key_id)) do
      fail(@exit_usage, "receipt must carry signed_payload, signature and key_id")
    end

    note_ignored_key(receipt)

    # ORDER IS VERDICTS.md's. Every trust question (exit 5) but the signing window precedes every
    # accusation (exit 1), because an accusation requires standing. The compromised verdict (6)
    # and the signing-window check come after the signature check, so only a receipt whose
    # signature verified reaches them.
    entry = trusted_entry(registry, key_id)
    # the entry's window BEFORE the receipt's instant (VERDICTS.md step 2's order; the Python
    # verifier's and the issuing system's)
    {valid_from, valid_to} = window(entry, key_id)
    signed = signed_object(payload)
    occurred = occurred_at(signed)

    check_hash(receipt, payload)
    check_siblings(receipt, signed)
    raw_key = check_signature(payload, signature, entry)
    _ = raw_key

    if member(entry, "status") == "compromised", do: compromised(key_id, entry)

    check_window(occurred, valid_from, valid_to, key_id, entry, signed)

    verified(key_id, entry, signed, log_checkpoint(receipt, checkpoint, key_id))
  end

  defp verify(_receipt, _registry, _checkpoint), do: fail(@exit_usage, "the receipt must be a JSON object")

  defp log_checkpoint(_receipt, nil, _key_id), do: []

  defp log_checkpoint(receipt, checkpoint, key_id) do
    case LogCheckpoint.check(receipt, checkpoint, &decode/1) do
      {:ok, lines, note} ->
        held = checkpoint.held

        if checkpoint.write and (held == nil or note.size > elem(held, 0)) do
          case File.write(checkpoint.state, LogCheckpoint.state_text(note)) do
            :ok ->
              lines ++ ["log checkpoint: the held-state file now holds size #{note.size}"]

            {:error, reason} ->
              fail(@exit_usage, "cannot write the held-state file #{checkpoint.state}: #{:file.format_error(reason)}")
          end
        else
          lines
        end

      {:usage, message} ->
        fail(@exit_usage, "usage: " <> message)

      {:refused, code, message} ->
        fail(
          @exit_checkpoint_refused,
          "TRUST NOT ESTABLISHED — the log checkpoint: #{message}.\n\n" <>
            "The receipt's signature is valid under key_id #{inspect(key_id)}. What is not established is the log's\n" <>
            "account of it: its inclusion under a checkpoint that the log key and the witnesses your\n" <>
            "policy names signed, not older than the tree size you hold.\n\nverdict_code: #{code}"
        )
    end
  end

  # The receipt may carry a public_key. It is NEVER used. A verifier that reads the key out of the
  # thing it is checking establishes nothing — it is the symmetric scheme wearing asymmetric
  # clothes.
  defp note_ignored_key(receipt) do
    if is_binary(member(receipt, "public_key")) do
      IO.puts("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")
    end
  end

  defp trusted_entry(registry, key_id) do
    # `entries` absent, null (`:json` renders it as the atom :null)
    # or not a list is a registry that gives no basis -- the same trust question as an absent
    # key, named by the same code.
    entries =
      case member(registry, "entries") do
        list when is_list(list) -> list
        _absent_null_or_other -> []
      end

    # A key_id that is the empty text names no key, whatever the registry holds under that text.
    entries =
      if key_id == "", do: [], else: Enum.filter(entries, &(member(&1, "key_id") == key_id))

    case entries do
      [] ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — the registry does not name key_id #{inspect(key_id)}.

        This is not a statement that the receipt is bad. It is a statement that the registry you
        supplied gives no basis to judge it. The verifier does not fall back to any other key.

        verdict_code: registry_missing_key
        """)

      # V-DUPKEY. Taking the first would let DOCUMENT ORDER select the verdict, inside a file whose
      # governing rule is that entries are never removed or rewritten.
      [_first, _second | _rest] ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — the registry names key_id #{inspect(key_id)} #{length(entries)} times.

        The registry is append-only: an entry is never removed and never rewritten, so one key_id
        names one key. Two entries mean the file is internally inconsistent, and picking either one
        would let the ORDER of a document decide the verdict.

        Detected on key_id only. Two entries sharing a public key under DIFFERENT key_ids is not
        this error.

        verdict_code: registry_duplicate_key
        """)

      [only] ->
        check_status(only, key_id)
        check_fingerprint(only, key_id)
        check_key_length(only, key_id)
        only
    end
  end

  # DEFAULT DENY. The registry defines exactly four statuses. A status this verifier cannot
  # interpret is a reason to refuse, never to pass.
  defp check_status(entry, key_id) do
    status = member(entry, "status")

    cond do
      is_binary(status) and status == "example" ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} is an example key, not a trust root.

        Example entries exist to demonstrate the registry's schema. They are generated from a
        published string, so their private half is not secret and anything they sign proves nothing.

        verdict_code: key_is_example
        """)

      is_binary(status) and status in @statuses ->
        :ok

      true ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} carries status #{inspect(status)}.

        The registry defines exactly four: example, active, retired, compromised. A status outside
        that set, or absent, is standing this verifier cannot interpret. It refuses rather than
        treating the unrecognised as the benign.

        verdict_code: key_status_not_active
        """)
    end
  end

  # The entry must hash to its own published fingerprint BEFORE its key, its window or a status of
  # active, retired or compromised is believed (an absent, undefined or example status is refused
  # first: VERDICTS.md, step 2). An entry failing its own integrity check may have been substituted.
  defp check_fingerprint(entry, key_id) do
    stated = member(entry, "public_key_fingerprint")

    with {:ok, raw} <- decode64(member(entry, "public_key")),
         true <- is_binary(stated),
         true <- Base.encode16(:crypto.hash(:sha256, raw), case: :lower) == stated do
      :ok
    else
      _otherwise ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} does not hash to its own published fingerprint.

        public_key_fingerprint is sha256 over the RAW key bytes, lowercase hex. This entry fails its
        own integrity check, so nothing it states — its status, its window, its key — can be relied
        on.

        verdict_code: key_fingerprint_mismatch
        """)
    end
  end

  # A public_key that is not 32 raw bytes is not an Ed25519 key.
  # A defect in the TRUST ROOT is a trust question (exit 5), never an accusation of the receipt.
  defp check_key_length(entry, key_id) do
    {:ok, raw} = decode64(member(entry, "public_key"))

    if byte_size(raw) != 32 do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} publishes a public_key of #{byte_size(raw)} bytes; an Ed25519 public key is 32.

      The entry hashes to its own fingerprint, so this is what the registry published: not a key
      this verifier can check a signature against. Nothing the receipt says is judged.

      verdict_code: key_public_key_malformed
      """)
    end
  end

  defp window(entry, key_id) do
    from = timestamp(member(entry, "valid_from"))
    to_raw = member(entry, "valid_to")

    if is_nil(from) do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} has no usable valid_from.

      Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly. A window that cannot be read cannot place a
      receipt inside or outside it.

      verdict_code: key_valid_from_unusable
      """)
    end

    # `:json.decode/1` renders JSON null as the ATOM :null, not nil. Both mean "no upper bound",
    # and conflating only one of them would read an open-ended window as an unreadable one.
    to =
      if to_raw in [nil, :null] do
        nil
      else
        case timestamp(to_raw) do
          nil ->
            fail(@exit_no_trust, """
            TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} has an unreadable valid_to.

            Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, or null for a key still signing.

            verdict_code: key_valid_to_unreadable
            """)

          value ->
            value
        end
      end

    {from, to}
  end

  # The signed bytes are read by the same rule as the input files. Bytes that are not read (not
  # JSON, an object repeating a member name, too deep, a number that is not read) carry no readable
  # occurred_at: a trust question, asked before anything accuses the receipt. Answers the object,
  # or `{:unread, why}`.
  defp signed_object(payload) do
    case decode(payload) do
      {:ok, decoded} when is_map(decoded) ->
        decoded

      {:ok, _not_an_object} ->
        {:unread, "they are not a JSON object"}

      {:error, why} ->
        {:unread, "they are not JSON that every implementation reads alike (#{why})"}
    end
  end

  defp occurred_at(signed) do
    value = timestamp(member(signed, "occurred_at"))

    if is_nil(value) do
      unread =
        case signed do
          {:unread, why} -> ": " <> why
          _object -> ""
        end

      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — the signed bytes carry no readable occurred_at#{unread}.

      occurred_at is the only signing time a receipt carries, and it is what the key's signing
      window is checked against. Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, and a real
      calendar instant; it is refused rather than coerced, so the implementations cannot drift.

      verdict_code: signed_occurred_at_unreadable
      """)
    end

    value
  end

  # Fixed width, zero padded, most significant field first, one literal UTC suffix. Within that
  # accepted set, and ONLY within it, byte order is chronological order — which is why the regex is
  # not decoration but the precondition that makes the comparison correct.
  #
  # The form alone is not enough: the text must also be a real instant of the proleptic Gregorian
  # calendar. Month 01 to 12, a day that month has in that year (year 0000 is a leap year), hour 00
  # to 23, minute and second 00 to 59; there is no leap second and no 24:00:00. `2026-02-30` has
  # the form, and comparing it as text would place it between two real days. The arithmetic is
  # written out, the same in verify_receipt.py, so no library decides.
  defp timestamp(value) when is_binary(value) do
    if Regex.match?(@timestamp, value) and calendar_instant?(value), do: value, else: nil
  end

  defp timestamp(_value), do: nil

  defp calendar_instant?(
         <<year::binary-size(4), ?-, month::binary-size(2), ?-, day::binary-size(2), ?T,
           hour::binary-size(2), ?:, minute::binary-size(2), ?:, second::binary-size(2), ?Z>>
       ) do
    [year, month, day, hour, minute, second] =
      Enum.map([year, month, day, hour, minute, second], &String.to_integer/1)

    leap? = rem(year, 4) == 0 and (rem(year, 100) != 0 or rem(year, 400) == 0)

    days =
      cond do
        month == 2 and leap? -> 29
        month == 2 -> 28
        month in [4, 6, 9, 11] -> 30
        month in [1, 3, 5, 7, 8, 10, 12] -> 31
        true -> 0
      end

    day >= 1 and day <= days and hour <= 23 and minute <= 59 and second <= 59
  end

  defp calendar_instant?(_value), do: false

  defp check_hash(receipt, payload) do
    case member(receipt, "receipt_hash") do
      hash when is_binary(hash) ->
        actual = :crypto.hash(:sha256, payload) |> Base.encode16(case: :lower)

        if actual != hash do
          fail(
            @exit_invalid,
            "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes.\n\nverdict_code: receipt_hash_mismatch"
          )
        end

      _absent ->
        fail(@exit_invalid, """
        SIGNATURE INVALID — the receipt carries no receipt_hash.

        A receipt states the digest of its own signed bytes. An absent field is not a check to be
        skipped; it is a receipt that declines to be held to anything.

        verdict_code: receipt_hash_missing
        """)
    end
  end

  # Any top-level field that also appears inside the signed bytes must agree with it. A reader takes
  # the visible field for part of the receipt, and the signature covers only the signed bytes.
  defp check_siblings(receipt, signed) when is_map(signed) do
    Enum.each(receipt, fn {key, value} ->
      cond do
        key in @envelope or key in @ignored -> :ok
        not Map.has_key?(signed, key) -> :ok
        tagged(value) == tagged(member(signed, key)) -> :ok
        true ->
          fail(@exit_invalid, """
          SIGNATURE INVALID — the receipt displays #{inspect(key)} as #{inspect(value)}, but the
          SIGNED bytes say #{inspect(member(signed, key))}.

          A reader takes the visible field for part of the receipt. The signature covers only the
          signed bytes, so a top-level field contradicting them is a claim no signature stands
          behind.

          verdict_code: displayed_field_mismatch
          """)
      end
    end)
  end

  defp check_siblings(_receipt, _signed), do: :ok

  # Type-tagged, so equality never merges an integer with a float or a boolean with 1. The canonical
  # encoding never merges those; a bare `==` in either language does, on exactly the values an
  # adversary would choose. A float is compared by its eight bytes, so `-0.0` displayed over a
  # signed `0.0` is a contradiction (`==` calls them equal).
  defp tagged(value) when is_boolean(value), do: {:bool, value}
  defp tagged(value) when is_integer(value), do: {:int, value}
  defp tagged(value) when is_float(value), do: {:float, <<value::float>>}
  defp tagged(value) when is_binary(value), do: {:str, value}
  defp tagged(value) when value in [nil, :null], do: {:null}
  defp tagged(value) when is_list(value), do: {:list, Enum.map(value, &tagged/1)}

  defp tagged(value) when is_map(value),
    do: {:object, value |> Enum.map(fn {k, v} -> {k, tagged(v)} end) |> Enum.sort()}

  defp tagged(value), do: {:other, inspect(value)}

  # A signature that does not decode or is not 64 raw bytes is
  # MALFORMED (the taxonomy's own word; the issuing system agrees). The
  # key's length is checked at the trust step (`check_key_length/2`), so the rescue below is a
  # belt for material this verifier did not foresee, never the path for a known shape.
  defp check_signature(payload, signature, entry) do
    raw_signature =
      case decode64(signature) do
        {:ok, raw} when byte_size(raw) == 64 -> raw
        _otherwise -> malformed_signature()
      end

    {:ok, raw_key} = decode64(member(entry, "public_key"))

    if Ed25519Strict.verify(raw_signature, payload, raw_key) do
      raw_key
    else
      fail(
        @exit_invalid,
        "SIGNATURE INVALID — the signature does not check out against the registry's public key.\n\nverdict_code: signature_invalid"
      )
    end
  rescue
    ErlangError -> malformed_signature()
  end

  defp malformed_signature do
    fail(@exit_invalid, "SIGNATURE INVALID — malformed signature or key material.\n\nverdict_code: signature_malformed")
  end

  # Half-open: valid_from <= occurred_at < valid_to. VERDICTS.md records why the published
  # registries settle that convention rather than taste.
  defp check_window(occurred, from, to, key_id, entry, signed) do
    outside = occurred < from or (not is_nil(to) and occurred >= to)

    if outside do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — the receipt says it was signed at #{member(signed, "occurred_at")}, outside
      key_id #{inspect(key_id)}'s signing window [#{member(entry, "valid_from")}, #{member(entry, "valid_to")}).

      A retired key's signatures survive its retirement; a signature dated after the window closed
      was never covered by that rule. The window is half-open, so an occurred_at equal to valid_to
      is outside it.

      Sound for honest history, advisory against a forger: occurred_at is asserted by the receipt,
      and an adversary holding the key can backdate it.

      verdict_code: signed_outside_key_validity
      """)
    end
  end

  defp decode64(value) when is_binary(value), do: Base.decode64(value)
  defp decode64(_value), do: :error

  defp verified(key_id, entry, signed, checkpoint_lines) do
    IO.puts("""
    VERIFIED — signature is valid under key_id #{inspect(key_id)} (status: #{member(entry, "status")}).

    A retired key verifies exactly like an active one WITHIN ITS SIGNING WINDOW. Rotation does not
    invalidate receipts already issued; only new signing stops.

    #{chain_note(signed)}
    """)

    Enum.each(checkpoint_lines, &IO.puts/1)

    System.halt(@exit_verified)
  end

  # A signature binds the receipt's position in its chain only when the signed bytes carry both
  # members. Nothing above requires either, so the note says which is absent.
  defp chain_note(signed) do
    case Enum.reject(["sequence", "previous_hash"], &Map.has_key?(signed, &1)) do
      [] ->
        "Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so a\n" <>
          "valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content."

      absent ->
        "Note: the signed bytes carry no #{Enum.join(absent, " and no ")}, so this signature does not " <>
          "bind the receipt's position in a chain."
    end
  end

  # 6 asserts the signature IS cryptographically valid, so it is never reached over a failed
  # verification. It sits after the receipt checks for that reason and not by accident.
  defp compromised(key_id, entry) do
    IO.puts("""
    KEY COMPROMISED — the signature is cryptographically valid under key_id #{inspect(key_id)}, but
    the registry marks that key compromised as of #{shown(member(entry, "status_changed_at"))}.

    WHAT THIS VERDICT CAN AND CANNOT ESTABLISH:

      * The signature checks out against the published key.
      * It does NOT establish that the issuer produced it. Anyone holding the compromised private
        key could have.
      * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on the
        signing time, which the receipt asserts about itself and an adversary holding that key can
        backdate.

    Sound for honest history, advisory against a forger. Closing the gap requires anchoring signing
    times outside the issuing system; that is named future work.

    Exit code 6 is PROVISIONAL, pending reconciliation with the VIRP vocabulary.
    """)

    System.halt(@exit_compromised)
  end

  defp read_json(path) do
    case read_bounded(path) do
      {:ok, raw} ->
        case decode(raw) do
          {:ok, value} -> {:ok, value}
          {:error, why} -> {:error, "cannot read input: #{path} is not readable JSON (#{why})"}
        end

      {:error, :larger_than_the_bound} ->
        {:error, "cannot read input: #{path} is larger than #{@max_input_bytes} bytes"}

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  # A bounded read: at most @max_input_bytes + 1 bytes are asked for, so a file larger than the
  # bound is never taken into memory whole.
  defp read_bounded(path) do
    with {:ok, file} <- File.open(path, [:read, :binary]) do
      read = IO.binread(file, @max_input_bytes + 1)
      File.close(file)

      case read do
        :eof -> {:ok, ""}
        {:error, reason} -> {:error, reason}
        raw when byte_size(raw) > @max_input_bytes -> {:error, :larger_than_the_bound}
        raw -> {:ok, raw}
      end
    end
  end

  # The JSON value in `raw`, or `{:error, why}`. Stricter than `:json.decode/1` in exactly the ways
  # verify_receipt.py and the issuing system are: an object that repeats a member name is refused,
  # at every depth, the names compared after their escapes are decoded (one JSON reader keeps the
  # first occurrence and another the last, so a repeated name is two documents in one), and so is
  # nesting deeper than @max_depth and an integer of more than @max_integer_characters characters.
  # A negative zero written with an exponent and no fraction (`-0e5`) is refused: `:json` drops
  # its sign (0.0) where verify_receipt.py's reader keeps it (-0.0).
  # What `:json` itself refuses (NaN, Infinity, a number beyond a double, an unpaired surrogate,
  # bytes that are not UTF-8, text after the value) is refused here too. The input files AND the
  # signed bytes are read through here: there is one rule and no exception to it.
  defp decode(raw) do
    cond do
      not is_binary(raw) ->
        {:error, "not text"}

      too_deep?(raw, 0) ->
        {:error, "nested more than #{@max_depth} levels deep"}

      negative_zero_exponent?(raw) ->
        {:error, "a negative zero written with an exponent and no fraction"}

      true ->
        decoders = %{
          object_push: fn key, value, acc -> [{key, value} | acc] end,
          object_finish: fn acc, old ->
            map = Map.new(acc)
            if map_size(map) != length(acc), do: throw(:repeated_member_name)
            {map, old}
          end,
          integer: fn text ->
            if byte_size(text) > @max_integer_characters, do: throw(:integer_too_long)
            :erlang.binary_to_integer(text)
          end
        }

        try do
          case :json.decode(raw, :ok, decoders) do
            {value, :ok, ""} -> {:ok, value}
            {_value, :ok, _rest} -> {:error, "text after the value"}
          end
        rescue
          _error -> {:error, "not valid JSON"}
        catch
          :repeated_member_name -> {:error, "an object repeats a member name"}
          :integer_too_long ->
            {:error, "an integer of more than #{@max_integer_characters} characters"}
        end
    end
  end

  # Nesting depth of arrays and objects, outside strings. A document that is not JSON may be
  # counted wrongly here; it is then refused by the decoder all the same.
  defp too_deep?(<<>>, _depth), do: false
  defp too_deep?(<<?", rest::binary>>, depth), do: rest |> skip_string() |> too_deep?(depth)
  defp too_deep?(<<char, _rest::binary>>, depth) when char in [?[, ?{] and depth >= @max_depth, do: true
  defp too_deep?(<<char, rest::binary>>, depth) when char in [?[, ?{], do: too_deep?(rest, depth + 1)
  defp too_deep?(<<char, rest::binary>>, depth) when char in [?], ?}], do: too_deep?(rest, depth - 1)
  defp too_deep?(<<_char, rest::binary>>, depth), do: too_deep?(rest, depth)

  defp skip_string(<<>>), do: <<>>
  defp skip_string(<<?\\, _escaped, rest::binary>>), do: skip_string(rest)
  defp skip_string(<<?", rest::binary>>), do: rest
  defp skip_string(<<_char, rest::binary>>), do: skip_string(rest)

  # A negative zero written with an exponent and no fraction (`-0e5`, `-0E-9`), outside strings.
  # `:json` reads it as 0.0: the sign is gone before any decoder callback sees the text (a `float`
  # callback is handed "0.0e5"), so it cannot be kept and is looked for here, before the decoder.
  # verify_receipt.py's reader reads the same text as -0.0. One pass. In JSON a minus sign outside
  # a string begins a number or an exponent, and `-0` followed by `e` can only begin a number.
  defp negative_zero_exponent?(<<>>), do: false

  defp negative_zero_exponent?(<<?", rest::binary>>),
    do: rest |> skip_string() |> negative_zero_exponent?()

  defp negative_zero_exponent?(<<"-0", e, _rest::binary>>) when e in [?e, ?E], do: true
  defp negative_zero_exponent?(<<_char, rest::binary>>), do: negative_zero_exponent?(rest)

  # `map[name]` when `map` is a JSON object, and nil for anything else (a list, a string, a number,
  # null, a missing member). Every read of a named member of the receipt, the registry, a registry
  # entry or the signed bytes goes through here, so a value of the wrong shape is an absent value
  # and meets the same typed refusal an absent value meets. (The displayed-field check walks the
  # receipt's own members; `chain_note/1` asks only whether the signed bytes, already known to be
  # an object, carry sequence and previous_hash.)
  defp member(map, name) when is_map(map), do: Map.get(map, name)
  defp member(_not_an_object, _name), do: nil

  # A value for a message: itself when it is text, otherwise a fixed phrase.
  defp shown(value) when is_binary(value), do: value
  defp shown(_value), do: "an unstated instant"

  defp fail(_code, :no_registry) do
    IO.puts(:stderr, """
    TRUST NOT ESTABLISHED — no --registry was supplied.

    This verifier refuses to check a signature against key material that arrived with the receipt.
    A key obtained from the same download as the evidence proves nothing: whoever produced the
    bundle chose both halves.

    Supply a registry you obtained INDEPENDENTLY of this receipt:

        elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json

    The registry is published in the public repository, where every append is a dated commit you
    can walk and tampering is detectable against any older clone.

    A second channel — a Zenodo deposit carrying a DOI — is INTENDED and NOT YET LIVE. When it
    exists you will be able to cross-check one against the other, and disagreement between them
    will itself be an alarm. Until then there is one channel, and this tool says so rather than
    implying a check you cannot perform.

    verdict_code: registry_not_supplied
    """)

    System.halt(@exit_no_trust)
  end

  defp fail(code, message) do
    IO.puts(:stderr, message)
    System.halt(code)
  end
end

# Last resort, for an exception no check above foresaw. Exit 2 ("nothing was measured"), because
# neither 0 nor 1 may be said of an input this file could not evaluate, and no stack trace: the
# type of the exception is named so the defect can be reported.
try do
  VerifyReceipt.main(System.argv())
rescue
  error ->
    IO.puts(
      :stderr,
      "internal error (#{inspect(error.__struct__)}): this verifier could not evaluate the input; nothing was measured."
    )

    System.halt(2)
catch
  kind, _reason ->
    IO.puts(
      :stderr,
      "internal error (#{kind}): this verifier could not evaluate the input; nothing was measured."
    )

    System.halt(2)
end
