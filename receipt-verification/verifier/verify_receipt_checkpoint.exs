#!/usr/bin/env elixir
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
#
# verify_receipt_checkpoint.exs -- the log checkpoint checks of verify_receipt.exs, loaded by it (Code.require_file)
# only when a checkpoint flag is given, so a receipt checked without one compiles none of this. Not run on its own.
#
# LOG CHECKPOINTS (CHECKPOINTS.md, beside this file). Run only when --checkpoint is given, and only after
# the receipt itself VERIFIED. The same three checks as verify_receipt.py's section of that name, written
# again from CHECKPOINTS.md and C2SP/RFC 9162, sharing no code with it:
#
#   (1) INCLUSION. The relying party's witness policy names the log key and the witnesses. The checkpoint
#       (a C2SP signed note) carries a verifying line of every log key, under the note's own origin, and
#       Ed25519 (type 0x04) witness cosignatures meeting the policy's quorum; the receipt's leaf is
#       included under its SHA-256 root by the RFC 9162 inclusion proof given.
#   (2) CONSISTENCY and (3) NOT OLDER THAN THE HELD SIZE. A checkpoint smaller than the tree size the
#       relying party holds is refused (checkpoint_older_than_held); one of that size with another root
#       is refused (checkpoint_split_view_at_held_size); a larger one needs an RFC 9162 consistency
#       proof from the held tree that verifies.
#
# A key change of the log is followed only through the log's signed key-transition record, endorsed
# by an old key the policy names. Every refusal exits 5. An ML-DSA-44 (type 0x06) witness key is
# refused by name: this file computes Ed25519 only.
defmodule LogCheckpoint do
  import Bitwise

  @flags ~w(--checkpoint --inclusion-proof --witness-policy --held-size --held-root --consistency-proof --key-transition --held-state)
  @leaf_tag "requisition.lab.log.leaf.v1\n"
  @transition_type "requisition.lab.log.key_transition.v0"
  @decimal ~r/\A(0|[1-9][0-9]{0,17})\z/
  @threshold ~r/\A[+-]?[0-9]+\z/
  @hex4 ~r/\A[0-9a-f]{8}\z/

  def flags, do: @flags

  # a refusal is {:refused, code, message}; a usage error {:usage, message}
  defp refuse(code, message), do: throw({:refused, code, message})
  defp usage(message), do: throw({:usage, message})

  defp b64(value) when is_binary(value) do
    case Base.decode64(value) do
      {:ok, raw} -> if Base.encode64(raw) == value, do: raw, else: nil
      :error -> nil
    end
  end

  defp b64(_value), do: nil

  defp h(data), do: :crypto.hash(:sha256, data)
  defp node_hash(left, right), do: h(<<1>> <> left <> right)

  def key_id(name, type, public), do: binary_part(h(name <> "\n" <> type <> public), 0, 4)

  def vkey(text) do
    with [name, hex, encoded] when name != "" <- String.split(text, "+", parts: 3),
         true <- Regex.match?(@hex4, hex),
         blob when is_binary(blob) <- b64(encoded),
         {:ok, kind} <- kind(blob),
         <<type::binary-size(1), public::binary>> = blob,
         {:ok, id} = Base.decode16(hex, case: :lower),
         true <- key_id(name, type, public) == id do
      %{name: name, id: id, kind: kind, public: public}
    else
      _ -> nil
    end
  end

  defp kind(<<1, _::binary-size(32)>>), do: {:ok, :ed25519}
  defp kind(<<4, _::binary-size(32)>>), do: {:ok, :cosig_ed25519}
  defp kind(<<6, _::binary-size(1312)>>), do: {:ok, :cosig_mldsa44}
  defp kind(_blob), do: :error

  # ------------------------------------------------------------------ the policy

  def policy(raw) do
    if not String.valid?(raw), do: usage("the witness policy is not UTF-8")

    acc =
      raw
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.reduce(%{logs: [], witnesses: [], components: %{}, quorum: nil}, fn {line, n}, acc ->
        line |> String.split("#", parts: 2) |> hd() |> String.split() |> policy_line(n, acc)
      end)

    cond do
      acc.quorum == nil -> usage("the witness policy has no quorum line")
      acc.quorum != "none" and not Map.has_key?(acc.components, acc.quorum) -> usage("the witness policy's quorum #{inspect(acc.quorum)} is not defined")
      acc.logs == [] -> usage("the witness policy has no log line: the log key is the relying party's to name")
      true -> :ok
    end

    case for(%{kind: :cosig_mldsa44, name: name} <- acc.witnesses, do: name) do
      [] ->
        acc

      names ->
        refuse(
          "checkpoint_algorithm_unsupported",
          "the witness policy names ML-DSA-44 (type 0x06) witness key(s) #{Enum.join(Enum.sort(names), ", ")}; this verifier computes Ed25519 only"
        )
    end
  end

  defp policy_line([], _n, acc), do: acc

  defp policy_line(["log", text | _], n, acc) do
    case vkey(text) do
      %{kind: :ed25519} = key -> %{acc | logs: acc.logs ++ [key]}
      _ -> usage("the witness policy, line #{n}: not an Ed25519 log vkey")
    end
  end

  defp policy_line(["witness", name, text | _], n, acc) do
    if Map.has_key?(acc.components, name), do: usage("the witness policy, line #{n}: the name #{inspect(name)} is taken")

    case vkey(text) do
      %{kind: kind} = key when kind in [:cosig_ed25519, :cosig_mldsa44] ->
        %{acc | components: Map.put(acc.components, name, {:witness, key}), witnesses: acc.witnesses ++ [key]}

      _ ->
        usage("the witness policy, line #{n}: not a witness cosigner vkey")
    end
  end

  defp policy_line(["group", name, threshold | members], n, acc) when members != [] do
    if Map.has_key?(acc.components, name), do: usage("the witness policy, line #{n}: the name #{inspect(name)} is taken")

    count =
      cond do
        threshold == "any" -> 1
        threshold == "all" -> length(members)
        Regex.match?(@threshold, threshold) and String.to_integer(threshold) in 1..length(members)//1 -> String.to_integer(threshold)
        true -> usage("the witness policy, line #{n}: the threshold #{inspect(threshold)}")
      end

    if not Enum.all?(members, &Map.has_key?(acc.components, &1)),
      do: usage("the witness policy, line #{n}: a member is not defined above it")

    %{acc | components: Map.put(acc.components, name, {:group, count, members})}
  end

  defp policy_line(["quorum", name | _], n, acc) do
    if acc.quorum != nil, do: usage("the witness policy, line #{n}: a second quorum line")
    %{acc | quorum: name}
  end

  defp policy_line(_fields, n, _acc), do: usage("the witness policy, line #{n}: not a policy line")

  # ------------------------------------------------------------------ the note

  def note(raw) do
    malformed = fn why -> refuse("checkpoint_note_malformed", why) end
    if not String.valid?(raw), do: malformed.("the checkpoint is not UTF-8")

    if String.match?(raw, ~r/[\x00-\x09\x0b-\x1f\x7f]/),
      do: malformed.("the checkpoint carries a control character")

    split =
      case :binary.matches(raw, "\n\n") do
        [] -> nil
        found -> found |> List.last() |> elem(0)
      end

    if split == nil or not String.ends_with?(raw, "\n"),
      do: malformed.("no blank line between the text and the signatures")

    text = binary_part(raw, 0, split + 1)
    block = binary_part(raw, split + 2, byte_size(raw) - split - 2)
    lines = block |> String.split("\n") |> Enum.drop(-1)
    if lines == [] or length(lines) > 16, do: malformed.("#{length(lines)} signature lines (1 to 16)")

    signatures =
      Enum.reduce(lines, [], fn line, acc ->
        {name, signature} =
          with "— " <> rest <- line,
               [name, encoded] when name != "" <- String.split(rest, " "),
               raw_signature when is_binary(raw_signature) and byte_size(raw_signature) >= 5 <- b64(encoded) do
            {name, raw_signature}
          else
            _ -> malformed.("a signature line is not '— <name> <base64>'")
          end

        if Enum.any?(acc, fn {n, s} -> n == name and binary_part(s, 0, 4) == binary_part(signature, 0, 4) end),
          do: malformed.("two signature lines of one name and key")

        acc ++ [{name, signature}]
      end)

    rows = text |> binary_part(0, byte_size(text) - 1) |> String.split("\n")

    if length(rows) < 3 or "" in rows or not Regex.match?(@decimal, Enum.at(rows, 1)),
      do: malformed.("the text is not origin, decimal size, root")

    root = b64(Enum.at(rows, 2))
    if not (is_binary(root) and byte_size(root) == 32), do: malformed.("the root line is not a base64 SHA-256 hash")

    %{text: text, origin: hd(rows), size: String.to_integer(Enum.at(rows, 1)), root: root, signatures: signatures}
  end

  # ------------------------------------------------------------------ the key transition

  def transition(record, origin, logs, decode) do
    unendorsed = fn why -> refuse("checkpoint_transition_unendorsed", why) end

    {meta, previous, new, endorsement, size, root, point} =
      with %{"signed_payload" => payload} when is_binary(payload) <- record,
           {:ok, %{"receipt_type" => @transition_type, "metadata" => %{} = meta}} <- decode.(payload),
           ^origin <- meta["origin"],
           previous when is_binary(previous) <- b64(meta["previous_public_key"]),
           new when is_binary(new) and byte_size(new) == 32 <- b64(meta["new_public_key"]),
           endorsement when is_binary(endorsement) <- b64(meta["endorsement"]),
           size when is_integer(size) and size >= 0 <- meta["previous_checkpoint_size"],
           root when is_binary(root) <- meta["previous_checkpoint_root_sha256"],
           point when is_binary(point) and byte_size(point) == 32 <- b64(root) do
        {meta, previous, new, endorsement, size, root, point}
      else
        _ -> unendorsed.("the key-transition record does not name this log's origin, both keys and an endorsement")
      end

    _ = meta
    old = Enum.find(logs, &(&1.public == previous and &1.name == origin))

    message =
      <<0>> <> "#{@transition_type}\n#{origin}\n#{size}\n#{root}\n" <> Base.encode64(new) <> "\n"

    if old == nil or not Ed25519Strict.verify(endorsement, message, previous),
      do: unendorsed.("the key change is not endorsed by a log key the witness policy names")

    {old, %{name: origin, id: key_id(origin, <<1>>, new), kind: :ed25519, public: new, size: size, root: point}}
  end

  # ------------------------------------------------------------------ the cosigned note

  defp cosignature_ok?(key, text, <<_id::binary-size(4), time::64, signature::binary-size(64)>>)
       when time <= (1 <<< 63) - 1,
       do: Ed25519Strict.verify(signature, "cosignature/v1\ntime #{time}\n" <> text, key.public)

  defp cosignature_ok?(_key, _text, _raw), do: false

  defp satisfied?(policy, name, signers) do
    case policy.components[name] do
      {:witness, w} -> MapSet.member?(signers, {w.name, w.id})
      {:group, count, members} -> Enum.count(members, &satisfied?(policy, &1, signers)) >= count
    end
  end

  def cosigned(policy, note, logs) do
    keys = logs ++ policy.witnesses

    verified =
      Enum.reduce(note.signatures, [], fn {name, raw}, acc ->
        case Enum.find(keys, &(&1.name == name and &1.id == binary_part(raw, 0, 4))) do
          nil ->
            acc

          key ->
            <<_::binary-size(4), rest::binary>> = raw

            ok =
              if key.kind == :ed25519,
                do: Ed25519Strict.verify(rest, note.text, key.public),
                else: cosignature_ok?(key, note.text, raw)

            if not ok,
              do: refuse("checkpoint_signature_invalid", "the line of #{name} (key #{Base.encode16(binary_part(raw, 0, 4), case: :lower)}) does not verify")

            acc ++ [key]
        end
      end)

    if verified == [], do: refuse("checkpoint_no_trusted_signature", "no line of the checkpoint is by a key the witness policy names")

    if Enum.any?(logs, &(&1.name != note.origin)),
      do: refuse("checkpoint_origin_mismatch", "the checkpoint is for origin #{inspect(note.origin)}, not the log the witness policy names")

    if Enum.any?(logs, &(&1 not in verified)),
      do: refuse("checkpoint_no_trusted_signature", "the log key the witness policy names did not sign the checkpoint")

    cosigners = Enum.filter(verified, &(&1.kind != :ed25519))

    if policy.quorum != "none" and
         not satisfied?(policy, policy.quorum, MapSet.new(cosigners, &{&1.name, &1.id})) do
      names = if cosigners == [], do: "no witness", else: Enum.map_join(cosigners, ", ", & &1.name)
      refuse("checkpoint_quorum_not_met", "the witness quorum #{inspect(policy.quorum)} is not met; cosigned by: #{names}")
    end

    cosigners
  end

  # ------------------------------------------------------------------ the leaf and the proofs

  def leaf(receipt) do
    co =
      case Map.get(receipt, "cosignature") do
        %{} = envelope -> Map.get(envelope, "signature")
        other -> other
      end

    signature = b64(receipt["signature"])
    cosignature = if co == nil, do: <<>>, else: b64(co)

    if signature == nil or cosignature == nil or byte_size(signature) >= 65_536 or byte_size(cosignature) >= 65_536,
      do: refuse("checkpoint_leaf_malformed", "the receipt's signature or co-signature is not canonical base64 under 65,536 bytes")

    payload = receipt["signed_payload"]

    @leaf_tag <>
      <<byte_size(payload)::32>> <>
      payload <> <<byte_size(signature)::16>> <> signature <> <<byte_size(cosignature)::16>> <> cosignature
  end

  defp proof(document, sizes) do
    if not (is_map(document) and Map.get(document, "hash") in [nil, "sha256"]),
      do: refuse("checkpoint_proof_malformed", "a proof that is not an object over the SHA-256 tree")

    for {name, value} <- sizes do
      found = Map.get(document, name)

      if not (is_integer(found) and found == value),
        do: refuse("checkpoint_proof_malformed", "the proof's #{name} is #{inspect(found)}, not #{value}")
    end

    hashes = Map.get(document, "proof")
    out = if is_list(hashes), do: Enum.map(hashes, &b64/1), else: nil

    if out == nil or Enum.any?(out, &(not (is_binary(&1) and byte_size(&1) == 32))),
      do: refuse("checkpoint_proof_malformed", "the proof is not a list of base64 SHA-256 hashes")

    out
  end

  # RFC 9162 section 2.1.3.2
  def verify_inclusion(leaf_hash, index, size, proof, root) do
    if index < 0 or index >= size do
      false
    else
      result =
        Enum.reduce_while(proof, {index, size - 1, leaf_hash}, fn p, {fn_, sn, r} ->
          cond do
            sn == 0 ->
              {:halt, :fail}

            (fn_ &&& 1) == 1 or fn_ == sn ->
              {fn2, sn2} = shift_while_even(fn_, sn)
              {:cont, {fn2 >>> 1, sn2 >>> 1, node_hash(p, r)}}

            true ->
              {:cont, {fn_ >>> 1, sn >>> 1, node_hash(r, p)}}
          end
        end)

      match?({_, 0, ^root}, result)
    end
  end

  defp shift_while_even(fn_, sn) when (fn_ &&& 1) == 0 and fn_ != 0, do: shift_while_even(fn_ >>> 1, sn >>> 1)
  defp shift_while_even(fn_, sn), do: {fn_, sn}

  # RFC 9162 section 2.1.4.2, for 0 < first < second
  def verify_consistency(first, second, proof, first_root, second_root) do
    if not (first > 0 and first < second and proof != []) do
      false
    else
      path = if (first &&& first - 1) == 0, do: [first_root | proof], else: proof
      {fn0, sn0} = shift_while_odd(first - 1, second - 1)
      [start | rest] = path

      result =
        Enum.reduce_while(rest, {fn0, sn0, start, start}, fn c, {fn_, sn, fr, sr} ->
          cond do
            sn == 0 ->
              {:halt, :fail}

            (fn_ &&& 1) == 1 or fn_ == sn ->
              {fn2, sn2} = shift_while_even(fn_, sn)
              {:cont, {fn2 >>> 1, sn2 >>> 1, node_hash(c, fr), node_hash(c, sr)}}

            true ->
              {:cont, {fn_ >>> 1, sn >>> 1, fr, node_hash(sr, c)}}
          end
        end)

      match?({_, 0, ^first_root, ^second_root}, result)
    end
  end

  defp shift_while_odd(fn_, sn) when (fn_ &&& 1) == 1, do: shift_while_odd(fn_ >>> 1, sn >>> 1)
  defp shift_while_odd(fn_, sn), do: {fn_, sn}

  # ------------------------------------------------------------------ the inputs and the checks

  @doc "The held {size, root, origin or nil} the relying party gives, or nil."
  def held(opts, read_json) do
    {size, root_text, origin} =
      cond do
        Map.has_key?(opts, "--held-state") ->
          if Map.has_key?(opts, "--held-size") or Map.has_key?(opts, "--held-root"),
            do: usage("--held-state and --held-size/--held-root are two sources of one thing; give one")

          case read_json.(opts["--held-state"]) do
            {:absent} ->
              throw({:held, nil})

            {:ok, %{"origin" => origin, "size" => size, "root" => root}} when is_binary(origin) and is_integer(size) ->
              {Integer.to_string(size), root, origin}

            {:ok, _other} ->
              usage("the held-state file is not {\"origin\", \"root\", \"size\"}")

            {:error, message} ->
              usage("the held-state file is not readable: #{message}")
          end

        Map.has_key?(opts, "--held-size") or Map.has_key?(opts, "--held-root") ->
          if not (Map.has_key?(opts, "--held-size") and Map.has_key?(opts, "--held-root")),
            do: usage("--held-size and --held-root go together")

          {opts["--held-size"], opts["--held-root"], nil}

        true ->
          throw({:held, nil})
      end

    root = b64(root_text)

    if not (Regex.match?(@decimal, size) and String.to_integer(size) >= 1 and is_binary(root) and byte_size(root) == 32),
      do: usage("a held size is a decimal of at least 1, and a held root a base64 SHA-256 hash")

    {String.to_integer(size), root, origin}
  catch
    {:held, nil} -> nil
  end

  @doc "nil without checkpoint flags; else the inputs, read; throws {:usage, message}."
  def inputs(opts, read_json, read_bytes) do
    if not Enum.any?(@flags ++ ["--write-held-state"], &Map.has_key?(opts, &1)) do
      nil
    else
      if not Enum.all?(~w(--checkpoint --inclusion-proof --witness-policy), &Map.has_key?(opts, &1)),
        do: usage("--checkpoint, --inclusion-proof and --witness-policy go together")

      held = held(opts, read_json)

      if Map.has_key?(opts, "--consistency-proof") and held == nil and not Map.has_key?(opts, "--held-state"),
        do: usage("--consistency-proof proves consistency with a held size: give one")

      if Map.has_key?(opts, "--write-held-state") and not Map.has_key?(opts, "--held-state"),
        do: usage("--write-held-state writes the file --held-state names")

      json = fn flag ->
        case read_json.(opts[flag]) do
          {:ok, value} -> value
          {:absent} -> usage("cannot read input: #{opts[flag]} does not exist")
          {:error, message} -> usage(message)
        end
      end

      bytes = fn flag ->
        case read_bytes.(opts[flag]) do
          {:ok, raw} -> raw
          {:error, message} -> usage(message)
        end
      end

      %{
        held: held,
        checkpoint: bytes.("--checkpoint"),
        policy: bytes.("--witness-policy"),
        inclusion: json.("--inclusion-proof"),
        consistency: Map.has_key?(opts, "--consistency-proof") && json.("--consistency-proof"),
        transition: Map.has_key?(opts, "--key-transition") && json.("--key-transition"),
        state: opts["--held-state"],
        write: Map.has_key?(opts, "--write-held-state")
      }
    end
  end

  @doc "The checks: {:ok, lines, note} or {:refused, code, message} or {:usage, message}."
  def check(receipt, i, decode) do
    policy = policy(i.policy)
    note = note(i.checkpoint)

    {logs, transition_lines, point} =
      if i.transition do
        {old, new} = transition(i.transition, note.origin, policy.logs, decode)

        {Enum.map(policy.logs, &if(&1 == old, do: new, else: &1)),
         ["key transition at size #{new.size}: the log key #{hex(old.id)} endorsed the key #{hex(new.id)}"], new}
      else
        {policy.logs, [], nil}
      end

    cosigners = cosigned(policy, note, logs)

    witnesses =
      if cosigners == [],
        do: "no witness",
        else: Enum.map_join(cosigners, ", ", &"#{&1.name} (key #{hex(&1.id)})")

    lines =
      ["origin #{note.origin}, size #{note.size}, root sha256 #{Base.encode64(note.root)}"] ++
        transition_lines ++
        Enum.map(logs, &"signed by the log key #{&1.name}+#{hex(&1.id)}") ++
        ["witness quorum #{policy.quorum} met; cosigned by #{witnesses}"]

    document = i.inclusion
    index = if is_map(document), do: Map.get(document, "leaf_index")
    if not is_integer(index), do: refuse("checkpoint_proof_malformed", "the inclusion proof has no integer leaf_index")
    path = proof(document, [{"tree_size", note.size}])
    leaf_hash = h(<<0>> <> leaf(receipt))
    stated = Map.get(document, "leaf_hash")

    if stated != nil and b64(stated) != leaf_hash,
      do: refuse("checkpoint_inclusion_invalid", "the proof's leaf_hash is not this receipt's leaf")

    if not verify_inclusion(leaf_hash, index, note.size, path, note.root),
      do: refuse("checkpoint_inclusion_invalid", "the receipt is not leaf #{index} of the tree of size #{note.size}")

    lines = lines ++ ["the receipt is leaf #{index} of #{note.size} (RFC 9162 inclusion proof, SHA-256)"]

    {held, point_lines} = after_transition(point, note, i.held)
    lines = lines ++ point_lines

    held_line =
      case held do
        {_size, _root, origin} when origin != nil and origin != note.origin ->
          usage("the held-state file is for the log #{inspect(origin)}, not #{inspect(note.origin)}")

        nil ->
          start = if i.state, do: "the held-state file is absent: nothing held", else: "no held size given"
          "#{start}: a checkpoint older than a size the relying party holds is not refused"

        {m, _root, _origin} when note.size < m ->
          refuse("checkpoint_older_than_held", "the checkpoint's size #{note.size} is below the held size #{m}")

        {m, root, _origin} when note.size == m ->
          if note.root != root,
            do: refuse("checkpoint_split_view_at_held_size", "size #{m}: the checkpoint's root is not the held root")

          "not older than the held size #{m}: the same root"

        {m, root, _origin} ->
          if i.consistency in [false, nil],
            do: refuse("checkpoint_consistency_unproven", "the checkpoint is larger than the held size #{m} and no consistency proof is given")

          path = proof(i.consistency, [{"old", m}, {"new", note.size}])

          if not verify_consistency(m, note.size, path, root, note.root),
            do: refuse("checkpoint_consistency_invalid", "the tree of size #{note.size} does not extend the held tree of size #{m}")

          "not older than the held size #{m}: consistent with it (RFC 9162 consistency proof)"
      end

    lines = lines ++ [held_line, "all checks held: inclusion, witness quorum, not older than the held size"]
    {:ok, Enum.map(lines, &("log checkpoint: " <> &1)), note}
  catch
    {:refused, code, message} -> {:refused, code, message}
    {:usage, message} -> {:usage, message}
  end

  # the new key signs only checkpoints at or after the point the old key endorsed it at, and at that point the endorsed
  # root; a held tree older than that point is checked from it. The held-state file's log is compared first.
  defp after_transition(_point, note, {_size, _root, origin}) when origin != nil and origin != note.origin,
    do: usage("the held-state file is for the log #{inspect(origin)}, not #{inspect(note.origin)}")

  defp after_transition(nil, _note, held), do: {held, []}

  defp after_transition(point, note, held) do
    if note.size < point.size,
      do: refuse("checkpoint_before_transition", "the checkpoint's size #{note.size} is below the key transition's size #{point.size}")

    if note.size == point.size and note.root != point.root,
      do: refuse("checkpoint_transition_root_mismatch", "size #{point.size}: the checkpoint's root is not the root the key transition names")

    case held do
      {m, _root, origin} when m < point.size ->
        {{point.size, point.root, origin},
         ["held size #{m} is below the key transition at size #{point.size}: checked from the transition point"]}

      _ ->
        {held, []}
    end
  end

  @doc "The held-state file's text for a checkpoint (the same bytes as verify_receipt.py's)."
  def state_text(note) do
    ~s({"origin": #{json_string(note.origin)}, "root": "#{Base.encode64(note.root)}", "size": #{note.size}}\n)
  end

  # json.dumps's default: ASCII only, "\uXXXX" escapes (surrogate pairs above the BMP)
  defp json_string(text) do
    body =
      text
      |> String.to_charlist()
      |> Enum.map_join(fn
        ?" -> "\\\""
        ?\\ -> "\\\\"
        ?\n -> "\\n"
        ?\r -> "\\r"
        ?\t -> "\\t"
        ?\b -> "\\b"
        ?\f -> "\\f"
        c when c < 0x20 or (c > 0x7F and c < 0x10000) -> "\\u" <> pad4(c)
        c when c >= 0x10000 ->
          v = c - 0x10000
          "\\u" <> pad4(0xD800 + (v >>> 10)) <> "\\u" <> pad4(0xDC00 + (v &&& 0x3FF))
        c -> <<c>>
      end)

    "\"" <> body <> "\""
  end

  defp pad4(c), do: c |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
end
