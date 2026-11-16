# Checking a lab record against a log checkpoint

`verify_receipt.py` and `verify_receipt.exs` check one record: its signature, under a key you supplied. (The Elixir
checks are in `verify_receipt_checkpoint.exs`, beside it, which it loads only when a checkpoint flag is given.) With the
flags below they also check what the transparency log of the evaluation environment says of that record. The log,
its checkpoints and its witnesses exist in the evaluation environment only. `bin/lab-verify` (Requisition's lab
record checker) and requisition-aws's `bin/verify_offline.py` take the same flags and hand them to
`verify_receipt.py`.

## What is checked

The checks run only after the record's own signature verified. In this order:

1. **Inclusion under a checkpoint the log key signed and the evaluation environment's witnesses cosigned.** The
   checkpoint is a C2SP signed note (origin, tree size, base64 SHA-256 root). Your policy file names the log's
   Ed25519 key and the keys of the witnesses of the evaluation environment you rely on. The checkpoint must carry a
   valid line of every log key, under the checkpoint's own origin, and its witness cosignatures (C2SP
   tlog-cosignature, Ed25519, type 0x04) must meet your quorum, in the evaluation environment. A line of a key your
   policy does not name is ignored, and a line of a key it names that does not verify refuses the checkpoint. The
   record's leaf must then be included under the checkpoint's root by the RFC 9162 inclusion proof given. The leaf
   is `"requisition.lab.log.leaf.v1\n" || u32be(|P|) || P || u16be(|S|) || S || u16be(|C|) || C`, where P is the
   signed bytes, S the signature and C the co-signature (empty when there is none). Leaf and node hashes are
   RFC 9162's, with SHA-256.
2. **Consistency with the tree you hold.** If the checkpoint is larger than the tree size you hold, the RFC 9162
   consistency proof given must show that the checkpoint's tree extends your tree (your size and root).
3. **Not older than the tree you hold.** A checkpoint smaller than the tree size you hold is refused. One of the same
   size with a different root is refused too.

What a pass shows: the record is in the log's tree at the checkpoint's size, and that tree is an append-only
extension of the tree you hold. Nothing more. In particular a pass does not show:

- that no larger checkpoint exists, or that the checkpoint is the log's newest;
- that the act the record describes ran, or ran once;
- anything about any record other than this one.

## Who can cheat, and what catches it

A log operator can show different histories ("forks") to different parties. A consistency proof covers only the two
trees it connects: the one you hold and the checkpoint given. On its own it cannot show that someone else was shown a
different tree. In the evaluation environment, witness cosignatures are what make a fork detectable: each witness
cosigns only checkpoints consistent with what it has already cosigned, so a fork shown to you has to be cosigned by
your witnesses on a history they have not cosigned elsewhere. In the evaluation environment, as anywhere, that holds
only for witness keys you configure yourself, at a threshold you choose, and only as far as those witnesses are
independent of the log. This program cannot tell where a witness runs in the evaluation environment: a cosignature
shows what a key signed, never who holds the key.

## The inputs

Yours, the relying party's, never taken from the bundle under test:

- `--witness-policy FILE`: in the C2SP policy format (`log <vkey>`, `witness <name> <vkey>`, `group <name>
  <N|any|all> <member>...`, `quorum <name|none>`, `#` comments), the log key, the keys of the evaluation
  environment's witnesses you rely on, the groups and the quorum. At least one `log` line is required.
- `--held-size N --held-root ROOT`: the largest tree size you hold and its base64 SHA-256 root.
- `--held-state FILE`: instead of the two flags, a file you keep, `{"origin": ..., "root": ..., "size": ...}`. An
  absent file means nothing is held, and the output says so.
- `--write-held-state`: after a full pass, write the checkpoint's origin, size and root to the `--held-state` file,
  if its size is larger than the held size. Never written otherwise, and never lowered.

The held-state file resists a rollback only as far as the file itself does. If it is lost or reset, the next
checkpoint is compared with nothing. If it is restored from a backup, copied from an older machine, or written by
someone else, the next checkpoint is compared with that older or chosen state, and check 3 proves only "not older than
that". The file carries no signature or checksum of its own, so nothing in it shows where it came from. Keep it where
you keep other security state. It is written in place after the pass. If that write cannot be made, the run is a
usage error (exit 2). If the write is cut off, the next run refuses the file as unreadable (exit 2) rather than treat
it as empty.

From the bundle under test:

- `--checkpoint NOTE`: the cosigned checkpoint (`GET /v1/log/checkpoint`, its `cosigned.note`).
- `--inclusion-proof FILE`: `{"hash": "sha256", "leaf_index", "tree_size", "leaf_hash", "proof": [base64...]}`
  (`GET /v1/log/inclusion`).
- `--consistency-proof FILE`: `{"hash": "sha256", "old", "new", "proof": [base64...]}` from your held size to the
  checkpoint's (`GET /v1/log/consistency`).
- `--key-transition FILE`: the log's signed key-transition record, when the log's key changed (served with its
  inclusion proof).

The checkpoint, the inclusion proof and the policy go together. A held size needs its root, and a consistency proof
needs a held size. Anything else is a usage error (exit 2).

**A key change.** A checkpoint signed by a key your policy does not name is refused, unless the log's key-transition
record is given. That record must name the checkpoint's origin and carry the old key's Ed25519 endorsement of the
new key, over `0x00 || "requisition.lab.log.key_transition.v0\n" || origin "\n" || previous size "\n" || base64
previous root "\n" || base64 new key "\n"`. The old key must be a log key your policy names. The endorsed new key
then stands in for it, and only from the point the old key endorsed it at: a checkpoint it signs must be at least the
record's previous checkpoint size (else `checkpoint_before_transition`), and at that size must carry the record's
previous root (else `checkpoint_transition_root_mismatch`). If the tree size you hold is below that point, check 2 runs
from the transition point instead: the consistency proof must start at the record's previous size and root.

## Refusals

Every refusal exits 5 (TRUST NOT ESTABLISHED). The record's signature checked out; what is not established is the
log's account of it. The last line names the code:

- `checkpoint_note_malformed`: the checkpoint is not a signed note (not UTF-8, a control character, no blank line, 0
  or more than 16 signature lines, a line that is not `— <name> <base64>`, two lines of one name and key, or a text
  that is not origin, decimal size, base64 SHA-256 root).
- `checkpoint_signature_invalid`: a line of a key your policy names does not verify.
- `checkpoint_no_trusted_signature`: no line is by a key your policy names, or a log key your policy names did not
  sign.
- `checkpoint_origin_mismatch`: a log key's line verifies, but the checkpoint is for another origin (a signature line
  relabelled from another log).
- `checkpoint_quorum_not_met`: in the evaluation environment, the witnesses that cosigned do not meet your quorum.
- `checkpoint_algorithm_unsupported`: your policy names an ML-DSA-44 (type 0x06) key of an evaluation environment
  witness; these verifiers compute Ed25519 only.
- `checkpoint_transition_unendorsed`: the key-transition record does not name this log, both keys and an
  endorsement, or its endorsement is not by a log key your policy names.
- `checkpoint_before_transition`: the checkpoint the new key signed is smaller than the point the old key endorsed
  it at.
- `checkpoint_transition_root_mismatch`: the checkpoint the new key signed has that point's size and another root.
- `checkpoint_proof_malformed`: a proof is not an object over the SHA-256 tree, its sizes are not the checkpoint's
  (and your held size), or its hashes are not base64 SHA-256.
- `checkpoint_leaf_malformed`: the record's signature or co-signature is not canonical base64 under 65,536 bytes.
- `checkpoint_inclusion_invalid`: the proof's leaf hash is not this record's, or the proof does not take the
  record's leaf to the checkpoint's root.
- `checkpoint_older_than_held`: the checkpoint's size is below the size you hold.
- `checkpoint_split_view_at_held_size`: the checkpoint has the size you hold and a different root.
- `checkpoint_consistency_unproven`: the checkpoint is larger than the size you hold and no consistency proof is
  given.
- `checkpoint_consistency_invalid`: the consistency proof does not show the checkpoint's tree extending yours.

`bin/lab-verify` passes these through unchanged. A record whose own signature is ML-DSA-87 (the evaluation
environment's post-quantum seat) takes `bin/lab-verify`'s other path, where `verify_receipt.py` does not run, so the
flags are refused there by name, `lab_checkpoint_unchecked_mldsa87`. `verify_offline.py` reports a checkpoint refusal
as `verdict: FAIL (the log checkpoint: <code>)`, exit 6.

A pass prints, after the receipt's own verdict, lines beginning `log checkpoint:` (the origin, size and root, the log
key, the cosigners from the evaluation environment, the record's leaf index, the comparison with your held size), and
last `log checkpoint: all checks held: inclusion, witness quorum, not older than the held size`.

## Not checked

- In the evaluation environment, ML-DSA-44 witness cosignatures (type 0x06): refused by name, above.
- In the evaluation environment, the log's ML-DSA-87 note line and the SHA-384 root of its four-line note: proofs
  are checked over the SHA-256 tree, the one its witnesses cosign.
- A record whose own signature is ML-DSA-87 in the evaluation environment, through `bin/lab-verify` and
  `verify_offline.py`: refused by name.
- Whether the checkpoint is the log's newest, or how old it is: cosignature times are not compared with any clock.
- That the key-transition record itself is included in the log, or its own signature by the new key. The old key's
  endorsement is what is checked. When the tree size you hold is below the transition point, that your tree extends to the
  transition point is not checked: the old key's endorsement of that point stands in for it.
- Who runs a witness of the evaluation environment, or whether those witnesses are independent of the log or of each
  other.

## Vectors

`lab/checkpoint-vectors/` in the Requisition repository holds 32 cases made by the evaluation environment's own code
(its `PROVENANCE.md` says how): 6 that pass and 26 that are refused, each with the verdict every verifier above must give. The tests run all four
verifiers over every case.
