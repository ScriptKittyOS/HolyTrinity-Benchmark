# Verify a Trinity authority receipt

```
elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json
python3 verify_receipt.py  --receipt RECEIPT.json --registry REGISTRY.json
```

No Mix project, no hex packages, no pip installs, **no network**. `verify_receipt.exs` needs
Elixir 1.17 / OTP 27 or later; verified on Elixir 1.19.2 / OTP 28. `verify_receipt.py` is tested
with Python 3.11 and 3.12.

## The one thing to understand before running it

**Supply a registry you obtained independently of the receipt.** The verifier will not use key
material that arrived with the evidence — a receipt may carry a `public_key` field and it is
always ignored. A key from the same download as the receipt proves nothing, because whoever
produced the bundle chose both halves. Given no `--registry`, the verifier **refuses** and exits
`5` rather than reporting a verdict it has no basis for.

The registry is published in the public repository, where every append is a dated commit you can
walk and tampering is detectable against any older clone.

A second channel — a Zenodo deposit carrying a DOI — is **intended and not yet live.** When it
exists, cross-checking one against the other becomes available and **disagreement between them is
itself an alarm.** Until then there is one channel, and this document says so rather than sending
you to look for a mirror that is not there.

## Exit codes and verdicts

**`VERDICTS.md`, beside this file, is the single source.** It defines every code, every input
condition that produces it, and the order the checks run in, and the cross-check test parses it.
This README does not restate the table: four copies of one rule is how the copies drift.

The codes are frozen at `0 1 2 5 6`. The distinction to carry in your head is that **`1` accuses
the receipt and `5` declines to judge it**, and collapsing them tells an examiner a receipt was
**forged** when it was merely **unverifiable as presented**. Those demand opposite responses.

`0`, `1`, `2` and `6` are this project's proposal and are **provisional** pending reconciliation
with the VIRP verifier's vocabulary.

## Log checkpoints in the evaluation environment

`CHECKPOINTS.md`, beside this file, says how both verifiers also check what the transparency log of
the evaluation environment says of a lab record: its inclusion under a checkpoint the log key signed
and the evaluation environment's witnesses cosigned, that checkpoint's consistency with a tree you
hold, and that it is not older than that tree. The Elixir checks of the evaluation environment's log
are in `verify_receipt_checkpoint.exs`, which `verify_receipt.exs` loads only when one of their flags
is given. The log, its checkpoints and its witnesses exist in the evaluation environment only.

## What a verified signature actually attests

The signed bytes are the receipt's canonical payload. When they carry `sequence` and
`previous_hash`, a valid signature binds the receipt's **position in its chain**, not only its
content. Neither verifier requires the two members. On exit `0` each ends with a note: when the
signed bytes carry both, that the signature binds the receipt's position in its chain; otherwise
what is absent, and that the signature does not bind the receipt's position in a chain. Neither
verifier reads a chain: one receipt is checked, alone.

## The signing scheme, so you can reimplement it

1. The receipt's `signed_payload` is a **canonical JSON** encoding: object keys sorted, an object
   whose keys normalise to one name refused rather than written (so no name appears twice; before
   2026-09-16 both were written, and such bytes are not read today), strings byte-exact with no unicode
   normalization, integers and floats never merged (canonical versions 2 and 3 write a float in the form they declare,
   which differs from the JSON Canonicalization Scheme's for some values; since the change of 2026-11-16 the issuing
   system signs no float, and version 4 refuses one), datetimes ISO 8601. It is stored as the literal
   byte string — **never re-serialize it**; that is the whole point of persisting it.
2. `receipt_hash` is SHA-256 over those bytes, lowercase hex.
3. `signature` is Ed25519 (RFC 8032) over those same bytes, base64. A reimplementation must also
   refuse a non-canonical encoding of the public key or of R, a public key or R of small order
   (`[8]P` is the identity), a public key not of prime order (`[L]A` is not the identity), and an
   `S` not below `L`: under the identity key every `R = [S]B`
   verifies for every message. `VERDICTS.md` ("the Ed25519 refusals") gives the verdict.
4. `key_id` names the registry entry whose `public_key` checks it.

Verification, in the order `VERDICTS.md` fixes: look up `key_id` in the registry and refuse if it
is absent **or named more than once**; refuse an `example` entry, a status the registry does not
define, or an entry that **does not hash to its own `public_key_fingerprint`**; refuse an entry
whose window bounds are unreadable, and signed bytes that carry no readable `occurred_at`; then
hold the receipt itself to its own `receipt_hash`, to **agreement between any visible top-level
field and the signed bytes**, and to the signature; then report a `compromised` entry; then refuse
a receipt whose signed `occurred_at` is **outside the key's signing window**
`[valid_from, valid_to)`.

Every trust question but the signing window runs before every accusation, because an accusation
requires standing; the window is checked after the signature.

## The compromised verdict states its own limit

A `compromised` key still produces cryptographically valid signatures. Separating a receipt signed
**before** the compromise from one signed **after** depends on knowing when it was signed — and the
signing time is asserted by the receipt, which an adversary holding that key can backdate.

So the verdict is **sound for honest history and advisory against a forger**, and the verifier says
so in its own output rather than only here. Closing the gap requires anchoring signing times
outside the issuing system (a transparency log, an RFC 3161 timestamp, a chain anchor). In the
evaluation environment a transparency log now exists, and both verifiers check a lab record's
inclusion under a checkpoint of it (`CHECKPOINTS.md`). That does not close this gap: neither
verifier compares a cosignature's time with the time a key was marked compromised (`CHECKPOINTS.md`,
"Not checked"), and the log runs in the evaluation environment only.

## Two implementations, and why

`verify_receipt.exs` is the reference. `verify_receipt.py` exists so an examiner without an Elixir
toolchain is not excluded, and it carries a hand-written RFC 8032 verification because Python's
standard library has no Ed25519 and requiring a package would break the no-installs property.

That is a deliberate second implementation of one check. It is bounded by a **cross-check corpus**
run through both in CI — good signatures, tampered payloads, wrong keys, truncated signatures, an
example-key receipt that must be refused, and a receipt naming an unregistered key that must error
rather than fall back. **Their verdicts must match**, so neither can drift.

## This verifier is our artifact

An examiner who does not trust us has no reason to trust it either. Three things bound that:

* both files are short and dependency-free, so they can be read in full;
* the scheme is specified above, so it can be reimplemented from scratch and checked against both;
* two independent implementations agreeing is a stronger basis than either alone.

**Not yet reproducibly buildable.** These are scripts run by stock runtimes, so there is no build
to reproduce — but neither is there a signed release artifact you can pin. Stated because you would
otherwise have to find it out.

**There are now pins, and they are not signed artifacts.** Four annotated tags name immutable
points: `receipt-verification-r1`, `receipt-verification-r2`, `receipt-verification-r3` and
`receipt-verification-r4`. Cite one of those rather than a branch. **The sentence above stays true
as written:** an annotated tag is not a GPG-signed release artifact, no such artifact exists, and a
tag can be moved by whoever holds the remote. What a tag gives you is a fixed name for a commit you
can diff against any older clone; what it does not give you is a signature over that state.

## A limitation this verifier discloses rather than hides

**`key_id` is not inside the signed bytes.** A receipt names the registry entry that judges it, so
whoever presents a receipt selects which entry applies by editing an unsigned field. v1 trusts the
presenter's `key_id` to select the entry; **registries must therefore keep public keys unique per
entry**; v2 binds `key_id` into the signed bytes and closes it. Recorded as row `V-KEYSUB` in
`VERDICTS.md`, whose expected exit is the current behaviour so the limitation stays pinned rather
than forgotten.

## Pattern credit

The default-distrust posture, the refusal with a distinct exit code when signer trust is not
established from bundle-local key material, and the discipline of disclosing flaws unprompted are
taken from:

> **Nathan Howard** (Third Level IT / thirdlevel.ai)
> **VIRP verifier, v0.1.0** — <https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier>

## r4 — every failure names its typed code (appended 2026-09-14)

Since r4, `verify_receipt.exs` prints one extra final line on every failure, `verdict_code: <code>`
— one of the thirteen typed codes the reference verifier's denial taxonomy assigns to trust and
signature failures. **The exit codes and every message byte before that line are unchanged**;
`VERDICTS.md` (the `verdict_code` section) governs the mapping, and the r3 corpus replays with
identical exits and identical bytes plus that line (21 of 21 entries, measured at preparation).

**Correction, appended 2026-09-18.** Thirteen was two short: the two exit-1 sites for a
`receipt_hash` that does not match its signed bytes and a signature that does not check out
carried no code until now. They name `receipt_hash_mismatch` and `signature_invalid`; the
taxonomy holds fifteen. See `VERDICTS.md`, the `verdict_code` section's correction.
`verify_receipt.py` does not print it yet — a stated parity gap, not a divergence in verdicts.

## The Python names the code too, and the parity is three-way (appended 2026-09-20)

`verify_receipt.py` now ends every exit-1 and exit-5 message with the same `verdict_code` line,
on stderr with the message; the parity gap the correction above stated is closed, and the
cross-check compares the code on every row across the Elixir verifier, the Python verifier and
the issuing system's own verdict. Three rows were added to hold what the exit-only cross-check
could not see (`V-KEY-MALFORMED`, `V-NO-ENTRIES`, `V-NULL-ENTRIES`), one message line moved
(`V-TRUNCATED` is `signature_malformed`, the taxonomy's word), and one case's exit moved from an
accidental `1` to `5` (a registry key that is not 32 bytes: `key_public_key_malformed`, the
sixteenth code). `VERDICTS.md`'s parity paragraph records the measurement and the ruling; the
verifier-primitive rule is stated in the Python's header.

## No input ends in a stack trace (appended 2026-11-13)

Every exit-1 and exit-5 message either verifier writes ends with its `verdict_code` line, and no
input, however shaped, ends in a runtime stack trace: a registry or receipt that is valid JSON and
not an object, a member of the wrong type, a number, string or nesting the other runtime reads
differently, are each answered by a typed refusal with the exit `VERDICTS.md` assigns (`5` for a
registry that gives no basis to judge, `2` for input that could not be read). An exception nobody
foresaw ends in exit `2` with a one-line `internal error` message, never `0` or `1`. See the last
section of `VERDICTS.md` for the measurement and the rules.

## One reading rule, in both verifiers and the issuing system (appended 2026-11-14)

What one implementation reads, every implementation reads, to the same value; what one refuses,
every one refuses. The two verifiers hold to that for the receipt file, the registry file and the
signed bytes; the issuing system holds to it for the signed bytes of a chain receipt, when it
judges one and before it signs one, and for its registry file (it reads no receipt file). It does
not apply the rule to the other records it signs or checks: the lab records of its execute API
(an API of its evaluation environment, which a production release does not serve) are signed without it and chain-checked through its general JSON reader (`VERDICTS.md`, "The
rule").
A member name written twice is never read (there is no first-wins or last-wins), nor is nesting
beyond 64, an integer of more than 1024 characters, a negative zero written with an exponent and
no fraction (`-0e5`, which two JSON runtimes read to two values), or a file over 1,048,576 bytes;
a timestamp must be a real calendar instant, not only the right form (`2026-02-30T00:00:00Z` is
refused); `-0.0` displayed over a signed `0.0` is a contradiction; an empty `key_id` names no key;
base64 is read only in its padded form. The nesting check is one pass, so no input makes a
verifier slow. Each of these but the size of a file has a row in `VERDICTS.md` with a fixture that
carries a valid signature; the size bound is held by a test that writes a file of exactly the
bound and one a byte larger. The last section of `VERDICTS.md` states the rule, the measurement
behind it, and every kind of input it now refuses that an earlier verifier accepted.
