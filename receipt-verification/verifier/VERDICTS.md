# Verdicts

**This file is the single source of truth for what each verifier exit code means and for which
input produces it.** `verify_receipt.py`, `verify_receipt.exs`, `README.md` and the cross-check
matrix all cite this table rather than restating it. Four copies of one rule is how the copies
drift; there is one copy, and the others cite it.

**Every trust question but the signing window precedes every accusation; `6` and the signing-window
answer are given only over a signature that has already verified.**

The cross-check test **parses this file**. A row with no fixture fails it, a fixture with no row
fails it, and an expected exit changed here without a matching code change fails it. The table is
executable documentation, not a description of it.

## The codes

They are frozen. `0 1 2 5 6`, and no others may be introduced (`docs/naming.md:41-42`).

| code | verdict | what it says about the receipt |
|---|---|---|
| `0` | verified | the signature is good under an independently supplied key whose standing the registry establishes |
| `1` | signature invalid | **the receipt is bad** — its own bytes, hash, fields or signature disagree |
| `2` | usage error | nothing about any receipt; the invocation was malformed, or an input could not be read |
| `5` | trust not established | **the receipt is unjudged** — no independent basis to judge it |
| `6` | key compromised | signature valid, signer trust degraded — **provisional** |

**`1` and `5` are deliberately different and must never be collapsed.** `1` accuses the receipt.
`5` declines to judge it. Reporting the second as the first tells an examiner a receipt was
**forged** when it was merely **unverifiable as presented**, and those demand opposite responses.
`0`, `1`, `2` and `6` are this project's proposal and are provisional pending reconciliation with
the VIRP verifier's vocabulary.

## How to read a row

`registry` and `receipt` are **closed vocabularies of tokens, never command lines.** The table can
name a situation; it can never name an invocation. Adding a token is deliberately a code change.

| token | in `registry` | in `receipt` |
|---|---|---|
| a path | `--registry <path>` | `--receipt <path>` |
| `corpus` | `--registry corpus/registry.json` | — |
| `duplicate` | `--registry corpus/registry-duplicate-key-id.json` | — |
| `live` | `--registry ../keys/registry.json` | — |
| `absent-from` | `--registry corpus/registry-absent-valid-from.json` | — |
| `null-from` | `--registry corpus/registry-null-valid-from.json` | — |
| `malformed-key` | `--registry corpus/registry-malformed-key.json` | — |
| `small-order-key` | `--registry corpus/registry-small-order-key.json` | — |
| `no-entries` | `--registry corpus/registry-no-entries.json` | — |
| `null-entries` | `--registry corpus/registry-null-entries.json` | — |
| `not-object` | `--registry corpus/registry-not-object.json` | — |
| `entries-object` | `--registry corpus/registry-entries-object.json` | — |
| `entries-not-objects` | `--registry corpus/registry-entries-not-objects.json` | — |
| `key-wrong-type` | `--registry corpus/registry-key-wrong-type.json` | — |
| `absent-key` | `--registry corpus/registry-absent-public-key.json` | — |
| `reading` | `--registry corpus/registry-reading.json` | — |
| `empty-entries` | `--registry corpus/registry-empty-entries.json` | — |
| `none` | the flag is omitted entirely | the flag is omitted entirely |
| `dangling` | — | `--receipt` supplied with no value after it |

Paths are relative to `verifier/`, which is where both verifiers are run from.

## The table

| id | receipt | registry | exit | verdict | why |
|---|---|---|---|---|---|
| V-VERIFIED | `corpus/verified.json` | `corpus` | `0` | verified | active key, inside its window, fingerprint matches, hash and signature agree |
| V-RETIRED-IN | `corpus/retired-key-in-window.json` | `corpus` | `0` | verified | a retired key's signatures survive its retirement; `occurred_at` is inside the signing window |
| V-KEYSUB | `corpus/key-substitution.json` | `corpus` | `0` | verified | ACCEPTED-KNOWN-LIMITATION, see below; `key_id` is outside the signed bytes so the presenter selects the judging entry |
| V-INVALID-SIG | `corpus/invalid-signature.json` | `corpus` | `1` | signature invalid | the payload gained a byte after signing; its own `receipt_hash` no longer matches its bytes |
| V-WRONG-KEY | `corpus/wrong-key.json` | `corpus` | `1` | signature invalid | signed by a key that is not the one the registry names for this `key_id` |
| V-TRUNCATED | `corpus/truncated.json` | `corpus` | `1` | signature invalid | the signature is not 64 bytes, which Ed25519 requires; MALFORMED, not merely invalid (`signature_malformed` in all three implementations since 2026-09-20) |
| V-HASH-ABSENT | `corpus/no-receipt-hash.json` | `corpus` | `1` | signature invalid | `receipt_hash` is absent, so the receipt states no digest to be held to; absence is a failure, not a skip |
| V-SIBLING | `corpus/sibling-contradiction.json` | `corpus` | `1` | signature invalid | a top-level field contradicts the same field inside the signed bytes |
| V-EXAMPLE-KEY | `corpus/example-key.json` | `corpus` | `5` | trust not established | an example entry is never a trust root; its private half is derived from a published string |
| V-UNKNOWN-KEYID | `corpus/unknown-key-id.json` | `corpus` | `5` | trust not established | the registry names no such `key_id`, and the verifier never falls back to another key |
| V-STATUS-UNKNOWN | `corpus/revoked-key.json` | `corpus` | `5` | trust not established | the entry's status is not one of the four the registry defines; unknown standing is not good standing |
| V-STATUS-ABSENT | `corpus/no-status-key.json` | `corpus` | `5` | trust not established | the entry carries no status at all; default deny |
| V-FINGERPRINT | `corpus/bad-fingerprint-key.json` | `corpus` | `5` | trust not established | the entry does not hash to its own published `public_key_fingerprint`, so nothing it says can be believed |
| V-WINDOW-AFTER | `corpus/expired-key.json` | `corpus` | `5` | trust not established | `occurred_at` is at or after `valid_to`; the key was not signing then |
| V-WINDOW-EDGE | `corpus/window-edge-key.json` | `corpus` | `5` | trust not established | `occurred_at` equals `valid_to` exactly; the window is half-open and excludes its upper bound |
| V-WINDOW-BEFORE | `corpus/window-before-key.json` | `corpus` | `5` | trust not established | `occurred_at` is before `valid_from`, a claim to have been signed in an era the key did not cover |
| V-BOUND-ABSENT | `corpus/verified.json` | `absent-from` | `5` | trust not established | the entry omits `valid_from`; a required bound that is missing makes the entry malformed and its era unjudgeable |
| V-BOUND-NULL | `corpus/verified.json` | `null-from` | `5` | trust not established | the entry's `valid_from` is null; a bound is open-ended only where the schema permits it, and it does not permit it here |
| V-KEY-MALFORMED | `corpus/verified.json` | `malformed-key` | `5` | trust not established | the entry hashes to its own fingerprint and its `public_key` is 31 raw bytes: what the registry published is not an Ed25519 key. A defect in the trust root is a trust question, never an accusation (before 2026-09-20 the Elixir verifier exited `1` here by accident — OTP's argument check caught by a rescue) |
| V-SMALL-ORDER-KEY | `corpus/forged-small-order-key.json` | `small-order-key` | `1` | signature invalid | the registry's active key is the Ed25519 identity (a small-order point; it hashes to its own fingerprint) and the receipt carries `R = B, S = 1`, which verifies over any message under that key; refused as an invalid signature (`signature_invalid`), never trusted |
| V-NO-ENTRIES | `corpus/verified.json` | `no-entries` | `5` | trust not established | the registry has no `entries` key; it gives no basis to judge anything, the same question as an unnamed `key_id` |
| V-KEY-ABSENT | `corpus/verified.json` | `absent-key` | `5` | trust not established | the entry has no `public_key` and its fingerprint is sha256 of nothing: a fingerprint failure in all three (an earlier Python version coalesced the absent key to empty bytes and reached the key-length check instead) |
| V-INSTANT-UNREADABLE | `corpus/bad-occurred-at.json` | `corpus` | `5` | trust not established | the signed bytes carry an `occurred_at` that is not the accepted form; asked after the entry's window, before any accusation |
| V-BOUND-AND-INSTANT | `corpus/bad-occurred-at.json` | `absent-from` | `5` | trust not established | the entry's `valid_from` is absent AND the instant is unreadable: the window's bound is asked first, in all three (an earlier Elixir version asked the instant first) |
| V-NULL-ENTRIES | `corpus/verified.json` | `null-entries` | `5` | trust not established | the registry's `entries` is null; the Elixir verifier crashed on this shape before 2026-09-20 (a stack trace and the runtime's exit `1`) while the Python exited `5` — a divergence the exit-only cross-check saw only once the row existed |
| V-REGISTRY-NOT-OBJECT | `corpus/verified.json` | `not-object` | `5` | trust not established | the registry file is valid JSON and is not an object (here `[]`; `null`, a number and a string are the same); it carries no `entries` list, so it gives no basis to judge anything, the same question as an unnamed `key_id` |
| V-ENTRIES-NOT-LIST | `corpus/verified.json` | `entries-object` | `5` | trust not established | `entries` is an object keyed by `key_id`, not a list; the entry the receipt names is inside it, and it is still not read: a registry whose `entries` is not a list gives no basis to judge |
| V-ENTRY-NOT-OBJECT | `corpus/verified.json` | `entries-not-objects` | `5` | trust not established | every element of `entries` is something other than an object (null, a number, a string, lists, a boolean); none of them names a `key_id`, so the registry does not name this one |
| V-ENTRY-MEMBER-TYPE | `corpus/verified.json` | `key-wrong-type` | `5` | trust not established | the entry's `public_key` is a list, not a base64 string; that is the same failure as an absent one, an entry that cannot hash to its own fingerprint |
| V-RECEIPT-NOT-OBJECT | `corpus/receipt-not-object.json` | `corpus` | `2` | usage error | the receipt file is valid JSON and is not an object (here `[]`); nothing was measured |
| V-RECEIPT-FIELD-TYPE | `corpus/receipt-field-type.json` | `corpus` | `2` | usage error | `signed_payload` is an object, not a string; the receipt does not carry `signed_payload`, `signature` and `key_id` in the form a verifier can read, and nothing was measured |
| V-HASH-NOT-STRING | `corpus/receipt-hash-not-string.json` | `corpus` | `1` | signature invalid | `receipt_hash` is a number, not a string; the receipt states no digest to be held to, the same as an absent one |
| V-READING-CONTROL | `corpus/reading-control.json` | `reading` | `0` | verified | the control for the reading rows: a receipt signed by the reading registry's active fixture key verifies, so a refusal in the rows below is about how an input is read and not about the fixture's signature |
| V-SIGNED-REPEAT-OUT-IN | `corpus/reading-repeat-outside-inside.json` | `reading` | `5` | trust not established | the signed bytes hold `occurred_at` twice: first outside the retired key's window, then inside it. An object that repeats a member name is not read by any implementation; the signed bytes are then not readable, so they carry no readable `occurred_at`. (Reading the last one verified this receipt; reading the first one refused it for its window.) |
| V-SIGNED-REPEAT-IN-OUT | `corpus/reading-repeat-inside-outside.json` | `reading` | `5` | trust not established | the same with the order turned: first inside the window, then outside. The verdict does not depend on which occurrence a reader would have kept |
| V-SIGNED-REPEAT-ESCAPED | `corpus/reading-repeat-escaped-name.json` | `reading` | `5` | trust not established | the second `occurred_at` is written with an escape for its first letter; names are compared after decoding, so it is the same name and the object repeats it |
| V-SIGNED-REPEAT-BAD-GOOD | `corpus/reading-repeat-unreadable-readable.json` | `reading` | `5` | trust not established | `occurred_at` twice: first not an instant, then a good one. Refused for the repeat, not for whichever value a reader kept |
| V-SIGNED-REPEAT-GOOD-BAD | `corpus/reading-repeat-readable-unreadable.json` | `reading` | `5` | trust not established | `occurred_at` twice: first a good instant, then not an instant |
| V-SIGNED-REPEAT-SIBLING-LAST | `corpus/reading-repeat-sibling-last.json` | `reading` | `5` | trust not established | the signed bytes hold `sequence` twice (1, then 2) and the receipt displays 2. A reader keeping the last saw no contradiction and one keeping the first saw one; the bytes are not read at all |
| V-SIGNED-REPEAT-SIBLING-FIRST | `corpus/reading-repeat-sibling-first.json` | `reading` | `5` | trust not established | the same signed bytes, the receipt displays 1 |
| V-SIGNED-REPEAT-NESTED-LAST | `corpus/reading-repeat-nested-last.json` | `reading` | `5` | trust not established | the repeat is one level down: `metadata` holds `verdict` twice (deny, then allow) and the receipt displays allow. The rule holds at every depth |
| V-SIGNED-REPEAT-NESTED-FIRST | `corpus/reading-repeat-nested-first.json` | `reading` | `5` | trust not established | the same signed bytes, the receipt displays deny |
| V-SIGNED-REPEAT-DEEP-LAST | `corpus/reading-repeat-deep-last.json` | `reading` | `5` | trust not established | the repeat is inside an object inside a list inside `metadata`; the receipt displays the last value |
| V-SIGNED-REPEAT-DEEP-FIRST | `corpus/reading-repeat-deep-first.json` | `reading` | `5` | trust not established | the same signed bytes, the receipt displays the first value |
| V-INSTANT-NOT-A-DAY | `corpus/reading-instant-day-30-february.json` | `reading` | `5` | trust not established | `occurred_at` is `2026-02-30T00:00:00Z`: the accepted form, and not a day. An instant is read only when it is a real calendar instant; comparing the text alone placed this one inside the window |
| V-INSTANT-HOUR-24 | `corpus/reading-instant-hour-24.json` | `reading` | `5` | trust not established | `occurred_at` has hour 24; hours run 00 to 23 and `24:00:00` is not read as the next day |
| V-INSTANT-SECOND-60 | `corpus/reading-instant-second-60.json` | `reading` | `5` | trust not established | `occurred_at` has second 60; no leap second is read |
| V-BOUND-FROM-NOT-A-DAY | `corpus/reading-bound-from-30-february.json` | `reading` | `5` | trust not established | the entry's `valid_from` is `2026-02-30T00:00:00Z`; a bound that is not a real instant is not a bound, the same as an unreadable one |
| V-BOUND-TO-NOT-A-DAY | `corpus/reading-bound-to-30-february.json` | `reading` | `5` | trust not established | the entry's `valid_to` is `2026-02-30T00:00:00Z`; unreadable, and never read as open-ended |
| V-SIBLING-NEGATIVE-ZERO | `corpus/reading-sibling-negative-zero.json` | `reading` | `1` | signature invalid | the receipt displays `metadata.score` as `-0.0` and the signed bytes say `0.0`. They are different numbers (they differ in their sign bit) and no implementation merges them |
| V-DISPLAYED-NEGATIVE-ZERO-EXPONENT | `corpus/reading-displayed-negative-zero-exponent.json` | `reading` | `2` | usage error | the receipt file displays `metadata.score` as `-0e5`: a negative zero written with an exponent and no fraction. One JSON runtime reads that text as `-0.0` and another as `0.0`, so the file is not read (the signed bytes say `0.0`; a verifier that kept the sign would accuse this receipt and one that dropped it would verify it) |
| V-DISPLAYED-NEGATIVE-ZERO-EXPONENT-SIGNED-NEGATIVE | `corpus/reading-displayed-negative-zero-exponent-over-negative-zero.json` | `reading` | `2` | usage error | the same displayed `-0e5`, over signed bytes that say `-0.0`: the converse disagreement, refused the same way |
| V-SIGNED-NEGATIVE-ZERO-EXPONENT | `corpus/reading-signed-negative-zero-exponent.json` | `reading` | `5` | trust not established | the signed bytes hold `-0e5`; not read by any implementation, the issuing system included; the signed bytes are then not readable, so they carry no readable `occurred_at` |
| V-NEGATIVE-ZERO-FRACTION-EXPONENT | `corpus/reading-negative-zero-fraction-exponent.json` | `reading` | `0` | verified | the receipt displays `metadata.score` as `-0.0e5` and the signed bytes say `-0.0`: a negative zero written with a fraction is read to the same value by every implementation, with or without an exponent |
| V-KEYID-EMPTY | `corpus/reading-empty-key-id.json` | `reading` | `5` | trust not established | the receipt's `key_id` is the empty text. It names no key, also when a registry entry carries the empty text as its `key_id` (this registry has one, and the signature is good under it) |
| V-SIGNED-INTEGER-1024 | `corpus/reading-integer-1024-characters.json` | `reading` | `0` | verified | the signed bytes hold an integer written with 1024 characters: the longest that is read |
| V-SIGNED-INTEGER-1025 | `corpus/reading-integer-1025-characters.json` | `reading` | `5` | trust not established | an integer written with 1025 characters is not read by any implementation; the signed bytes are then not readable, so they carry no readable `occurred_at` |
| V-SIGNED-INTEGER-SIGN | `corpus/reading-integer-negative-1025-characters.json` | `reading` | `5` | trust not established | a minus sign and 1024 digits: 1025 characters. The sign counts |
| V-SIGNED-NESTED-64 | `corpus/reading-nested-64.json` | `reading` | `0` | verified | the signed bytes are nested 64 deep, the signed object itself counted: the deepest that is read |
| V-SIGNED-NESTED-65 | `corpus/reading-nested-65.json` | `reading` | `5` | trust not established | nested 65 deep; not read by any implementation, the issuing system included; the signed bytes are then not readable, so they carry no readable `occurred_at` |
| V-KEY-PADDING | `corpus/reading-key-extra-padding.json` | `reading` | `5` | trust not established | the entry's `public_key` is a full base64 group followed by one more `=`. That text is not base64, so the entry has no key bytes and cannot hash to its own fingerprint (a decoder that drops the stray `=` reads 33 bytes that do hash to it; that reading is refused) |
| V-ENTRIES-EMPTY | `corpus/verified.json` | `empty-entries` | `5` | trust not established | the registry's `entries` is an empty list: a registry was supplied and it names no key, the same question as an unnamed `key_id` (and not the answer for a registry that was not supplied) |
| V-RETIRED-OUT | `corpus/retired-key-out-of-window.json` | `corpus` | `5` | trust not established | retired key, `occurred_at` after `valid_to`; retirement refuses post-window signatures |
| V-DUPKEY | `corpus/verified.json` | `duplicate` | `5` | trust not established | the registry names one `key_id` more than once, so position would select the verdict; an internally inconsistent trust root gives no basis to judge |
| V-NO-REGISTRY | `corpus/verified.json` | `none` | `5` | trust not established | no registry supplied; a key arriving with the evidence establishes nothing |
| V-WRONG-REGISTRY | `corpus/verified.json` | `live` | `5` | trust not established | the published registry does not name this corpus `key_id`; a finding about the command line, not the receipt |
| V-COMPROMISED | `corpus/compromised-key.json` | `corpus` | `6` | key compromised | signature valid and in window, under a key the registry marks compromised |
| V-NO-RECEIPT | `none` | `corpus` | `2` | usage error | no `--receipt`; says nothing about any receipt |
| V-ARGV-ODD | `dangling` | `corpus` | `2` | usage error | `--receipt` with no value; a malformed invocation must not be read as a verdict |

## The order the checks run in, because two conditions can both be true

All three implementations (the two verifiers and the issuing system's own verdict) evaluate in this
order and stop at the first that fires:

1. **`2`** — malformed invocation, unreadable input, or a receipt that is not a JSON object or is
   missing `signed_payload`, `signature` or `key_id` (as text). Nothing was measured. A file is
   unreadable when it is larger than 1,048,576 bytes, or is not JSON that every implementation
   reads to the same value (the reading rule, stated in full in the last section): besides invalid
   JSON and bytes that are not UTF-8, that means `NaN` or `Infinity`, a number beyond a double, an
   integer written with more than 1024 characters (its sign included), a string with an unpaired
   surrogate, an object that repeats a member name at any depth, nesting more than 64 levels deep,
   and text after the value. The signed bytes are read by the same rule, with no exception; signed
   bytes that are not read are a step 2 answer, because they are inside a file that was read.
2. **`5`** — no registry; `key_id` absent from the registry (a `key_id` that is the empty text
   names no key and is absent from every registry); `key_id` present more than once;
   entry status missing or outside the defined four; status `example`; fingerprint absent or not
   matching `sha256(raw public_key bytes)` (an absent or non-string `public_key` is this case);
   the entry's `public_key` not 32 raw bytes (2026-09-20); the entry's `valid_from` or
   `valid_to` unreadable (the window's bounds, BEFORE the receipt's instant — 2026-09-20);
   `occurred_at` absent or not the accepted timestamp form (the signed bytes that are not JSON
   every implementation reads alike, by the rules of step 1, carry no readable `occurred_at`). A
   registry that is not a JSON object, or whose `entries` is absent, null or not a list, is
   "`key_id` absent from the registry"; so is an `entries` that is an empty list, and one none of
   whose elements is an object with that `key_id`; an element that is not an object names no key.
3. **`1`** — `receipt_hash` absent or mismatched; a sibling field contradicting the signed bytes;
   signature failing to verify, which includes the Ed25519 refusals below.
4. **`6`** — status `compromised`.
5. **`5`** — `occurred_at` outside `[valid_from, valid_to)`.
6. **`0`** — otherwise.

**Why the trust questions of step 2 precede every accusation.** Steps 2 and 5 mean *we cannot
judge this*; step 3 means *this receipt is bad*. An accusation requires standing. Concretely: a
good receipt checked against the wrong registry must report `5`, and it only does so because the
`key_id` lookup runs before the hash and signature comparisons.

**Why `6` precedes the window.** Exit `6` states that the signature is cryptographically valid,
which cannot be said over a signature that failed to verify — so `6` is placed after step 3, never
before it.

## The signing window, stated once so the two implementations cannot drift

`valid_from` and `valid_to` are **the signing window** (`../keys/README.md`). They are compared
against `occurred_at`, taken from inside the signed bytes, which is the only signing time the
receipt carries.

**The interval is half-open: `valid_from <= occurred_at < valid_to`.** `valid_to: null` means no
upper bound. Three facts in the published registries settle the convention rather than taste:
`example_ed25519_v0` has `valid_from == valid_to`, and `keys/README.md` calls that window *closed*
with *no verifier accepts it as a trust root* — only half-open makes it genuinely empty;
`corpus_retired_v1`'s `valid_to` equals `corpus_active_v1`'s `valid_from`, and half-open gives
every instant at most one authorized key; and `valid_to` equals `status_changed_at`, the instant
signing stopped.

**Timestamps are accepted only as `YYYY-MM-DDTHH:MM:SSZ`.** Every timestamp in both registries and
every fixture already has exactly this form. A timestamp in any other form (a trailing newline
included) is **refused with `5`**, never coerced and never guessed: a verifier that accepts two spellings of an instant is a verifier
whose two implementations will eventually disagree about one of them.

**And only when the text is a real instant** (2026-11-14): month `01` to `12`; a day that month has
in that year, in the proleptic Gregorian calendar (year `0000` is a leap year); hour `00` to `23`;
minute and second `00` to `59`. There is no leap second and no `24:00:00`. `2026-02-30T00:00:00Z`
has the form, names no instant, and compared as text would sit between two real days; it is
refused with the code an unreadable timestamp has in that place (rows `V-INSTANT-NOT-A-DAY`,
`V-INSTANT-HOUR-24`, `V-INSTANT-SECOND-60`, `V-BOUND-FROM-NOT-A-DAY`, `V-BOUND-TO-NOT-A-DAY`). Both
verifiers do this arithmetic themselves, so no date library decides.

### Absent versus null, on each bound

**A bound is open-ended only where the registry's own schema permits it.**

| bound | absent | null | why |
|---|---|---|---|
| `valid_to` | open-ended | open-ended | the schema makes it optional; `keys/README.md` says it is null while a key is still signing |
| `valid_from` | **`5`** | **`5`** | the schema makes it required, so neither spelling of "missing" is a window |

**This is a deliberate divergence from the intuitive rule that null means open-ended on either
bound, and the reason is that the intuitive rule would put two authorities in conflict over one
file.** The issuing system's key registry lists `valid_from` among its required fields and
**deliberately omits `valid_to`**, and its presence check returns false for `nil` — so there an
absent `valid_from` and a null one are **already** treated identically, and both are invalid. A
verifier that accepted `valid_from: null` as "no lower bound" would accept a registry that the
issuing system's own validation rejects. Two authorities disagreeing about the same file is the
defect this table exists to remove, not one to introduce.

`V-BOUND-ABSENT` and `V-BOUND-NULL` pin both halves, so the seam where the two implementations
could drift — Python collapsing absent and null into `None`, Elixir splitting them across `nil` and
the `:null` atom that `:json.decode/1` produces — goes red rather than silent.

**This check is sound for honest history and advisory against a forger**, the same limit the
compromised verdict states: `occurred_at` is asserted by the receipt, and an adversary holding the
key can backdate it. Closing that gap needs a signing time anchored outside the issuing system.
That is named future work, not a solved problem.

## What "signature failing to verify" includes: the Ed25519 refusals

Both verifiers refuse the following before they compute the signature equation, with the existing
verdict `1` `signature_invalid` (no new exit, no new `verdict_code`). The terms are those of
RFC 8032: A is the public key, R the first half of the signature, S the second half, B the base
point, L the order of the prime-order subgroup, and the curve's cofactor is 8.

1. a **non-canonical encoding** of A or of R: `y >= p`, or `x = 0` with the sign bit set
   (RFC 8032 section 5.1.3);
2. a public key A of **small order**;
3. a signature R of **small order**;
4. an `S` that is not below `L`;
5. a public key A of **mixed order**: a key that is not in the prime-order subgroup, that is, one
   for which `[L]A` is not the identity (it is a multiple of B plus a point of small order). It is
   refused because implementations that reduce the hash modulo `L` and implementations that do not
   can give different answers for the same signature under such a key.

**Small order is decided by arithmetic, never by a list of encodings: `[8]P` is the identity.**
The plainest case is the identity key (`01 00 .. 00`): under it `[h]A` is the identity whatever
the message, so `R = [S]B` verifies for **every message**. The other seven points of order
dividing 8 (one of order 2, two of order 4, four of order 8) are not as bad, but they are bad.
For a key `A` of order 2, 4 or 8, `[h]A` is the identity exactly when `h` is a multiple of the
key's order, so a forged signature with `R = [S]B` verifies for roughly one message in two, four
or eight respectively (measured over 2048 messages per point with verify_receipt.py's arithmetic:
about 0.52, 0.26 and 0.12), and a forger who tries values of `R` finds, on average after about
two, four or eight tries respectively, one that verifies for any message they choose. Whatever
the fraction, no secret is needed to produce such a signature, so it says nothing about who made
it. That is why the whole class of eight points is refused, by the one test `[8]P` is the
identity, and not only the identity key. Before these refusals both verifiers answered exit `0` to
the identity-key forgery (the Python by its own arithmetic, the Elixir through OTP's
`:crypto.verify/5`).
The Elixir verifier writes the refusals out itself because OTP's `:crypto.verify/5` accepts such
keys; the Python verifier does its own arithmetic throughout and never delegated this check.

**Why `1` and not `5` for a registry that publishes a small-order key.** A registry key that is
not 32 bytes is a defect of the trust root and is `5` (`key_public_key_malformed`). A small-order,
non-canonical or mixed-order key is 32 bytes long and hashes to its own fingerprint, so the
registry's entry is well formed; what fails is the signature check, and the issuing system's own
verdict for it is also `signature_invalid`. Keeping one answer across the two verifiers and the
issuing system avoids a new row in the vocabulary; moving the question to step 2 would be a
separate change to that verdict and to the taxonomy. `V-SMALL-ORDER-KEY` holds it.

The refusals have no verdict code of their own: every one of them prints
`verdict_code: signature_invalid`.

## Two limitations this table records rather than hides

**V-KEYSUB — `key_id` is not inside the signed bytes.** A receipt names the registry entry that
judges it, so a presenter holding one signature can select which entry applies by editing an
unsigned field. In this corpus `corpus_active_v1` and `corpus_revoked_v1` carry the same public
key, and the same bytes verify under either. **Exit `0` is the documented v1 behaviour and the
matrix asserts it**, so the limitation is pinned rather than forgotten. It is unenforceable in v1
and is closed by the v2 preimage (domain separation), at which point the row's **v2 expectation**
becomes a non-zero exit. **The flip changes the v2 expectation only and never the v1 one:**
v1-format receipts keep exit `0` under this limitation permanently, and once v2 exists the matrix
asserts per format. Until then, **a production registry must never hold one public key under two
entries.**

**Duplicate detection is on `key_id` only.** V-DUPKEY fires when one `key_id` appears more than
once. **Duplicate public keys across distinct `key_id`s are not an error at the verifier and must
not become one** — that is the shape the reused-key fixtures in this corpus depend on. Why a real
registry must avoid them regardless is V-KEYSUB above, which is a different finding with a
different closer.

## One stricter rule considered and not adopted

A top-level field that appears **nowhere** in the signed payload is **ignored**, not refused. The
stricter rule — refuse any top-level field the signature does not cover — was considered and not
adopted in this version; this table records the ignore rule. It has a real argument
behind it: a receipt carrying `"approved_by": "alice"` at top level is covered by no signature, and
an examiner reading the JSON may take it for part of the receipt. The bound today is that the
production export emits exactly `signature`, `key_id`, `signed_payload`, `receipt_hash` (a frozen
export script of the issuing system). **Recorded here as a known gap so that the weaker rule is a
decision on the record and not an oversight.**

## `verdict_code` (added 2026-09-12)

The exit set above is unchanged. In addition, `verify_receipt.exs` now ends every `1` and `5`
message with a line `verdict_code: <code>` — one of the ten `:trust` codes (exit 5) or three
`:signature` codes (exit 1) in the issuing system's denial taxonomy,
one per failure site, so a caller can tell *which* trust question failed without matching prose.
The message bytes before that line are unchanged. `verify_receipt.py` does **not** emit it yet;
its failure sites are not one-to-one with the Elixir verifier's, and mapping them is a separate
cross-check, not a line to paste. Until then the code line is an Elixir-verifier feature and the
cross-check matrix compares exits only, as before.

**Correction, appended 2026-09-18.** "Every `1` and `5` message" was not true of two exit-1 sites:
*the receipt's own `receipt_hash` does not match its signed bytes* and *the signature does not check
out against the registry's public key* ended without a code (the count of three `:signature` codes
above was taken by a regex that saw only single-line `fail(` calls; there are five sites). Both now
end with a line — `verdict_code: receipt_hash_mismatch` and `verdict_code: signature_invalid` — and
the taxonomy carries **five** `:signature` codes. The exit codes and every message byte before the
line are unchanged; the corpus replays with identical exits. The issuing system's own verdict now
implements this table's order and names the same codes, and runs the corpus above row by row.

**Parity, appended 2026-09-20.** `verify_receipt.py` now ends every exit-1 and exit-5 message with
the same `verdict_code` line, written to stderr with the message (stdout is flushed first, so the
`public_key` note never lands after the verdict on a merged stream). The cross-check compares the
CODE on every row, three ways: the Elixir verifier, the Python verifier and the issuing system's
verdict. Measured before the port, the three did not agree: `V-TRUNCATED` was `signature_malformed`
in the issuing system, `signature_invalid` in the Elixir verifier (`:crypto.verify` returns false on
63 bytes), and codeless in the Python; a registry key that is not 32 bytes was exit `1`
`signature_malformed` in the Elixir verifier (OTP's raise, rescued) and would have been
`signature_invalid` in the Python; a null `entries` crashed the Elixir verifier. The rule now
applied: a signature that does not decode or is not 64 raw bytes is `signature_malformed`
everywhere; a registry `public_key` that is not 32 raw bytes is exit `5` `key_public_key_malformed`
— the taxonomy's eleventh `:trust` code — and is asked right after the fingerprint; `entries`
absent, null or not a list is `registry_missing_key`. Three rows hold the ruling: `V-KEY-MALFORMED`,
`V-NO-ENTRIES`, `V-NULL-ENTRIES`. The "ten `:trust` codes" and "thirteen" above are the 2026-09-12
counts; the taxonomy holds eleven and five.

**No input ends in a stack trace, appended 2026-11-13.** A runtime that dies on an uncaught
exception exits `1`, the code for "the receipt is bad", and writes no `verdict_code` line. Measured
over 19,000 structural mutations of the receipt and the registry (every member replaced by each
JSON type, removed or repeated, the top level replaced, numbers, strings and files of odd form),
the Python verifier did this for a registry that is not an object, for deeply nested input and for
an unpaired surrogate, and the Elixir verifier for a registry that is not an object and for a
compromised key whose `status_changed_at` is not text; the two also read some inputs differently (a repeated member name,
`NaN`, `1e999`, an unpaired surrogate, a timestamp with a trailing newline). Now every member of
the receipt, the registry, an entry and the signed bytes is read through one helper per verifier,
which answers "absent" for anything that is not an object, so a value of the wrong shape meets the
typed refusal an absent one meets (rows `V-REGISTRY-NOT-OBJECT`, `V-ENTRIES-NOT-LIST`,
`V-ENTRY-NOT-OBJECT`, `V-ENTRY-MEMBER-TYPE`, `V-RECEIPT-NOT-OBJECT`, `V-RECEIPT-FIELD-TYPE`,
`V-HASH-NOT-STRING`); every input file is read by one function per verifier, which refuses with `2`
exactly what is listed under step 1. Each verifier also ends in a last-resort guard that turns an
exception nobody foresaw into exit `2` and a one-line `internal error (<type>)` message: never `0`
and never `1`, because neither may be said of an input that could not be evaluated. The repeated
member name, the integer length and the nesting limit are refusals with the existing exit `2`; no
exit meaning and no `verdict_code` was added.

**The reading rule is one rule in three places, appended 2026-11-14.** The paragraph above made the
two verifiers read their input files alike. It left three things open, each measured on fixtures
that now sit in the corpus (the `reading` rows; the fixtures are signed by keys whose seeds are
published in `corpus/registry-reading.json`, so a row can carry a valid signature):

- *The signed bytes were read by a different rule from the files, and the issuing system by a
  third.* For a member name written twice in the signed bytes, the verifiers of the paragraph above
  read the last occurrence and the issuing system the first; the two verifiers published before it
  read one each (the Python the last, the Elixir the first). So one receipt whose signed bytes held
  `occurred_at` twice, once inside the key's signing window and once outside, was `0` to one
  reader and `5` to another, and a displayed field could agree with one occurrence while
  contradicting the other. The issuing system also read signed bytes nested deeper than 64 and
  refused an integer the verifiers read.
- *The form of a timestamp was checked and its meaning was not.* `2026-02-30T00:00:00Z`,
  `…T24:00:00Z` and `…T23:59:60Z` were read by both verifiers, as `occurred_at` and as a bound of
  the signing window, and refused by the issuing system.
- *Four smaller differences.* A `key_id` that is the empty text was looked up like any other; a
  displayed `-0.0` over a signed `0.0` was called equal by both verifiers and unequal by the
  issuing system; a registry key written as full base64 groups followed by a stray `=` was decoded
  by the Python verifier and not by the Elixir one; a registry whose `entries` is an empty list was
  `registry_missing_key` to the verifiers and `registry_not_supplied` to the issuing system. And
  the Python verifier's nesting check took time that grew with the square of the input on a string
  that never ends (six seconds for 64 KB, no answer in ten minutes for 1.5 MB), with no bound on
  the size of a file.

**The rule.** An input is read only if every implementation reads it, and reads it to the same
value. The two verifiers (`verify_receipt.py`, `verify_receipt.exs`) apply it to the receipt file,
the registry file and the signed bytes. The issuing system applies it to a chain receipt (a receipt
of its receipt chain): to the signed bytes when it judges one, the row it holds as much as the
exported form, and before it signs one; and to its registry file. It has no reader of receipt
files. It applies the rule to nothing else it signs or checks. In particular
the lab records of its execute API (an API of its evaluation environment, which a production
release does not serve), which `bin/lab-verify` hands to this verifier, are signed by
the issuing system without this rule and their chain is checked through its general JSON reader:
what their signed bytes may hold is bounded by that path's own checks, not by this rule, and a
lab record this verifier refuses under the rule is not thereby one the issuing system refused
(read in the code on 2026-11-14; no such record was built).
Where a row of this table is run on the issuing system, the test reads the fixture's file with the
issuing system's general JSON reader and hands the members to the verdict: the three-way agreement
on a DISPLAYED field rests on that reader for the displayed side, and a row whose file is not read
(`2`) is not run on the issuing system. The rule:

1. *Size.* A file larger than 1,048,576 bytes is not read (`2`), and no more than that many bytes
   plus one are taken into memory. Signed bytes cannot be larger than the file that carries them.
2. *Depth.* Arrays and objects nested more than 64 deep are not read. The check is one pass over
   the text, linear in its length whatever the text is.
3. *A repeated member name* is not read, at any depth, the names compared after their escapes are
   decoded (`"\u006fccurred_at"` is `occurred_at`). There is no first-wins and no last-wins: a
   document that says a thing twice has not said it.
4. *Numbers.* `NaN`, `Infinity` and a number beyond a double are not read; an integer written with
   more than 1024 characters, its sign included, is not read (the stricter of the limits the three
   runtimes had; it was 4300 digits in the paragraph above). A negative zero written with
   an exponent and no fraction (`-0e5`) is not read: Python's JSON reader keeps its sign (`-0.0`)
   and Erlang's drops it (`0.0`), measured on every number text of a grid of 2,688 and found for
   this form alone. Written with a fraction (`-0.0`, `-0.0e5`) every reader keeps the sign, and it
   is read.
5. *Text.* Bytes that are not UTF-8, a string holding an unpaired surrogate, and text after the
   value are not read.
6. *Instants* are the fixed form and a real calendar instant, as stated under the signing window.
7. *Base64* (the registry's key, the signature) is read only in its padded form: groups of four
   characters of the standard alphabet, the last group padded with `=` to four, nothing else.
8. *Displayed against signed.* Two numbers are the same only with the same type, value and sign:
   `-0.0` is not `0.0`, as `1` is not `1.0`.

**What each refusal is.** A FILE that is not read is `2`: nothing was measured. SIGNED BYTES that
are not read are `5`, `signed_occurred_at_unreadable`: they carry no readable `occurred_at`, the
same answer signed bytes that are not JSON at all have always had, and the message names the
cause. A repeated name in the signed bytes was considered for a code of its own and not given one:
every other way the signed bytes can be unread already answers this code, and a second code for
one member of that class would split the class. To give it one later is a taxonomy row and one
string in three places. An empty `key_id` and an empty `entries` are `registry_missing_key`; a key
in a base64 form that is not read has no readable bytes, so its fingerprint cannot match:
`key_fingerprint_mismatch`. No exit meaning and no `verdict_code` was added.

**What the rule costs, stated.** Nothing the two verifiers published before this refused is now
read: on every fixture and every probe, an input either keeps its answer or moves from "read" to
"not read". These are the inputs a published verifier answered `0` that are refused now, each
measured on the published verifiers and on these (the `reading` rows, and probes of the file
kinds):

- *In the signed bytes* (now `5`): a member name written twice (each published verifier read one
  occurrence, and not the same one); nesting beyond 64; an integer of more than 1024 characters; a
  negative zero written with an exponent and no fraction; an `occurred_at` of the right form that
  is not a calendar instant (30 February, hour 24, second 60), or one followed by a newline; and,
  answered `0` by the published Python verifier alone, a number beyond a double and an unpaired
  surrogate.
- *In the registry* (now `5`): a `valid_from` or `valid_to` of the right form that is not a
  calendar instant; and a receipt whose `key_id` is the empty text, under an entry whose `key_id`
  is the empty text.
- *Displayed against signed* (now `1`): `-0.0` displayed over a signed `0.0`, or the converse.
- *A file* (now `2`): larger than 1,048,576 bytes; nested beyond 64; holding an integer of more
  than 1024 characters, or a negative zero written with an exponent and no fraction; or repeating
  a member name (each published verifier read one occurrence: for a registry entry stating
  `status` twice, one answered `0` and the other `6`).

Which of these could be in the signed bytes of a CHAIN RECEIPT the issuing system itself issued
(its lab records are the paragraph after this list). Not the instant kinds: it stamps
`occurred_at` from its own clock. Not a number beyond a double: its runtime has none. Not the
negative zero with an exponent: canonical versions 2 and 3, the forms of its chain receipts, write every float with a
fraction. Since the change of 2026-11-16 the issuing system signs no float: it refuses one by name
(`float_refused`) at every door that signs or hashes into signed bytes, and canonical version 4 refuses a float
itself; a chain receipt signed before that change may hold a float, in the form versions 2 and 3 write. Three kinds
could:

- *A member name written twice*, before 2026-09-16. Since that date its encoder refuses an object
  whose keys normalise to one name (`ambiguous_key`); before it, the encoder could write one name
  twice only for a record holding the same key once as an atom and once as text.
- *Nesting beyond 64* and *an integer of more than 1024 characters*, until this change, for a
  caller that handed such metadata to the append of a chain receipt. A chain receipt's signed
  bytes have been bounded at 4096 bytes since 2026-10-22 and had no such bound before.

Such a chain receipt is now `5` in both verifiers. What the issuing system's own verdict does with
the ROW it holds differs by kind. No row of any of the three kinds was stored and judged by the
issuing system's own code; the pieces were measured apart, as each item says:

- *Nested beyond 64.* The row can be read back: the database and the reader that loads the row
  keep the nesting (measured to a depth of 70). The verdict, measured on a receipt built in
  memory, is now `signed_occurred_at_unreadable`; until this change it was "verified".
- *An integer of more than 1024 characters.* The row cannot be read back. The database keeps every
  digit, and the reader that loads the row refuses an integer that long with an error (measured
  on the database driver and its JSON reader: 1024 digits are read, 1025 raise). So the issuing
  system reaches no verdict on such a row, "verified" or any other, before this change or after
  it: a query that loads the row fails. What this change adds is that the append of a chain
  receipt no longer signs such bytes.
- *A member name written twice.* The row holds one value per name (measured: the database keeps
  the last), so the bytes rebuilt from the row lack the repeat and do not hash to the receipt's
  hash. Such a receipt was not "verified" on this path before this change and is not after it
  (the verdict on it read in the code, not run).

None of the three is known. No production database was searched for one.

A LAB RECORD of the execute API is not covered by the list above ("The rule": the issuing system
does not apply this rule to it). Read in the code of its builder on 2026-11-14: its metadata may
hold text, integers within plus or minus 2^53 - 1, booleans, null, lists and objects with text
names, so it cannot hold an integer of more than 1024 characters, any float (refused by name, `float_refused`, since
the change of 2026-11-16), or one name twice;
its instant is the clock's or a calendar instant the builder passes. That check does not bound
NESTING. As far as the code reads, the builder would still sign a lab record nested beyond 64
today (whether any caller of the builder can hand it one was not examined): this verifier answers
`5` for such signed bytes (the row V-SIGNED-NESTED-65), and the issuing system's own check of the
lab chain, which reads the bytes with its general JSON reader, does not refuse them. No such
record was built, and none is known.

**Why 1024, 64 and 1,048,576.** 1024 is the limit the issuing system's general JSON reader has on
an integer token, and the rule takes the stricter side. 64 is the depth the paragraph above set.
1,048,576 bytes is far above any file in this corpus (the largest is under 8 KB), and the issuing
system bounds the signed bytes of a chain receipt at 4096 bytes. Its append of a chain receipt also
refuses to sign bytes this rule does not read (a record nested beyond 64, or holding an integer of
more than 1024 characters), so a chain receipt appended since this change is one that it, and
either verifier, reads. That sentence is about the append of a chain receipt and no other signing
path of the issuing system.
