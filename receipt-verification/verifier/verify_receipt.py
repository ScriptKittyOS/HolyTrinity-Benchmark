#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""verify_receipt.py — check a Trinity authority receipt's Ed25519 signature.

    python3 verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json
        [--checkpoint NOTE --inclusion-proof PROOF.json --witness-policy POLICY
         [--held-size N --held-root ROOT | --held-state FILE [--write-held-state]]
         [--consistency-proof PROOF.json] [--key-transition RECORD.json]]

Python standard library only. No pip installs, no network. Tested with Python 3.11 and 3.12.

This is the SECOND, INDEPENDENT implementation. verify_receipt.exs is the reference. Two
implementations exist so an examiner who distrusts one can run the other, and so neither can drift
unnoticed — a shared corpus is run through both in CI and their verdicts must agree.

EXIT CODES AND EVERY VERDICT CASE ARE DEFINED IN ONE PLACE: VERDICTS.md, beside this file. It is
the single source, it is parsed by the cross-check test, and this header cites it rather than
restating it. Four copies of one rule is how the copies drift.

The numbers are frozen at 0, 1, 2, 5, 6 and no others may be introduced; 0, 1, 2 and 6 are this
project's proposal and are PROVISIONAL. The one distinction to
carry in your head while reading the code below: `1` accuses the receipt, `5` declines to judge it,
and collapsing them tells an examiner a receipt was forged when it was merely unverifiable.

PATTERN CREDIT — default-distrust posture, refusal with a distinct code when signer trust is not
established from bundle-local key material, flaws disclosed unprompted:

    Nathan Howard (Third Level IT / thirdlevel.ai)
    VIRP verifier, v0.1.0
    https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier

HAND-ROLLED CRYPTO, DECLARED. The Ed25519 verification below is the RFC 8032 section 6 reference
construction, written out because Python's standard library has no Ed25519 and requiring a package
would break the no-installs property this file exists to provide. It is a NAMED EXCEPTION to the
rule against second implementations, and the exception is bounded by the cross-check corpus: this
file and verify_receipt.exs must agree on every case, including known-bad signatures, wrong keys
and truncated input. Verification only — this file never signs anything.

STRICT VERIFICATION. Before it computes the Ed25519 equation (RFC 8032 section 5.1.7) this file
refuses: a non-canonical encoding of the public key A or of R, an A or R of small order, an A of
mixed order, and an S that is not below L (see `_refusal`). Without these refusals the identity
key (01 00 .. 00) verifies R = [S]B for every message, so a signature under it proves nothing.
VERDICTS.md states the rule and its verdict. Scalar multiplication is in extended coordinates
(RFC 8032 section 5.1.4), with one inversion at the end.

THE RULE THIS FILE BOUNDS — the verifier-primitive rule (stated 2026-09-20). Nothing a
stranger is asked to check may
require a primitive this file cannot compute from the standard library: SHA-2/SHA-3/SHAKE, the
hand-written Ed25519 above, hash-based signatures. ML-DSA, BLS, pairing-based proofs, X.509 and
ECDSA are OUT — a construction that "gives the verifier X" adds a verification domain to a file
whose one stated exception is Ed25519. The import list below is the whole of what this file may
reach, and the cross-check test pins it exactly.

VERDICT CODES. Every exit-1 and exit-5 message this file writes ends with a line
`verdict_code: <code>`, the same code verify_receipt.exs and the issuing system name for that
input, written to STDERR with the message. The cross-check test compares the codes, not only the
exits, on every corpus row. Exit 0, 2 and 6 carry no code.

LOG CHECKPOINTS. With --checkpoint, a receipt that VERIFIED is also checked against a checkpoint of
the evaluation environment's transparency log: its inclusion under a checkpoint signed by the log key
and cosigned by the witnesses the relying party's policy names, and that the checkpoint is not older
than the tree the relying party holds. CHECKPOINTS.md, beside this file, states the checks, the
inputs, every refusal and what is not checked; the code is the section of that name below.

NO INPUT ENDS IN A STACK TRACE. A runtime that dies on an uncaught exception exits 1, which
VERDICTS.md reserves for "the receipt is bad", and writes no code line. So every named member of the
receipt and of the registry is read through `member`, which answers None for anything that is not
an object, and every input file is read through `parse_json`, which refuses (exit 2, "cannot read
input") what verify_receipt.exs refuses. A last-resort guard at the bottom of this file turns an
exception nobody foresaw into exit 2 with a one-line message, never into 0 or 1.
"""

import base64
import hashlib
import json
import re
import sys

# THE READING RULE. One rule, stated in VERDICTS.md ("how an input is read") and applied by this
# file, by verify_receipt.exs and by the issuing system: what one of them reads, all three read, to
# the same value; what one refuses, all three refuse. The three numbers below are that rule's.
#
# The largest input file that is read, in bytes. A larger file is refused (exit 2) before it is
# parsed, and no more than this many bytes plus one are ever taken into memory.
MAX_INPUT_BYTES = 1048576
# A number is read as a JSON number, which has no NaN, no Infinity and no value beyond a double. An
# integer written with more characters than this, its sign included, is not read: the issuing
# system's JSON reader refuses it, and so do both verifiers.
MAX_INTEGER_CHARACTERS = 1024
# The deepest nesting of arrays and objects that is read. Python's own recursion limit would
# otherwise decide, and decide differently from the other runtimes.
MAX_DEPTH = 64

EXIT_VERIFIED, EXIT_INVALID, EXIT_USAGE, EXIT_NO_TRUST, EXIT_COMPROMISED = 0, 1, 2, 5, 6

# --- RFC 8032 Ed25519 verification -------------------------------------------------------------
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = 4 * _inv(5)
B = [_xrecover(BY) % P, BY % P]


def _edwards(a, b):
    x1, y1 = a
    x2, y2 = b
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return [x3 % P, y3 % P]


def _ext_add(p, q):
    """Unified addition in extended coordinates (X, Y, Z, T), RFC 8032 section 5.1.4: no inversion."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, e):
    """[e]point, as an affine [x, y]: double-and-add in extended coordinates, one inversion at the end."""
    result = (0, 1, 1, 0)
    addend = (point[0], point[1], 1, point[0] * point[1] % P)
    while e > 0:
        if e & 1:
            result = _ext_add(result, addend)
        addend = _ext_add(addend, addend)
        e >>= 1
    zi = _inv(result[2])
    return [result[0] * zi % P, result[1] * zi % P]


def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decode_point(raw):
    """Decode a point as RFC 8032 section 5.1.3 requires, and no more leniently. Raises ValueError,
    beginning with the refusal's identifier, for: y >= p (`ed25519_non_canonical`), x = 0 with the
    sign bit set (`ed25519_non_canonical`), and no point on the curve for that y
    (`ed25519_not_on_curve`). The verdict is the same for all of them (see ed25519_verify)."""
    n = int.from_bytes(raw, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("ed25519_non_canonical: y >= p")
    x = _xrecover(y)
    point = [x, y]
    if not _on_curve(point):
        raise ValueError("ed25519_not_on_curve")
    if x == 0 and sign == 1:
        raise ValueError("ed25519_non_canonical: x = 0 with the sign bit set")
    if x & 1 != sign:
        point[0] = P - x
    return point


def _small_order(point):
    """True when [8]P is the identity: the point lies in the torsion subgroup of order 8. Decided by
    arithmetic (three doublings), never by a list of encodings."""
    for _ in range(3):
        point = _edwards(point, point)
    return point == [0, 1]


def _prime_order(point):
    """True when [L]P is the identity: P lies in the prime-order subgroup (no torsion component)."""
    return _scalarmult(point, Q) == [0, 1]


def _refusal(signature, public_key):
    """The identifier of the first reason `signature` / `public_key` is refused before the equation
    is computed, or None. A signature that is not 64 bytes or a key that is not 32 is refused as
    non-canonical, never raised. The identifiers:

      ed25519_non_canonical  A or R is not a canonical encoding (y >= p; x = 0 with the sign bit
                             set), or S >= L
      ed25519_not_on_curve   A or R is not a point
      ed25519_small_order    A or R is of small order: [8]P is the identity (decided by
                             arithmetic, never by a list of encodings)
      ed25519_mixed_order    A is not in the prime-order subgroup: [L]A is not the identity (A is
                             a multiple of B plus a point of small order). Such a key is refused
                             because implementations that reduce h modulo L and ones that do not
                             can otherwise disagree about the same signature, depending on h mod 8.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return "ed25519_non_canonical"
    try:
        r = _decode_point(signature[:32])
        a = _decode_point(public_key)
    except ValueError as refusal:
        return str(refusal).split(":")[0]
    if _small_order(a) or _small_order(r):
        return "ed25519_small_order"
    if not _prime_order(a):
        return "ed25519_mixed_order"
    if int.from_bytes(signature[32:], "little") >= Q:
        return "ed25519_non_canonical"
    return None


def ed25519_verify(signature, message, public_key):
    """True when `signature` is a valid Ed25519 signature over `message` under `public_key`.

    Refuses, with False and before the equation, whatever `_refusal` names: a non-canonical
    encoding of A or R, A of small order (under the identity key every R = [S]B verifies for every
    message), R of small order, S >= L, A not in the prime-order subgroup. The verdict for all of
    them is `signature_invalid`.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    if _refusal(signature, public_key) is not None:
        return False
    r = _decode_point(signature[:32])
    a = _decode_point(public_key)
    s = int.from_bytes(signature[32:], "little")
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _scalarmult(B, s) == _edwards(r, _scalarmult(a, h))


# --- verdicts ------------------------------------------------------------------------------------
# Order, and the whole of it, is VERDICTS.md's "the order the checks run in". Every trust question
# (exit 5) but the signing window precedes every accusation (exit 1), because an accusation requires
# standing. The compromised verdict (6) and the signing-window check come after the signature check,
# so only a receipt whose signature verified reaches them.
STATUSES = ("example", "active", "retired", "compromised")
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
IGNORED = ("public_key", "_note")
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def member(obj, name):
    """`obj[name]` when `obj` is a JSON object, and None for anything else (a list, a string, a
    number, null, a missing member). Every read of a named member of the receipt, the registry, a
    registry entry or the signed bytes goes through here, so a value of the wrong shape is an absent
    value and meets the same typed refusal an absent value meets. (The displayed-field check walks
    the receipt's own members, of two values already known to be objects; the note on exit 0 asks
    only whether the signed bytes, already known to be an object, carry sequence and
    previous_hash.)"""
    return obj.get(name) if isinstance(obj, dict) else None


def shown(value):
    """A value for a message: itself when it is text, otherwise a fixed phrase (never a repr of
    something the registry or the receipt chose the shape of)."""
    return value if isinstance(value, str) else "an unstated instant"


_SURROGATE = re.compile("[\ud800-\udfff]")


def _too_deep(text):
    """True when arrays and objects nest more than MAX_DEPTH deep, outside strings.

    ONE pass over the characters, with two flags: inside a string, and after a backslash inside a
    string. The time is linear in the length of the text whatever the text is; in particular a
    string that never ends is walked once, to the end of the text. A document that is not JSON may
    be counted wrongly here; it is then refused by the parser all the same."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "[" or char == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif char == "]" or char == "}":
            depth -= 1
    return False


def _object(pairs):
    seen = {}
    for name, value in pairs:
        if name in seen:
            raise ValueError("an object repeats the member name %r" % name)
        seen[name] = value
    return seen


def _constant(name):
    raise ValueError("%s is not a JSON number" % name)


def _integer(text):
    if len(text) > MAX_INTEGER_CHARACTERS:
        raise ValueError("an integer of more than %d characters" % MAX_INTEGER_CHARACTERS)
    return int(text)


def _float(text):
    # A negative zero written with an exponent and no fraction (`-0e5`). This reader keeps the
    # sign (-0.0); Erlang's reader, under verify_receipt.exs and the issuing system, drops it
    # (0.0). A text that two runtimes read to two values is not read. Written with a fraction
    # (`-0.0`, `-0.0e5`) every reader keeps the sign, and it is read.
    if text[:2] == "-0" and text[2:3] in ("e", "E"):
        raise ValueError("a negative zero written with an exponent and no fraction (%s)" % text)
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("a number beyond the range of a double")
    return value


def parse_json(text):
    """The JSON value in `text`, or ValueError. Stricter than `json.loads` in exactly the ways
    verify_receipt.exs and the issuing system are: NaN, Infinity and numbers beyond a double are
    refused, and so is a negative zero written with an exponent and no fraction (`-0e5`: the two
    runtimes read it to two values); an object that repeats a member name is refused, at every
    depth, the names compared
    after their escapes are decoded (one JSON reader keeps the first occurrence and another the
    last, so a repeated name is two documents in one); an integer of more than
    MAX_INTEGER_CHARACTERS characters is refused; a string holding an unpaired surrogate is
    refused; and nesting deeper than MAX_DEPTH is refused. The input files AND the signed bytes are
    read through here: there is one rule and no exception to it."""
    if _too_deep(text):
        raise ValueError("nested more than %d levels deep" % MAX_DEPTH)
    value = json.loads(
        text,
        object_pairs_hook=_object,
        parse_constant=_constant,
        parse_int=_integer,
        parse_float=_float,
    )
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item):
                raise ValueError("a string holds an unpaired surrogate")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            for name, inner in item.items():
                if _SURROGATE.search(name):
                    raise ValueError("a member name holds an unpaired surrogate")
                stack.append(inner)
    return value


def read_json(path):
    # a bounded read: a file larger than the bound is never taken into memory whole
    with open(path, "rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("%s is larger than %d bytes" % (path, MAX_INPUT_BYTES))
    return parse_json(raw.decode("utf-8"))


def die(code, message, stream=sys.stderr, verdict_code=None):
    # stdout first: the public_key note is block-buffered on a pipe and would otherwise land
    # AFTER the verdict when a caller merges the streams
    sys.stdout.flush()
    if verdict_code is not None:
        message = message + "\n\nverdict_code: " + verdict_code
    print(message, file=stream)
    stream.flush()
    sys.exit(code)


# Base64 as verify_receipt.exs and the issuing system read it: groups of four characters of the
# standard alphabet, the last group padded with `=` to four, and nothing else. Python's decoder
# alone also takes a full group followed by stray `=`; the form is checked here, so that decoder
# does not decide.
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


def b64(value):
    if not _BASE64.match(value):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def timestamp(value):
    """The instant, as a comparable tuple, or None when the form is not the accepted one.

    Only `YYYY-MM-DDTHH:MM:SSZ` is accepted. A verifier that accepts two spellings of an instant is
    a verifier whose two implementations eventually disagree about one of them, and the disagreement
    surfaces first on a real receipt rather than in the corpus. Not coerced, not guessed: refused.

    The form alone is not enough: the text must also be a real instant of the proleptic Gregorian
    calendar. Month 01 to 12, a day that month has in that year (year 0000 is a leap year), hour 00
    to 23, minute and second 00 to 59; there is no leap second and no 24:00:00. `2026-02-30` has
    the form, and comparing it as text would place it between two real days. The arithmetic is
    written out, the same in verify_receipt.exs, so no library decides.
    """
    if not isinstance(value, str) or not TS.match(value):
        return None
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    if month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59:
        return None
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    if day < 1 or day > days:
        return None
    return (value[0:4], value[5:7], value[8:10], value[11:13], value[14:16], value[17:19])


def tagged(value):
    """Type-tagged form, so equality never merges an int with a float or a bool with 1.

    VERDICTS.md's canonical encoding never merges integers and floats; Python's `==` does, and
    `True == 1` as well. Comparing untagged would make a contradiction invisible on exactly the
    values an adversary would choose. A float is compared by its exact value AND its sign, so
    `-0.0` displayed over a signed `0.0` is a contradiction (`==` calls them equal).
    """
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value.hex())
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, list):
        return ("list", [tagged(v) for v in value])
    if isinstance(value, dict):
        return ("object", sorted((k, tagged(v)) for k, v in value.items()))
    return ("other", repr(value))


# --- THE LOG CHECKPOINT CHECKS (CHECKPOINTS.md, beside this file) --------------------------------
# Run only when --checkpoint is given, and only after the receipt itself VERIFIED (exit 0): an
# answer about the log needs a receipt whose signature checked out. Three checks, in this order:
#
#   (1) INCLUSION. The relying party's witness policy (--witness-policy, its own file; the format of
#       C2SP tlog-witness policies: "log <vkey>", "witness <name> <vkey>", "group <name> <N|any|all>
#       <member>...", "quorum <name|none>") names the log key and the witnesses. The checkpoint
#       (--checkpoint, a C2SP signed note) must carry a verifying line of every log key, under the
#       note's own origin, and cosignatures (C2SP tlog-cosignature, Ed25519 type 0x04) that meet the
#       policy's quorum. The receipt's leaf, "requisition.lab.log.leaf.v1\n" || u32be(|P|) || P ||
#       u16be(|S|) || S || u16be(|C|) || C (P the signed bytes, S the signature, C the co-signature,
#       empty when absent), must be included under the checkpoint's SHA-256 root by the RFC 9162
#       inclusion proof given (--inclusion-proof).
#   (2) CONSISTENCY and (3) NOT OLDER THAN THE HELD SIZE. The relying party passes the largest tree
#       size it already holds and that tree's root (--held-size and --held-root, or a held-state
#       file it keeps, --held-state). A checkpoint smaller than that is refused
#       (checkpoint_older_than_held); one of that size with another root is refused
#       (checkpoint_split_view_at_held_size); a larger one needs an RFC 9162 consistency proof from
#       the held tree (--consistency-proof) that verifies. This proves membership and append-only
#       growth between the trees the relying party holds and the checkpoint given, no more: that
#       no larger tree exists is not something a checkpoint can show.
#
# A key change of the log is followed only through the log's own signed key-transition record
# (--key-transition): the old key, named in the policy, endorses the new one. Every refusal exits 5
# (TRUST NOT ESTABLISHED): the receipt's signature checked out, and what is not established is the
# log's account of it. A witness key of type 0x06 (ML-DSA-44) is refused by name: ML-DSA is outside
# the primitives this file computes (THE RULE THIS FILE BOUNDS, above).

CHECKPOINT_FLAGS = ("--checkpoint", "--inclusion-proof", "--witness-policy", "--held-size", "--held-root",
                    "--consistency-proof", "--key-transition", "--held-state")
CHECKPOINT_LEAF_TAG = b"requisition.lab.log.leaf.v1\n"
CHECKPOINT_TRANSITION_TYPE = "requisition.lab.log.key_transition.v0"
_CHECKPOINT_DECIMAL = re.compile(r"(0|[1-9][0-9]{0,17})\Z")
_CHECKPOINT_THRESHOLD = re.compile(r"[+-]?[0-9]+\Z")
_CHECKPOINT_HEX4 = re.compile(r"[0-9a-f]{8}\Z")


class CheckpointRefused(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class CheckpointUsage(Exception):
    pass


def _cp_b64(value):
    """Canonical base64 only: the text must be what encoding its bytes gives back."""
    raw = b64(value) if isinstance(value, str) else None
    if raw is None or base64.b64encode(raw).decode("ascii") != value:
        return None
    return raw


def _cp_hash(data):
    return hashlib.sha256(data).digest()


def _cp_node(left, right):
    return _cp_hash(b"\x01" + left + right)


def checkpoint_key_id(name, key_type, public):
    """C2SP signed-note's key ID: SHA-256(name || 0x0A || type || public key)[:4]."""
    return _cp_hash(name.encode("utf-8") + b"\n" + key_type + public)[:4]


def checkpoint_vkey(text):
    """A C2SP vkey <name>+<hex key id>+<base64(type || public key)>, as a dict, or None."""
    parts = text.split("+", 2)
    if len(parts) != 3 or parts[0] == "" or not _CHECKPOINT_HEX4.match(parts[1]):
        return None
    blob = _cp_b64(parts[2])
    if blob is None:
        return None
    if blob[:1] == b"\x01" and len(blob) == 33:
        kind = "ed25519"
    elif blob[:1] == b"\x04" and len(blob) == 33:
        kind = "cosig_ed25519"
    elif blob[:1] == b"\x06" and len(blob) == 1313:
        kind = "cosig_mldsa44"
    else:
        return None
    name, key_id, public = parts[0], bytes.fromhex(parts[1]), blob[1:]
    if checkpoint_key_id(name, blob[:1], public) != key_id:
        return None
    return {"name": name, "id": key_id, "kind": kind, "public": public}


def checkpoint_policy(raw):
    """The relying party's witness policy, read as the lab reads one (its WitnessPolicy, verify
    mode), and requiring at least one log line. CheckpointUsage on a policy that does not read;
    CheckpointRefused (checkpoint_algorithm_unsupported) on a witness this file cannot check."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckpointUsage("the witness policy is not UTF-8")
    logs, witnesses, components, quorum = [], [], {}, None
    for number, line in enumerate(text.split("\n"), 1):
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        word = fields[0]
        if word == "log" and len(fields) >= 2:
            key = checkpoint_vkey(fields[1])
            if key is None or key["kind"] != "ed25519":
                raise CheckpointUsage("the witness policy, line %d: not an Ed25519 log vkey" % number)
            logs.append(key)
        elif word == "witness" and len(fields) >= 3:
            if fields[1] in components:
                raise CheckpointUsage("the witness policy, line %d: the name %r is taken" % (number, fields[1]))
            key = checkpoint_vkey(fields[2])
            if key is None or key["kind"] not in ("cosig_ed25519", "cosig_mldsa44"):
                raise CheckpointUsage("the witness policy, line %d: not a witness cosigner vkey" % number)
            components[fields[1]] = ("witness", key)
            witnesses.append(key)
        elif word == "group" and len(fields) >= 4:
            name, threshold, members = fields[1], fields[2], fields[3:]
            if name in components:
                raise CheckpointUsage("the witness policy, line %d: the name %r is taken" % (number, name))
            if threshold == "any":
                count = 1
            elif threshold == "all":
                count = len(members)
            elif _CHECKPOINT_THRESHOLD.match(threshold) and 1 <= int(threshold) <= len(members):
                count = int(threshold)
            else:
                raise CheckpointUsage("the witness policy, line %d: the threshold %r" % (number, threshold))
            if any(member not in components for member in members):
                raise CheckpointUsage("the witness policy, line %d: a member is not defined above it" % number)
            components[name] = ("group", count, members)
        elif word == "quorum" and len(fields) >= 2:
            if quorum is not None:
                raise CheckpointUsage("the witness policy, line %d: a second quorum line" % number)
            quorum = fields[1]
        else:
            raise CheckpointUsage("the witness policy, line %d: not a policy line" % number)
    if quorum is None:
        raise CheckpointUsage("the witness policy has no quorum line")
    if quorum != "none" and quorum not in components:
        raise CheckpointUsage("the witness policy's quorum %r is not defined" % quorum)
    if not logs:
        raise CheckpointUsage("the witness policy has no log line: the log key is the relying party's to name")
    unsupported = [key["name"] for key in witnesses if key["kind"] == "cosig_mldsa44"]
    if unsupported:
        raise CheckpointRefused(
            "checkpoint_algorithm_unsupported",
            "the witness policy names ML-DSA-44 (type 0x06) witness key(s) %s; this verifier computes Ed25519 only"
            % ", ".join(sorted(unsupported)))
    return {"logs": logs, "witnesses": witnesses, "components": components, "quorum": quorum}


def checkpoint_note(raw):
    """A C2SP signed note carrying a checkpoint: (text, origin, size, SHA-256 root, [(name, raw)])."""
    try:
        note = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckpointRefused("checkpoint_note_malformed", "the checkpoint is not UTF-8")
    if any(ord(ch) < 0x20 and ch != "\n" for ch in note) or "\x7f" in note:
        raise CheckpointRefused("checkpoint_note_malformed", "the checkpoint carries a control character")
    split = note.rfind("\n\n")
    if split < 0 or not note.endswith("\n"):
        raise CheckpointRefused("checkpoint_note_malformed", "no blank line between the text and the signatures")
    text, block = note[: split + 1], note[split + 2:]
    lines = block.split("\n")[:-1]
    if not lines or len(lines) > 16:
        raise CheckpointRefused("checkpoint_note_malformed", "%d signature lines (1 to 16)" % len(lines))
    signatures, seen = [], set()
    for line in lines:
        parts = line[2:].split(" ") if line.startswith("— ") else []
        signature = _cp_b64(parts[1]) if len(parts) == 2 and parts[0] != "" else None
        if signature is None or len(signature) < 5:
            raise CheckpointRefused("checkpoint_note_malformed", "a signature line is not '— <name> <base64>'")
        if (parts[0], signature[:4]) in seen:
            raise CheckpointRefused("checkpoint_note_malformed", "two signature lines of one name and key")
        seen.add((parts[0], signature[:4]))
        signatures.append((parts[0], signature))
    rows = text[:-1].split("\n")
    if len(rows) < 3 or "" in rows or not _CHECKPOINT_DECIMAL.match(rows[1]):
        raise CheckpointRefused("checkpoint_note_malformed", "the text is not origin, decimal size, root")
    root = _cp_b64(rows[2])
    if root is None or len(root) != 32:
        raise CheckpointRefused("checkpoint_note_malformed", "the root line is not a base64 SHA-256 hash")
    return {"text": text, "origin": rows[0], "size": int(rows[1]), "root": root, "signatures": signatures}


def checkpoint_transition(record, origin, logs):
    """The new log key a key-transition record names, when its signed metadata carries the old key's
    endorsement and the old key is one of the policy's log keys: (old key, new key)."""
    try:
        signed = parse_json(record["signed_payload"])
        meta = signed["metadata"]
        previous, new = _cp_b64(meta["previous_public_key"]), _cp_b64(meta["new_public_key"])
        endorsement = _cp_b64(meta["endorsement"])
        size, root = meta["previous_checkpoint_size"], meta["previous_checkpoint_root_sha256"]
        point = _cp_b64(root) if isinstance(root, str) else None
        usable = (signed["receipt_type"] == CHECKPOINT_TRANSITION_TYPE and meta["origin"] == origin
                  and None not in (previous, new, endorsement, point) and len(new) == 32 and len(point) == 32
                  and isinstance(size, int) and not isinstance(size, bool) and size >= 0)
    except (KeyError, TypeError, ValueError):
        usable = False
    if not usable:
        raise CheckpointRefused("checkpoint_transition_unendorsed",
                                "the key-transition record does not name this log's origin, both keys and an endorsement")
    old = [key for key in logs if key["public"] == previous and key["name"] == origin]
    message = (b"\x00" + ("%s\n%s\n%d\n%s\n" % (CHECKPOINT_TRANSITION_TYPE, origin, size, root)).encode("utf-8")
               + base64.b64encode(new) + b"\n")
    if not old or not ed25519_verify(endorsement, message, previous):
        raise CheckpointRefused("checkpoint_transition_unendorsed",
                                "the key change is not endorsed by a log key the witness policy names")
    return old[0], {"name": origin, "id": checkpoint_key_id(origin, b"\x01", new), "kind": "ed25519",
                    "public": new, "size": size, "root": point}


def _cp_cosignature(key, text, raw):
    """A type 0x04 checkpoint cosignature (C2SP tlog-cosignature): key id || u64be time || Ed25519
    over "cosignature/v1\\ntime <t>\\n" || the note text."""
    if len(raw) != 4 + 8 + 64:
        return False
    time = int.from_bytes(raw[4:12], "big")
    if time > 2 ** 63 - 1:
        return False
    message = ("cosignature/v1\ntime %d\n" % time).encode("utf-8") + text.encode("utf-8")
    return ed25519_verify(raw[12:], message, key["public"])


def _cp_satisfied(policy, name, signers):
    component = policy["components"][name]
    if component[0] == "witness":
        return (component[1]["name"], component[1]["id"]) in signers
    return sum(1 for member in component[2] if _cp_satisfied(policy, member, signers)) >= component[1]


def checkpoint_cosigned(policy, note, logs):
    """The policy's judgement of the note, as the lab's WitnessPolicy.verify_cosigned makes it: every
    line of a known key verifies and at least one does; every log key carries the note's origin as its
    name and signed it; the cosigners meet the quorum. `logs` are the log keys that must have signed.
    The list of the cosigners (key dicts), in note order."""
    keys = logs + policy["witnesses"]
    verified = []
    for name, raw in note["signatures"]:
        key = next((k for k in keys if k["name"] == name and k["id"] == raw[:4]), None)
        if key is None:
            continue
        if key["kind"] == "ed25519":
            ok = ed25519_verify(raw[4:], note["text"].encode("utf-8"), key["public"])
        else:
            ok = _cp_cosignature(key, note["text"], raw)
        if not ok:
            raise CheckpointRefused("checkpoint_signature_invalid",
                                    "the line of %s (key %s) does not verify" % (name, raw[:4].hex()))
        verified.append(key)
    if not verified:
        raise CheckpointRefused("checkpoint_no_trusted_signature",
                                "no line of the checkpoint is by a key the witness policy names")
    if any(key["name"] != note["origin"] for key in logs):
        raise CheckpointRefused("checkpoint_origin_mismatch",
                                "the checkpoint is for origin %r, not the log the witness policy names" % note["origin"])
    if any(key not in verified for key in logs):
        raise CheckpointRefused("checkpoint_no_trusted_signature",
                                "the log key the witness policy names did not sign the checkpoint")
    cosigners = [key for key in verified if key["kind"] != "ed25519"]
    if policy["quorum"] != "none" and not _cp_satisfied(
            policy, policy["quorum"], {(key["name"], key["id"]) for key in cosigners}):
        raise CheckpointRefused("checkpoint_quorum_not_met",
                                "the witness quorum %r is not met; cosigned by: %s" % (
                                    policy["quorum"], ", ".join(key["name"] for key in cosigners) or "no witness"))
    return cosigners


def checkpoint_leaf(receipt):
    """The receipt's leaf in the lab's log, or CheckpointRefused (checkpoint_leaf_malformed)."""
    payload = receipt["signed_payload"].encode("utf-8")
    signature = _cp_b64(receipt["signature"])
    cosignature = member(receipt, "cosignature")
    if isinstance(cosignature, dict):
        cosignature = member(cosignature, "signature")
    co = b"" if cosignature is None else _cp_b64(cosignature)
    if signature is None or co is None or len(signature) >= 65536 or len(co) >= 65536:
        raise CheckpointRefused("checkpoint_leaf_malformed",
                                "the receipt's signature or co-signature is not canonical base64 under 65,536 bytes")
    return (CHECKPOINT_LEAF_TAG + len(payload).to_bytes(4, "big") + payload + len(signature).to_bytes(2, "big")
            + signature + len(co).to_bytes(2, "big") + co)


def _cp_proof(document, sizes):
    """The proof hashes of a proof document whose hash is sha256 and whose sizes are `sizes`."""
    if not isinstance(document, dict) or member(document, "hash") not in (None, "sha256"):
        raise CheckpointRefused("checkpoint_proof_malformed", "a proof that is not an object over the SHA-256 tree")
    for name, value in sizes.items():
        found = member(document, name)
        if not isinstance(found, int) or isinstance(found, bool) or found != value:
            raise CheckpointRefused("checkpoint_proof_malformed", "the proof's %s is %r, not %d" % (name, found, value))
    hashes = member(document, "proof")
    out = [_cp_b64(h) for h in hashes] if isinstance(hashes, list) else None
    if out is None or any(h is None or len(h) != 32 for h in out):
        raise CheckpointRefused("checkpoint_proof_malformed", "the proof is not a list of base64 SHA-256 hashes")
    return out


def checkpoint_verify_inclusion(leaf_hash, index, size, proof, root):
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _cp_node(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _cp_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def checkpoint_verify_consistency(first, second, proof, first_root, second_root):
    """RFC 9162 section 2.1.4.2, for 0 < first < second."""
    if not 0 < first < second or not proof:
        return False
    path = [first_root] + proof if first & (first - 1) == 0 else list(proof)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _cp_node(c, fr), _cp_node(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _cp_node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def checkpoint_check(receipt, inputs):
    """The three checks over the inputs read by main (raw bytes and JSON values); the lines a pass
    prints, or CheckpointRefused / CheckpointUsage."""
    policy = checkpoint_policy(inputs["witness-policy"])
    note = checkpoint_note(inputs["checkpoint"])
    logs, lines, new = list(policy["logs"]), [], None
    if "key-transition" in inputs:
        old, new = checkpoint_transition(inputs["key-transition"], note["origin"], logs)
        logs = [new if key is old else key for key in logs]
        lines.append("key transition at size %d: the log key %s endorsed the key %s"
                     % (new["size"], old["id"].hex(), new["id"].hex()))
    cosigners = checkpoint_cosigned(policy, note, logs)
    lines = ["origin %s, size %d, root sha256 %s" % (note["origin"], note["size"],
                                                     base64.b64encode(note["root"]).decode("ascii"))] + lines
    lines += ["signed by the log key %s+%s" % (key["name"], key["id"].hex()) for key in logs]
    lines.append("witness quorum %s met; cosigned by %s" % (
        policy["quorum"], ", ".join("%s (key %s)" % (k["name"], k["id"].hex()) for k in cosigners) or "no witness"))
    document = inputs["inclusion-proof"]
    index = member(document, "leaf_index") if isinstance(document, dict) else None
    if not isinstance(index, int) or isinstance(index, bool):
        raise CheckpointRefused("checkpoint_proof_malformed", "the inclusion proof has no integer leaf_index")
    proof = _cp_proof(document, {"tree_size": note["size"]})
    leaf_hash = _cp_hash(b"\x00" + checkpoint_leaf(receipt))
    stated = member(document, "leaf_hash")
    if stated is not None and _cp_b64(stated) != leaf_hash:
        raise CheckpointRefused("checkpoint_inclusion_invalid", "the proof's leaf_hash is not this receipt's leaf")
    if not checkpoint_verify_inclusion(leaf_hash, index, note["size"], proof, note["root"]):
        raise CheckpointRefused("checkpoint_inclusion_invalid",
                                "the receipt is not leaf %d of the tree of size %d" % (index, note["size"]))
    lines.append("the receipt is leaf %d of %d (RFC 9162 inclusion proof, SHA-256)" % (index, note["size"]))
    held = inputs.get("held")
    if held is not None and held[2] is not None and held[2] != note["origin"]:
        raise CheckpointUsage("the held-state file is for the log %r, not %r" % (held[2], note["origin"]))
    if new is not None:
        # the new key signs only checkpoints at or after the point the old key endorsed it at, and at that point the
        # endorsed root; a held tree older than that point is checked from it
        if note["size"] < new["size"]:
            raise CheckpointRefused("checkpoint_before_transition",
                                    "the checkpoint's size %d is below the key transition's size %d"
                                    % (note["size"], new["size"]))
        if note["size"] == new["size"] and note["root"] != new["root"]:
            raise CheckpointRefused("checkpoint_transition_root_mismatch",
                                    "size %d: the checkpoint's root is not the root the key transition names" % new["size"])
        if held is not None and held[0] < new["size"]:
            lines.append("held size %d is below the key transition at size %d: checked from the transition point"
                         % (held[0], new["size"]))
            held = (new["size"], new["root"], held[2])
    if held is None:
        lines.append("%s: a checkpoint older than a size the relying party holds is not refused"
                     % ("the held-state file is absent: nothing held" if "held-state" in inputs else "no held size given"))
    elif note["size"] < held[0]:
        raise CheckpointRefused("checkpoint_older_than_held", "the checkpoint's size %d is below the held size %d"
                                % (note["size"], held[0]))
    elif note["size"] == held[0]:
        if note["root"] != held[1]:
            raise CheckpointRefused("checkpoint_split_view_at_held_size",
                                    "size %d: the checkpoint's root is not the held root" % held[0])
        lines.append("not older than the held size %d: the same root" % held[0])
    else:
        if "consistency-proof" not in inputs:
            raise CheckpointRefused("checkpoint_consistency_unproven",
                                    "the checkpoint is larger than the held size %d and no consistency proof is given"
                                    % held[0])
        proof = _cp_proof(inputs["consistency-proof"], {"old": held[0], "new": note["size"]})
        if not checkpoint_verify_consistency(held[0], note["size"], proof, held[1], note["root"]):
            raise CheckpointRefused("checkpoint_consistency_invalid", "the tree of size %d does not extend the held "
                                    "tree of size %d" % (note["size"], held[0]))
        lines.append("not older than the held size %d: consistent with it (RFC 9162 consistency proof)" % held[0])
    lines.append("all checks held: inclusion, witness quorum, not older than the held size")
    return ["log checkpoint: " + line for line in lines], note


def checkpoint_state_text(note):
    """The held-state file's text for a checkpoint: its origin, size and SHA-256 root."""
    return json.dumps({"origin": note["origin"], "root": base64.b64encode(note["root"]).decode("ascii"),
                       "size": note["size"]}, sort_keys=True) + "\n"


def checkpoint_held(opts):
    """The held (size, root, origin or None) the relying party gives, from --held-size and --held-root or from
    --held-state (absent file: None); CheckpointUsage otherwise."""
    if "held-state" in opts:
        if "held-size" in opts or "held-root" in opts:
            raise CheckpointUsage("--held-state and --held-size/--held-root are two sources of one thing; give one")
        try:
            state = read_json(opts["held-state"])
        except FileNotFoundError:
            return None
        except (OSError, ValueError, UnicodeDecodeError) as error:
            raise CheckpointUsage("the held-state file is not readable: %s" % error)
        size, root, origin = member(state, "size"), member(state, "root"), member(state, "origin")
        if not isinstance(origin, str) or not isinstance(size, int) or isinstance(size, bool):
            raise CheckpointUsage("the held-state file is not {\"origin\", \"root\", \"size\"}")
        size, root_text = str(size), root
    elif "held-size" in opts or "held-root" in opts:
        if "held-size" not in opts or "held-root" not in opts:
            raise CheckpointUsage("--held-size and --held-root go together")
        size, root_text, origin = opts["held-size"], opts["held-root"], None
    else:
        return None
    root = _cp_b64(root_text) if isinstance(root_text, str) else None
    if not _CHECKPOINT_DECIMAL.match(size) or int(size) < 1 or root is None or len(root) != 32:
        raise CheckpointUsage("a held size is a decimal of at least 1, and a held root a base64 SHA-256 hash")
    return int(size), root, origin


def checkpoint_inputs(opts):
    """None without --checkpoint and its companions; else the inputs, read (CheckpointUsage when incomplete).
    JSON inputs are read by THE READING RULE (read_json)."""
    given = [flag[2:] for flag in CHECKPOINT_FLAGS + ("--write-held-state",) if flag[2:] in opts]
    if not given:
        return None
    for needed in ("checkpoint", "inclusion-proof", "witness-policy"):
        if needed not in opts:
            raise CheckpointUsage("--checkpoint, --inclusion-proof and --witness-policy go together")
    held = checkpoint_held(opts)
    if "consistency-proof" in opts and held is None and "held-state" not in opts:
        raise CheckpointUsage("--consistency-proof proves consistency with a held size: give one")
    if "write-held-state" in opts and "held-state" not in opts:
        raise CheckpointUsage("--write-held-state writes the file --held-state names")
    inputs = {"held": held}
    for name in ("checkpoint", "witness-policy"):
        with open(opts[name], "rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise CheckpointUsage("%s is larger than %d bytes" % (opts[name], MAX_INPUT_BYTES))
        inputs[name] = raw
    for name in ("inclusion-proof", "consistency-proof", "key-transition"):
        if name in opts:
            inputs[name] = read_json(opts[name])
    for name in ("held-state", "write-held-state"):
        if name in opts:
            inputs[name] = opts[name]
    return inputs


def main(argv):
    # The messages carry characters outside ASCII. Under an ASCII or Latin-1 stream a strict encoder
    # would raise in the middle of a verdict, so a verified receipt could end in a stack trace; the
    # characters are written as escapes instead, and the verdict and its exit are unchanged.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

    opts = {}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag in ("--receipt", "--registry") + CHECKPOINT_FLAGS:
            if index + 1 >= len(argv):
                die(EXIT_USAGE, "usage: %s requires a value" % flag)
            opts[flag[2:]] = argv[index + 1]
            index += 2
        elif flag == "--write-held-state":
            opts["write-held-state"] = True
            index += 1
        else:
            index += 1

    if "receipt" not in opts:
        die(EXIT_USAGE, "usage: verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json")

    # DEFAULT DISTRUST. Without an independently supplied registry there is no basis to judge the
    # receipt, and taking the key from the bundle would be checking a signature against a key the
    # same party supplied. That is a refusal, not a verdict — hence 5, not 1.
    if "registry" not in opts:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — no --registry was supplied.\n\n"
            "This verifier refuses to check a signature against key material that arrived with the\n"
            "receipt. A key obtained from the same download as the evidence proves nothing:\n"
            "whoever produced the bundle chose both halves.\n\n"
            "Supply a registry you obtained INDEPENDENTLY of this receipt. It is published in\n"
            "the public repository, where every append is a dated commit you can walk and\n"
            "tampering is detectable against any older clone.\n\n"
            "A second channel — a Zenodo deposit carrying a DOI — is INTENDED and NOT YET LIVE.\n"
            "When it exists you will be able to cross-check one against the other, and\n"
            "disagreement between them will itself be an alarm. Until then there is one channel,\n"
            "and this tool says so rather than implying a check you cannot perform.",
            verdict_code="registry_not_supplied",
        )

    try:
        receipt = read_json(opts["receipt"])
        registry = read_json(opts["registry"])
    except (OSError, ValueError) as error:
        die(EXIT_USAGE, "cannot read input: %s" % error)

    # the log checkpoint's inputs (CHECKPOINTS.md), read now; judged only once the receipt verified
    try:
        checkpoint = checkpoint_inputs(opts)
    except CheckpointUsage as error:
        die(EXIT_USAGE, "usage: %s" % error)
    except (OSError, ValueError) as error:
        die(EXIT_USAGE, "cannot read input: %s" % error)

    if not isinstance(receipt, dict):
        die(EXIT_USAGE, "the receipt must be a JSON object")

    payload, signature, key_id = (
        member(receipt, "signed_payload"),
        member(receipt, "signature"),
        member(receipt, "key_id"),
    )
    if not all(isinstance(v, str) for v in (payload, signature, key_id)):
        die(EXIT_USAGE, "receipt must carry signed_payload, signature and key_id")

    # The receipt may carry a public_key. It is NEVER used.
    if isinstance(member(receipt, "public_key"), str):
        print("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")

    entries = member(registry, "entries")
    if not isinstance(entries, list):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry carries no entries list.",
            verdict_code="registry_missing_key",
        )

    # A key_id that is the empty text names no key, whatever the registry holds under that text.
    matches = [e for e in entries if member(e, "key_id") == key_id] if key_id != "" else []

    if not matches:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry does not name key_id %r.\n\n"
            "This is not a statement that the receipt is bad. It is a statement that the registry\n"
            "you supplied gives no basis to judge it. The verifier does not fall back to any other\n"
            "key." % key_id,
            verdict_code="registry_missing_key",
        )

    # V-DUPKEY. Taking the first match would let DOCUMENT ORDER select the verdict, inside a file
    # whose governing rule is that entries are never removed or rewritten.
    if len(matches) > 1:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry names key_id %r %d times.\n\n"
            "The registry is append-only: an entry is never removed and never rewritten, so one\n"
            "key_id names one key. Two entries mean the file is internally inconsistent, and\n"
            "picking either one would let the ORDER of a document decide the verdict.\n"
            "Detected on key_id only. Two entries sharing a public key under DIFFERENT key_ids is\n"
            "not this error." % (key_id, len(matches)),
            verdict_code="registry_duplicate_key",
        )

    entry = matches[0]
    status = member(entry, "status")

    # DEFAULT DENY. The registry defines exactly four statuses. Unknown standing is not good
    # standing, and a status this verifier cannot interpret is a reason to refuse, never to pass.
    if not isinstance(status, str) or status not in STATUSES:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r carries status %r.\n\n"
            "The registry defines exactly four: example, active, retired, compromised. A status\n"
            "outside that set, or absent, is standing this verifier cannot interpret. It refuses\n"
            "rather than treating the unrecognised as the benign." % (key_id, status),
            verdict_code="key_status_not_active",
        )

    if status == "example":
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r is an example key, not a trust root.\n\n"
            "Example entries demonstrate the registry's schema. They are generated from a published\n"
            "string, so their private half is not secret and anything they sign proves nothing."
            % key_id,
            verdict_code="key_is_example",
        )

    # The entry must hash to its own published fingerprint BEFORE its key, its window or a status of
    # active, retired or compromised is believed (an absent, undefined or example status is refused
    # first: VERDICTS.md, step 2). An entry failing its own integrity check may have been
    # substituted, and reporting a benign story read out of it would be the wrong answer.
    # an absent or non-string public_key is a fingerprint failure (the Elixir verifier's and the
    # issuing system's order; coalescing the absent key to `""` would hash to sha256(""), which
    # matches only a stated fingerprint equal to that value, and such an entry would then reach
    # the key-length check instead of failing as a fingerprint mismatch)
    published = member(entry, "public_key")
    raw_key = b64(published) if isinstance(published, str) else None
    stated = member(entry, "public_key_fingerprint")
    if raw_key is None or not isinstance(stated, str) or hashlib.sha256(raw_key).hexdigest() != stated:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r does not hash to its own published fingerprint.\n\n"
            "public_key_fingerprint is sha256 over the RAW key bytes, lowercase hex. This entry\n"
            "fails its own integrity check, so nothing it states — its status, its window, its key —\n"
            "can be relied on." % key_id,
            verdict_code="key_fingerprint_mismatch",
        )

    # A public_key that is not 32 raw bytes is not an Ed25519 key. A defect in
    # the TRUST ROOT is a trust question, never an accusation of the receipt. The entry hashed
    # to its own fingerprint, so this is what the registry published.
    if len(raw_key) != 32:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r publishes a public_key of %d bytes; an Ed25519\n"
            "public key is 32.\n\n"
            "The entry hashes to its own fingerprint, so this is what the registry published: not\n"
            "a key this verifier can check a signature against. Nothing the receipt says is judged."
            % (key_id, len(raw_key)),
            verdict_code="key_public_key_malformed",
        )

    valid_from, valid_to = timestamp(member(entry, "valid_from")), member(entry, "valid_to")
    if valid_from is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r has no usable valid_from.\n\n"
            "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly. A window that cannot be read cannot\n"
            "place a receipt inside or outside it." % key_id,
            verdict_code="key_valid_from_unusable",
        )
    if valid_to is not None:
        valid_to = timestamp(valid_to)
        if valid_to is None:
            die(
                EXIT_NO_TRUST,
                "TRUST NOT ESTABLISHED — key_id %r has an unreadable valid_to.\n\n"
                "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, or null for a key still signing."
                % key_id,
            verdict_code="key_valid_to_unreadable",
        )

    # The signed bytes are read by the same rule as the input files. Bytes that are not read
    # (not JSON, an object repeating a member name, too deep, a number that is not read) carry no
    # readable occurred_at: a trust question, asked before anything accuses the receipt.
    unread = ""
    try:
        signed = parse_json(payload)
        if not isinstance(signed, dict):
            signed = None
            unread = "they are not a JSON object"
    except ValueError as error:
        signed = None
        unread = "they are not JSON that every implementation reads alike (%s)" % error

    occurred = timestamp(member(signed, "occurred_at"))
    if occurred is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the signed bytes carry no readable occurred_at%s.\n\n"
            "occurred_at is the only signing time a receipt carries, and it is what the key's\n"
            "signing window is checked against. Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly,\n"
            "and a real calendar instant; it is refused rather than coerced, so the\n"
            "implementations cannot drift." % (": " + unread if unread else ""),
            verdict_code="signed_occurred_at_unreadable",
        )

    # --- the receipt itself. From here to the signature check everything accuses the receipt, so
    # --- it runs only once the registry has given us the standing to make an accusation. The
    # --- compromised-key and signing-window verdicts after the signature check do not accuse it.
    expected_hash = member(receipt, "receipt_hash")
    if not isinstance(expected_hash, str):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt carries no receipt_hash.\n\n"
            "A receipt states the digest of its own signed bytes. An absent field is not a check\n"
            "to be skipped; it is a receipt that declines to be held to anything.",
            verdict_code="receipt_hash_missing",
        )
    if hashlib.sha256(payload.encode("utf-8")).hexdigest() != expected_hash:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes.",
            verdict_code="receipt_hash_mismatch",
        )

    for key in receipt:
        if key in ENVELOPE or key in IGNORED or key not in signed:
            continue
        if tagged(receipt[key]) != tagged(signed[key]):
            die(
                EXIT_INVALID,
                "SIGNATURE INVALID — the receipt displays %r as %r, but the SIGNED bytes say %r.\n\n"
                "A reader takes the visible field for part of the receipt. The signature covers\n"
                "only the signed bytes, so a top-level field contradicting them is a claim no\n"
                "signature stands behind." % (key, receipt[key], signed[key]),
            verdict_code="displayed_field_mismatch",
        )

    # A signature that does not decode or is not 64 raw bytes is MALFORMED --
    # the taxonomy's word, the Elixir verifier's and the issuing system's; one that decodes and
    # fails the curve check is INVALID.
    raw_signature = b64(signature)
    if raw_signature is None or len(raw_signature) != 64:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — malformed signature or key material.",
            verdict_code="signature_malformed",
        )
    if not ed25519_verify(raw_signature, payload.encode("utf-8"), raw_key):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the signature does not check out against the registry's public key.",
            verdict_code="signature_invalid",
        )

    # 6 asserts the signature IS cryptographically valid, so it cannot be reached over a failed
    # verification. It sits after the checks above for that reason and not by accident.
    if status == "compromised":
        die(
            EXIT_COMPROMISED,
            "KEY COMPROMISED — the signature is cryptographically valid under key_id %r, but the\n"
            "registry marks that key compromised as of %s.\n\n"
            "WHAT THIS VERDICT CAN AND CANNOT ESTABLISH:\n\n"
            "  * The signature checks out against the published key.\n"
            "  * It does NOT establish that the issuer produced it. Anyone holding the compromised\n"
            "    private key could have.\n"
            "  * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on\n"
            "    the signing time, which the receipt asserts about itself and an adversary holding\n"
            "    that key can backdate.\n\n"
            "Sound for honest history, advisory against a forger. Closing the gap requires anchoring\n"
            "signing times outside the issuing system; that is named future work.\n\n"
            "Exit code 6 is PROVISIONAL, pending reconciliation with the VIRP vocabulary."
            % (key_id, shown(member(entry, "status_changed_at"))),
            stream=sys.stdout,
        )

    # The window is half-open: valid_from <= occurred_at < valid_to. See VERDICTS.md for why the
    # published registries settle that convention rather than taste.
    if occurred < valid_from or (valid_to is not None and occurred >= valid_to):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the receipt says it was signed at %s, outside key_id %r's\n"
            "signing window [%s, %s).\n\n"
            "A retired key's signatures survive its retirement; a signature dated after the window\n"
            "closed was never covered by that rule. The window is half-open, so an occurred_at\n"
            "equal to valid_to is outside it.\n\n"
            "Sound for honest history, advisory against a forger: occurred_at is asserted by the\n"
            "receipt, and an adversary holding the key can backdate it."
            % (
                member(signed, "occurred_at"),
                key_id,
                member(entry, "valid_from"),
                member(entry, "valid_to"),
            ),
            verdict_code="signed_outside_key_validity",
        )

    # A signature binds the receipt's position in its chain only when the signed bytes carry both
    # members. Nothing above requires either, so the note says which is absent.
    absent = [name for name in ("sequence", "previous_hash") if name not in signed]
    if absent:
        note = (
            "Note: the signed bytes carry no %s, so this signature does not bind the receipt's "
            "position in a chain." % " and no ".join(absent)
        )
    else:
        note = (
            "Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so\n"
            "a valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content."
        )
    checkpoint_lines = []
    if checkpoint is not None:
        try:
            checkpoint_lines, judged = checkpoint_check(receipt, checkpoint)
        except CheckpointUsage as error:
            die(EXIT_USAGE, "usage: %s" % error)
        except CheckpointRefused as refusal:
            die(
                EXIT_NO_TRUST,
                "TRUST NOT ESTABLISHED — the log checkpoint: %s.\n\n"
                "The receipt's signature is valid under key_id %r. What is not established is the log's\n"
                "account of it: its inclusion under a checkpoint that the log key and the witnesses your\n"
                "policy names signed, not older than the tree size you hold." % (refusal, key_id),
                verdict_code=refusal.code,
            )
        held = checkpoint["held"]
        if "write-held-state" in checkpoint and (held is None or judged["size"] > held[0]):
            try:
                with open(checkpoint["held-state"], "w", encoding="utf-8") as handle:
                    handle.write(checkpoint_state_text(judged))
            except OSError as error:
                die(EXIT_USAGE, "cannot write the held-state file %s: %s" % (checkpoint["held-state"], error))
            checkpoint_lines.append("log checkpoint: the held-state file now holds size %d" % judged["size"])

    print(
        "VERIFIED — signature is valid under key_id %r (status: %s).\n\n"
        "A retired key verifies exactly like an active one WITHIN ITS SIGNING WINDOW. Rotation does\n"
        "not invalidate receipts already issued; only new signing stops.\n\n"
        "%s" % (key_id, status, note)
    )
    for line in checkpoint_lines:
        print(line)
    sys.exit(EXIT_VERIFIED)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SystemExit:
        raise
    except BaseException as error:
        # Last resort, for an exception no check above foresaw. Exit 2 ("nothing was measured"),
        # because neither 0 nor 1 may be said of an input this file could not evaluate, and no
        # stack trace: the type of the exception is named so the defect can be reported.
        try:
            sys.stdout.flush()
            print(
                "internal error (%s): this verifier could not evaluate the input; nothing was measured."
                % type(error).__name__,
                file=sys.stderr,
            )
        finally:
            sys.exit(EXIT_USAGE)
