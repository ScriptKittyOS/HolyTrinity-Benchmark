# receipt-verification r4: correction note

Date: 2026-11-16.

Applies to: the release tagged `receipt-verification-r4` in this repository, that is, its two verifier programs
(`receipt-verification/verifier/verify_receipt.py` and `receipt-verification/verifier/verify_receipt.exs`) and its
`receipt-verification/verifier/VERDICTS.md`.

Does not change: the exit status of either r4 program on any receipt published in this repository (see
"Receipts published here", below).

r4 stays published as it is. This note is added beside it; nothing in r4 is rewritten.

## What we found

1. **The r4 Python verifier accepts a signature whose first half (R) is not a canonical point encoding.**
   RFC 8032, section 5.1.3, says that decoding a point fails when the y-coordinate it encodes is not below the
   field prime p, and section 5.1.7 says that a signature is invalid if any decoding fails. The r4
   `verify_receipt.py` clears the top bit of the 32 bytes and decodes the rest without that comparison
   (`_decode_point`, lines 110-118). On such a signature it prints `VERIFIED` and exits 0 (input `nc`).
2. **Both r4 verifiers accept a signature whose R is a point of small order** (input `c`: R is the identity point,
   written canonically). RFC 8032's verification procedure (section 5.1.7) has no rule against such an R.
3. **Both r4 verifiers accept a registry key of small order, and under such a key one signature verifies over
   any signed bytes.** Inputs `idkey1` and `idkey2` name a registry key equal to the identity point and carry the
   same signature (R the identity point, S = 0) over two different signed payloads; both r4 programs print
   `VERIFIED` and exit 0 for both. RFC 8032's verification procedure has no rule against such a key either.
4. **On input `nc` the two r4 verifiers give different answers.** The r4 `verify_receipt.exs` hands the signature
   to the Erlang runtime's `:crypto.verify/5` (line 411). On Erlang/OTP 28 built with OpenSSL 3.0.13 it prints
   `SIGNATURE INVALID` and exits 1, where the r4 `verify_receipt.py` prints `VERIFIED` and exits 0. Other OpenSSL
   versions were not measured.
5. **The r4 `VERDICTS.md` misstates the order of its checks.** Its lines 8-9 say "Every trust question precedes
   every accusation", and its paragraph at line 111 says the same of steps 2 and 5 of its list. That list
   (lines 105-108) puts the signing window (step 5, exit `5`, `signed_outside_key_validity`) after the signature
   (step 3, exit `1`), and both r4 programs follow the list: for a key whose signing window starts after the
   receipt's signed time, a valid signature gives exit 5 (input `win_ok`) and an invalid one gives exit 1 (input
   `win_bad`). The error is in the sentence, not in the programs.

## What this allows

- With the private key of a registered key, one can make a receipt that one r4 program accepts and the other
  refuses: input `nc` was made that way (`build_cases.py`), and the two programs disagree on it (point 4). Two
  verifiers of one release must give the same answer on every input. We treat this as a defect.
- Under a registry key of small order, the signature of point 3 needs no private key. Both r4 programs read the
  key from the registry file given with `--registry`; the registries published in this repository hold no such
  key (next section).

## Receipts published here

- We ran the r4 `verify_receipt.py` and the Python verifier prepared for the next release over every pairing of
  the 27 JSON files of `receipt-verification/verifier/corpus` at r4, each as a receipt, with those 27 files and the
  two registries in `receipt-verification/keys`, each as a registry: 783 pairs. The exit status is the same in all
  783.
- In those 29 files, 19 receipts carry a signature. In 18 of them R is a canonical encoding of a point of the
  prime-order subgroup; the 19th is a fixture whose signature is too short to hold an R. Every registry key of 32
  bytes in those files (38 keys, among them the two keys of `keys/registry.json` and the one key of
  `keys/evaluation-registry.json`) is a canonical encoding of a point of the prime-order subgroup.
- Outside `receipt-verification/verifier/corpus`, no file of this repository at r4 holds a receipt: the four other
  files that contain `signed_payload` or `"signature"` are the verifier folder's `README.md`, `VERDICTS.md` and its
  two programs.
- Receipts published anywhere else were not checked.

## What changes in the next release

- Both verifier programs refuse a non-canonical R, an R of small order and a registry key of small order. On
  inputs `nc`, `c`, `idkey1` and `idkey2` they print `SIGNATURE INVALID` and `verdict_code: signature_invalid`, and
  exit 1. Its `VERDICTS.md` lists these refusals in the section "What "signature failing to verify" includes: the
  Ed25519 refusals".
- Its `VERDICTS.md` says: "Every trust question but the signing window precedes every accusation; `6` and the
  signing-window answer are given only over a signature that has already verified."
- Both statements above were measured on the verifier sources prepared for that release, on the date of this
  note. That release is not published yet.

## How to check this yourself

The inputs are in [`correction-r4/`](correction-r4/): each folder holds a `receipt.json` and a `registry.json`,
written by [`correction-r4/build_cases.py`](correction-r4/build_cases.py) (Python standard library only; it
imports nothing from either verifier). From the root of this repository:

```
git show receipt-verification-r4:receipt-verification/verifier/verify_receipt.py > r4_verify_receipt.py
git show receipt-verification-r4:receipt-verification/verifier/verify_receipt.exs > r4_verify_receipt.exs
for c in ok nc c idkey1 idkey2 win_ok win_bad; do
  d=receipt-verification/correction-r4/$c
  python3 -I r4_verify_receipt.py --receipt $d/receipt.json --registry $d/registry.json; echo "$c python exit $?"
  elixir r4_verify_receipt.exs --receipt $d/receipt.json --registry $d/registry.json; echo "$c elixir exit $?"
done
```

Expected first line and exit status (measured with Python 3.12.3, and Elixir 1.19.2 on Erlang/OTP 28 built with
OpenSSL 3.0.13):

| input | what it is | r4 `verify_receipt.py` | r4 `verify_receipt.exs` |
|---|---|---|---|
| `ok` | an ordinary signature | `VERIFIED`, 0 | `VERIFIED`, 0 |
| `nc` | R written non-canonically (y = p + 1) | `VERIFIED`, 0 | `SIGNATURE INVALID`, 1 |
| `c` | R the identity point, a point of small order | `VERIFIED`, 0 | `VERIFIED`, 0 |
| `idkey1`, `idkey2` | registry key the identity point; one signature over two different payloads | `VERIFIED`, 0 | `VERIFIED`, 0 |
| `win_ok` | signing window starts after the signed time; valid signature | `TRUST NOT ESTABLISHED`, 5 | `TRUST NOT ESTABLISHED`, 5 |
| `win_bad` | the same key; one bit of the signature flipped | `SIGNATURE INVALID`, 1 | `SIGNATURE INVALID`, 1 |
