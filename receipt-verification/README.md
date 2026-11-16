# Receipt verification

Everything needed to check a Trinity authority receipt **without trusting the system that issued
it**: the public key registry, and two independent verifier implementations.

**Correction note for r4 (2026-11-16):** [`CORRECTION-r4-2026-11-16.md`](CORRECTION-r4-2026-11-16.md). The r4 Python verifier accepts a signature whose R is not a canonical point encoding, which RFC 8032 says is invalid, and the r4 Elixir verifier refuses that signature, so the two disagree on it. Both r4 verifiers accept the identity point as a signature's R and as a registry key. The r4 `VERDICTS.md` misstates the order of two checks. On every receipt published here, each r4 verifier gives the same exit status as the verifier prepared for the next release in the same language.

## What this is, and what it is not

This directory is **versioned independently of the HolyTrinity benchmark.** It ships when a key
ceremony or a verifier change makes it necessary, on its own schedule, with its own checksum files.

**It precedes the v2 benchmark release.** The benchmark's v1 deposit — the artifact the papers and
the DOIs resolve to — **is unchanged by this publication.** Nothing here modifies, re-scopes or
replaces it. If you cloned this repository for the benchmark, everything you had is still exactly
where it was and byte-identical; this is an addition beside it, not a new version of it.

## Two registries live here and they are NOT interchangeable

Confusing them makes a verification meaningless, so they are named plainly:

| file | what it is | key ids |
|---|---|---|
| `keys/registry.json` | **THE LIVE REGISTRY.** The real public keys. This is the one to verify a real receipt against. | `example_ed25519_v0`, `receipt_ed25519_v1` |
| `verifier/corpus/registry.json` | **A TEST FIXTURE.** Keys invented to exercise the verifier's own verdicts — active, retired, compromised, unknown. It has never verified anything real and none of its keys ever signed a production receipt. | `corpus_active_v1`, `corpus_retired_v1`, `corpus_compromised_v1`, `example_ed25519_v0` |

**Verifying a real receipt against the corpus fixture will not fail loudly — it will report
`unknown key id`,** which reads like a finding about the receipt when it is actually a finding
about your command line. If you are checking something real, the path you want is
`keys/registry.json`.

## Where to get the registry

**From a channel independent of the system whose receipts you are checking.** It is published in
this repository, where every append is a dated commit you can walk and tampering is detectable
against any older clone.

A second channel — a Zenodo deposit carrying a DOI — is **intended and not yet live.** When it
exists, cross-checking one channel against the other becomes available and disagreement between
them is itself an alarm. Until then there is one channel, and this file says so rather than
sending you to look for a mirror that is not there.

## Integrity

Each directory carries its own `SHA256SUMS`, scoped to that directory and nothing else:

    cd keys     && sha256sum -c SHA256SUMS
    cd verifier && sha256sum -c SHA256SUMS

They are separate files on purpose. `keys/` appends on every key ceremony; `verifier/` changes only
when a verifier does; and the benchmark's own `SHA256SUMS` at the repository root describes the
benchmark release and is not touched by either. **A checksum file that spans several independently
versioned things has to be regenerated whenever any of them moves, and "every file in this release"
stops meaning anything the moment "this release" is ambiguous.**

## Start here

    verifier/VERDICTS.md    THE SINGLE SOURCE: every verdict, the input that produces it, and
                            the order the checks run in
    verifier/README.md      how to run it, the signing scheme, and why a bundle-local key is refused
    keys/README.md          the registry's schema, its statuses, and the append-only rule
