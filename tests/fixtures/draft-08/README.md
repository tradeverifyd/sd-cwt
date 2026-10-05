# Canonical SD-CWT examples from the Internet-Draft

Copied verbatim from `examples/` in
[ietf-wg-spice/draft-ietf-spice-sd-cwt](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt)
at `draft-ietf-spice-sd-cwt-08`.

| File | What it is |
|---|---|
| `issuer_cwt.cbor` | Issued SD-CWT, ES384 issuer key, five disclosures in `sd_claims` |
| `kbt.cbor` | SD-KBT presentation, ES256 holder key, three disclosures selected |
| `decoy.cbor` | Issued SD-CWT with two decoy disclosures among four |
| `nested_issuer_cwt.cbor` | Issued SD-CWT with fifteen disclosures, nested |
| `nested_cwt.cbor` | Narrowed nested SD-CWT, seven disclosures |
| `nested_kbt.cbor` | Nested SD-KBT presentation |
| `aead_kbt.cbor` | **Not from the draft.** `issuer_cwt.cbor` presented with the Appendix C Holder key; disclosure `501` is in `sd_aead_encrypted_claims` (171), byte-identical to the draft's `aead-claim-array.edn` (key `aead-key.txt`). Regenerate with `make_aead_kbt.py`. |

A decoy disclosure is a one-element array holding only a salt. Its digest sits
in the payload like any other Redacted Claim Hash, so the count of redacted
claims reveals nothing, and disclosing it reveals nothing either.

Nested disclosures must be resolved iteratively: revealing one exposes Redacted
Claim Hashes inside its value, which later disclosures then match. Checking all
disclosures against only the outermost hashes fails on these files.

The signing keys are in Appendix C of the draft: the Holder key is P-256, the
Issuer key is P-384.

These bytes are the interoperability contract. A test that only round-trips
this library against itself will pass even when the library and the draft
disagree, so any change to hashing, header encoding, or signature construction
must be checked against these files.

## The `.pem` keys

`holder_privkey.pem` (P-256) and `issuer_privkey.pem` (P-384) are the Appendix C
test keys, published in the Internet-Draft itself. They are public sample keys
with no value, checked in so the tests can sign as well as verify.

Never use them for anything real.
