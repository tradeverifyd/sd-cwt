# Canonical SD-CWT examples from the Internet-Draft

Copied verbatim from `examples/` in
[ietf-wg-spice/draft-ietf-spice-sd-cwt](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt)
at `draft-ietf-spice-sd-cwt-08`.

| File | What it is |
|---|---|
| `issuer_cwt.cbor` | Issued SD-CWT, ES384 issuer key, five disclosures in `sd_claims` |
| `kbt.cbor` | SD-KBT presentation, ES256 holder key, three disclosures selected |

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
