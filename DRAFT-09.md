# Draft -09 alignment

Targets **draft-ietf-spice-sd-cwt-09**, the latest published draft checked on
19 November 2026. The editor's main branch and -09 tag both resolve to
`79c43819c74c3240b3eab8601996d2b694e30087`. See `SPEC-VERSION.json` for the
published text hash and normative source/schema hashes.

## Changes from -08

- Section 12.1 and the CDDL move `sd_aead` (172) into **unprotected** SD-CWT
  headers. The Holder chooses the AEAD algorithm; the enclosing KBT signature
  binds that selection. The Issuer's protected bytes, payload, and signature
  remain unchanged. Absence still means AES-128-GCM.
- Section 9 explicitly requires decryption for supported algorithms with an
  available key, withholding when no key is available, failure of the entire
  presentation when a selected key cannot authenticate a disclosure, and
  normal hash matching/reconstruction of decrypted disclosures. Unsupported
  algorithms remain opaque; key resolution is not attempted for them.
- Key lookup may also use a nonce. The context tuple and uint/text/byte-string
  context types are unchanged; the IANA value type now includes the context.
- Algorithms prohibited by section 16.9 are rejected. Unsupported permitted
  algorithms are distinct from forbidden algorithms. AEGIS X tags must be
  32 bytes. Generic COSE duplicate-header and critical-header checks remain.

`SDCWTPresenter.create_presentation(..., aead_algorithm=2)` and
`encrypt_sd_cwt_disclosures(..., algorithm=2)` select AES-256-GCM.
The existing issuer `sd_aead` option now writes an unprotected hint, not a signed
issuer restriction. A Holder can override it. `aead_entry_key_resolver(entry, algorithm)`
on the high-level verifier (or `entry_key_resolver` on the decryption helper)
allows lookup by nonce or tag while the original context resolver remains supported.

Old -08 tokens with protected header 172 are rejected explicitly. The library
does not rewrite issuer-signed bytes or silently fall back to the old placement.
Existing default-algorithm tokens with no 172 remain valid under -09.

The -09 text contains one stale occurrence of “sd_aead protected header field”
later in section 12.1. This implementation follows that section's changed opening
paragraph, the -09 CDDL, and the explicit header-placement change in spec commit
`cf867df`. This editorial inconsistency is recorded for the co-authors; it is
not a reason to use the superseded -08 placement.

## Validation and provenance

- 234 Python tests, Black, Ruff, and MyPy pass.
- Signed/non-self-generated controls cover native Rust AES-256 with and without
  keys, Holder selection without changing issuer-signed bytes, algorithm-id
  validation, opaque unsupported algorithms, and nonce-based key selection.
- The published -09 first-disclosure digest is pinned in a regression test;
  the corrected example digest matches the existing implementation hash.
- The six canonical binary fixtures were checked byte-for-byte against the -09
  tag. Their bytes are unchanged from -08; they now live under `fixtures/draft-09`
  with hashes in `draft-09-provenance.json`. Other files are explicitly derived
  regression fixtures using public Appendix C keys and historical clocks.
- The pinned -09 cross-implementation runners pass 539/539 extended profiles,
  306/306 encrypted-disclosure checks, and 54/54 original default-AES-128 checks.
  Counts overlap and are not additive. Beltram's library remains at `c6eb0e4`;
  only its CLI adapter is extended to expose its existing AEAD APIs.

## Correction and scope

The previous security/interop report compared against -08 and incorrectly
characterized Beltram's unprotected header 172 as a current-spec defect. That
conclusion is withdrawn. The earlier AES-256 failures came from our stale
implementation and test expectations; the -09 profile matrix passes.

This establishes alignment with the reviewed -08 to -09 changes and the tested
profiles. It does not certify every unchanged requirement: complete issuance
and Holder validation, all algorithm/confirmation profiles, claims split
between payload and header 15, exhaustive nesting/map-key rules, replay state,
revocation, and fuzzing remain outside this evidence. Applications still enforce
trusted issuers and required disclosed claims.
