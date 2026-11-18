# Verification security review — 18 November 2026

Scope: `SDCWTVerifier.verify_presentation`, holder-key resolution, COSE Sign1
verification, AEAD disclosure processing, and reconstruction. Base revision:
`5a2744c`; the branch also includes the preceding interop/reconstruction fixes.
This is a focused source review with executable regression cases, not an
independent audit, a complete conformance proof, or a guarantee of no defects.

## Confirmed findings and changes

| Finding | Impact and prerequisite | Change |
|---|---|---|
| Time claims were not enforced | High: a holder of an expired or not-yet-valid credential could present it successfully. Signatures remained valid. | Validate finite numeric dates, expiry/not-before/future issuance, internal ordering, and KBT bounds against the credential. Secure defaults use the system clock and zero leeway. |
| Resolved key not bound to signed `cnf` thumbprint | Medium, resolver-dependent: a fallback or incorrectly implemented resolver returning a different key allowed that key to sign the KBT. This is not an arbitrary signature forgery with a correctly constrained resolver. | Compute and constant-time compare the resolved key's thumbprint with the signed value. Reject ambiguous embedded-key/thumbprint confirmations. |
| Audience checked only in KBT | High when a credential restricts its audience: an issuer restriction, including one recovered from a disclosure, was ignored. | Check both authenticated, reconstructed credential claims and KBT claims. |
| Claim reconstruction and alias confusion | Medium, malformed/ambiguous issued-claim prerequisite: nested claims could move to the root, numeric claims disappear, or a custom `iss` overwrite the standard alias. Repeated disclosures were also accepted. | Reconstruct by hash location; preserve maps/arrays; reject collisions, duplicate consumption, unmatched claims/decoys, and ambiguous aliases. |
| Unsupported critical or conflicting COSE headers | Medium: extension semantics could be silently ignored. | Reject unknown critical parameters, unprotected `crit`, and duplicate protected/unprotected labels. Only the generic verifier's implemented critical algorithm semantics are accepted. Also enforce SD-CWT/KBT types and the supported disclosure hash. |
| Verification exception logging | Low: resolver error text or malformed/decrypted values could reach stdout/stderr. | Fail closed without automatic exception/traceback logging from the high-level verifier. |

`tests/test_security_review.py` starts with a valid signed control, then supplies
validly signed adversarial variants. Before the fixes, 15 rejection cases failed
(the library accepted them) and the positive control passed. The expanded suite
now also tests exact expiry/leeway boundaries, expected challenges, ambiguous
confirmation claims, unmatched decoys, understood critical headers, and absence
of resolver-secret logging. These tests do not count invalid signatures as proof
of claim-policy enforcement.

The policy follows [RFC 8392 claim semantics](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1),
[COSE header processing](https://www.rfc-editor.org/rfc/rfc9052.html#section-3), and
the checked draft-08 KBT/SD-CWT verifier procedure. Application profiles still
choose trusted issuers, required claims, intended audience, and replay policy.

## API changes and compatibility

- `verify_presentation(..., now=None, leeway=0, expected_nonce=None)` rejects
  expired and not-yet-valid tokens by default. `now` is epoch seconds from a
  **trusted application clock**, never a value selected from an untrusted token.
- `create_presentation(..., issued_at=None)` supports controlled clocks and test
  vectors; it does not extend an issuer's validity window.
- Public draft fixtures use explicit historical verification times. AEAD fixture
  generators issue KBTs at 1725244300, inside the unchanged issuer credential's
  validity window. Two-key regression KBTs were re-signed with public test keys;
  issuer signatures and encrypted disclosures are unchanged.
- The public API retains `iss`, `sub`, and `iat` aliases and omits `cnf` from its
  returned claims. Nested region is correctly returned at `claims[503]["region"]`.
- Unsupported disclosure hashes are rejected rather than silently assuming
  SHA-256. Low-level `CredentialVerifier`/COSE APIs remain signature primitives;
  use the high-level presentation verifier for the full policy.

## Validation

- Full Python suite: **209 passed**, including a fresh temporary environment
  installed from the locally resolved development dependency graph.
- Cross-implementation profiles: **316/316 passed** with the security changes
  and explicit historical clocks (Python/JavaScript, plus supported Rust checks).
- Prior duplicate-disclosure and reconstruction regressions remain included.
- Coverage configuration corrected: the former `...` regex excluded almost all
  source lines. Coverage percentages now reflect actual measured code.

## Dependency review and remaining risks

`pip-audit` on the installed environment found no known advisories in the
resolved production graph (`sd-cwt`, cbor-diag, cbor2, cffi, cryptography, fido2,
pycparser, PyYAML, regex, zcbor). This is advisory matching, not a reachability
or cryptographic audit.

The broad development environment initially had 50 advisories across seven
packages. Re-resolving the ignored local `uv.lock` and testing in a fresh
environment reduced this to 13 advisories in development-only `filelock` 3.32.7,
required by safety/python-discovery/virtualenv through the dev extra. Those
constraints still require follow-up; this PR does **not** claim a clean dev-tool
audit or publish the repository's intentionally ignored lockfile. No production
dependency update was required by the observed audit.

Not established by this review: resistance to exhaustive parser fuzzing or
resource-exhaustion attacks, constant-time behavior of every dependency,
external resolver authorization, revocation, or stateful replay prevention.
Applications must impose input/resource limits and enforce nonce/cti replay
state and any required expiry/claims profile. CWT permits absent expiry, so the
library cannot invent a maximum lifetime for such credentials. Critical claims
that a verifier requires must not be left undisclosed. Alternative hashes,
complete algorithm/profile coverage, and the Rust header-172 placement difference
remain separate interoperability work.
