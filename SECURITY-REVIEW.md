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

- Full Python suite: **217 passed**, including a fresh temporary environment
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

The broad development environment initially had 50 advisories. Safety pinned
`filelock<4`, preventing installation of the available fixes. Replaced that dev
tool with `pip-audit` and constrained filelock to >=4.2.1 on Python >=3.11.
The resolved Python 3.13 environment now reports **zero known advisories**, including
development dependencies. CI runs pip-audit as a required check instead of hiding
its exit status. The ignored local lockfile is still not published. This result
does not certify older Python development environments: the fixed filelock line
requires Python >=3.11, and the new audit tool requires Python >=3.10.

Follow-up: full Black, Ruff, and MyPy checks pass. Reconstruction annotations were
corrected, and MyPy's target moved to its minimum supported Python 3.10 (the
runtime metadata remains unchanged). A signed regression now enforces KBT
`iat < credential exp` even with clock leeway. Leeway changes wall-clock checks,
not the logical relationship between signed claims.

The expanded cross-implementation experiment adds Rust Holder nested/array
production, typed thumbprint contexts, AES-256, and partial parent/child encryption.
Unlike the narrower 316-case run, it exposes non-default algorithm incompatibility:
Rust reads/writes header 172 in unprotected headers. No production compatibility
fallback was added to weaken protected-header or duplicate-header validation.

Not established by this review: resistance to exhaustive parser fuzzing or
resource-exhaustion attacks, constant-time behavior of every dependency,
external resolver authorization, revocation, or stateful replay prevention.
Applications must impose input/resource limits and enforce nonce/cti replay
state and any required expiry/claims profile. CWT permits absent expiry, so the
library cannot invent a maximum lifetime for such credentials. Critical claims
that a verifier requires must not be left undisclosed. Alternative hashes,
complete algorithm/profile coverage, and the Rust header-172 placement difference
remain separate interoperability work.

## Spec-first follow-up

The accepted credential media type is `application/sd-cwt`, not
`application/sd+cwt`. Signed positive controls cover content-format 293, the
registered media type, and an application subtype with `+sd-cwt`; negative
controls cover the incorrect spelling and malformed types. KBT protected
header 15 (CWT Claims) is rejected as required by the current draft.

Expanded encrypted-profile evidence: **511 passed, 20 failed, 8 blocked out of
539 checks**. Every failure involves Rust AES-256/header-172 handling; blocked
negative cases have a failed positive control and do not count as demonstrated
rejections. The 261-case suite reports 259 passes and two Rust failures (header
placement and protected AES-256 selection). The original 54 default-algorithm
cross-pair assertions pass. Counts overlap and must not be added.

These results do not establish full specification conformance or maximal
interoperability. Remaining coverage includes complete issuance/Holder validation,
all permitted signature/hash and confirmation-method profiles, claims split
between payload and protected header 15, full map-key/nesting rules, and stateful
replay/revocation. Default AES-128 interoperability does not make Rust's header
placement conformant. No fallback reads an algorithm from unprotected header 172
or suppresses a duplicate-header error to increase the passing count.
