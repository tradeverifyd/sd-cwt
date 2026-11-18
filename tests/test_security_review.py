"""Signed adversarial presentations; signature failure is not the rejection oracle."""

import time

import pytest

from sd_cwt import cbor_utils as cbor
from sd_cwt.cose_sign1 import cose_sign1_sign
from sd_cwt.redaction import hash_disclosure
from sd_cwt.signers import CredentialSigner, PresentationSigner
from sd_cwt.simple_api import SDCWTVerifier
from sd_cwt.thumbprint import CoseKeyThumbprint
from test_draft_examples import FIXTURES, _cose_private_key

ISSUER = _cose_private_key(FIXTURES / "issuer_privkey.pem", 2)
HOLDER = _cose_private_key(FIXTURES / "holder_privkey.pem", 1)
AUD = "https://verifier.example/app"
NOW = int(time.time())


def token(claims=None, kbt=None, header=None, holder=HOLDER, unprotected=None, kbt_header=None):
    payload = {
        1: "issuer",
        2: "holder",
        6: NOW - 10,
        4: NOW + 3600,
        8: {1: {k: v for k, v in HOLDER.items() if k != -4}},
    }
    payload.update(claims or {})
    sd = cose_sign1_sign(
        cbor.encode(payload),
        CredentialSigner(ISSUER),
        protected_header={16: 293, 170: -16, **(header or {})},
        unprotected_header=unprotected,
    )
    kp = {3: AUD, 6: NOW}
    kp.update(kbt or {})
    return cose_sign1_sign(
        cbor.encode(kp),
        PresentationSigner(holder),
        protected_header={16: 294, 13: cbor.decode(sd), **(kbt_header or {})},
    )


def verify(t, **kw):
    return SDCWTVerifier(lambda kid: ISSUER).verify_presentation(t, AUD, **kw)[0]


def test_positive_control():
    assert verify(token())


@pytest.mark.parametrize(
    "claims,kbt",
    [
        ({4: NOW - 1}, {}),
        ({5: NOW + 100}, {}),
        ({}, {4: NOW - 1}),
        ({}, {5: NOW + 100}),
        ({4: float("nan")}, {}),
        ({}, {6: True}),
        ({5: NOW + 10, 4: NOW - 10}, {}),
        ({4: NOW + 10}, {6: NOW + 20}),
    ],
)
def test_reject_invalid_time_claims(claims, kbt):
    assert not verify(token(claims, kbt))


def test_resolver_must_return_the_key_named_by_cnf():
    victim = CoseKeyThumbprint.compute(HOLDER)
    assert not verify(token({8: {3: victim}}, holder=ISSUER), holder_key_resolver=lambda _: ISSUER)
    assert verify(token({8: {3: victim}}), holder_key_resolver=lambda _: HOLDER)


def test_issuer_audience_is_enforced():
    assert not verify(token({3: "another verifier"}))


def test_disclosed_audience_is_enforced():
    d = cbor.encode([b"a" * 16, "another verifier", 3])
    assert not verify(
        token({cbor.create_simple_value(59): [hash_disclosure(d)]}, unprotected={17: [d]})
    )


def test_claim_alias_cannot_overwrite_authenticated_issuer():
    assert not verify(token({"iss": "attacker-controlled alias"}))


@pytest.mark.parametrize("header", [{2: [999], 999: True}, {16: 294}])
def test_unknown_critical_header_or_wrong_credential_type(header):
    assert not verify(token(header=header))


def test_duplicate_protected_unprotected_parameter():
    assert not verify(token(unprotected={1: -35}))


def test_expiry_boundary_and_explicit_clock():
    t = token({4: NOW}, {6: NOW - 1})
    assert not verify(t, now=NOW)
    assert verify(t, now=NOW, leeway=1)
    assert verify(t, now=NOW - 1, leeway=1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, True])
def test_invalid_leeway_is_rejected(bad):
    assert not verify(token(), leeway=bad)


def test_nonce_is_checked_when_required():
    t = token(kbt={39: b"challenge"})
    assert verify(t, expected_nonce=b"challenge")
    assert not verify(t, expected_nonce=b"other")
    assert not verify(token(), expected_nonce=b"challenge")


def test_ambiguous_cnf_rejected():
    assert not verify(token({8: {1: HOLDER, 3: CoseKeyThumbprint.compute(HOLDER)}}))


def test_unmatched_decoy_rejected():
    assert not verify(token(unprotected={17: [cbor.encode([b"d" * 16])]}))


def test_understood_critical_algorithm_allowed():
    assert verify(token(header={2: [1]}))


def test_failures_do_not_log_resolver_secrets(capsys):
    def failing(_):
        raise ValueError("sensitive-resolver-details")

    assert not SDCWTVerifier(failing).verify_presentation(token(), AUD)[0]
    assert capsys.readouterr() == ("", "")


def test_kbt_issuance_must_precede_issuer_expiry_even_with_leeway():
    assert verify(token({4: NOW}, {6: NOW - 1}), now=NOW, leeway=10)
    assert not verify(token({4: NOW}, {6: NOW}), now=NOW, leeway=10)


@pytest.mark.parametrize("typ", [293, "application/sd-cwt", "application/example+sd-cwt"])
def test_spec_credential_types(typ):
    assert verify(token(header={16: typ}))


@pytest.mark.parametrize(
    "typ", ["application/sd+cwt", "application/+sd-cwt", "not a media type+sd-cwt"]
)
def test_reject_incorrect_credential_types(typ):
    assert not verify(token(header={16: typ}))


def test_kbt_cannot_carry_cwt_claims_header():
    assert not verify(token(kbt_header={15: {3: AUD}}))
