"""Explicit historical clocks for public draft vectors; never disables validation."""

from sd_cwt import cbor_utils as cbor
from sd_cwt.simple_api import SDCWTVerifier
from test_draft_examples import ISSUER_PUBLIC_KEY


def issuance_time(token):
    payload = cbor.decode(cbor.get_tag_value(cbor.decode(token))[2])
    return max(payload.get(5, 0), payload.get(6, 0), 1725244200) + 1


def verify_fixture(token, audience, **kwargs):
    payload = cbor.decode(cbor.get_tag_value(cbor.decode(token))[2])
    return SDCWTVerifier(lambda kid: ISSUER_PUBLIC_KEY).verify_presentation(
        token, audience, now=payload.get(6, 1725244300), **kwargs
    )
