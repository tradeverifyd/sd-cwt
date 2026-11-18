"""Checks on authenticated, reconstructed CWT claims (RFC 8392 and draft-08)."""

import math
import time
from typing import Any, Optional


def validate_presentation_claims(
    credential: dict[Any, Any],
    presentation: dict[Any, Any],
    audience: str,
    now: Optional[float] = None,
    leeway: float = 0,
    expected_nonce: Optional[bytes] = None,
) -> None:
    """Raise on invalid claims. An explicit clock supports historical fixtures."""
    now = time.time() if now is None else now

    def numeric(value: Any) -> bool:
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        )

    if not numeric(now) or not numeric(leeway) or leeway < 0:
        raise ValueError("invalid verification clock or leeway")
    if not isinstance(audience, str) or not audience:
        raise ValueError("expected audience is required")
    if not isinstance(credential, dict) or not isinstance(presentation, dict):
        raise ValueError("claims must be maps")
    for claims in (credential, presentation):
        if 3 in claims:
            aud = claims[3]
            if not (isinstance(aud, str) and aud == audience):
                raise ValueError("audience mismatch")
        for label in (4, 5, 6):
            if label in claims and not numeric(claims[label]):
                raise ValueError("time claim must be a finite number")
        if 4 in claims and now >= claims[4] + leeway:
            raise ValueError("token expired")
        if 5 in claims and now + leeway < claims[5]:
            raise ValueError("token not yet valid")
        if 6 in claims and now + leeway < claims[6]:
            raise ValueError("token issued in the future")
        for a, b, strict in [(5, 6, False), (5, 4, True), (6, 4, True)]:
            if (
                a in claims
                and b in claims
                and (claims[a] >= claims[b] if strict else claims[a] > claims[b])
            ):
                raise ValueError("inconsistent time claims")
    if 3 not in presentation or 1 in presentation or 2 in presentation:
        raise ValueError("invalid KBT registered claims")
    if 6 not in presentation and (7 not in presentation or 4 in presentation or 5 in presentation):
        raise ValueError("KBT requires iat or cti; exp/nbf require iat")
    if 7 in presentation and not isinstance(presentation[7], bytes):
        raise ValueError("cti must be a byte string")
    for p, c, relation in [
        (4, 4, "max"),
        (5, 5, "min"),
        (6, 6, "min"),
        (6, 5, "min"),
        (6, 4, "max"),
        (5, 4, "strictmax"),
    ]:
        if p in presentation and c in credential:
            a, b = presentation[p], credential[c]
            if (
                (relation == "max" and a > b)
                or (relation == "min" and a < b)
                or (relation == "strictmax" and a >= b)
            ):
                raise ValueError("KBT time lies outside credential validity")
    if 39 in presentation and not isinstance(presentation[39], bytes):
        raise ValueError("cnonce must be a byte string")
    if expected_nonce is not None and (
        not isinstance(expected_nonce, bytes) or presentation.get(39) != expected_nonce
    ):
        raise ValueError("nonce mismatch")
