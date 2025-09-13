"""Verifiers for SD-CWT credentials and presentations.

This module provides safe verifier classes for SD-CWT verification:
- CredentialVerifier: Verifies SD-CWT credentials using issuer's key
- PresentationVerifier: Verifies KBT presentations using holder's key
"""

from typing import Any, Optional

from . import cbor_utils
from .cose_sign1 import ES256Verifier, cose_sign1_verify


class CredentialVerifier:
    """Verifies SD-CWT credentials using issuer's public key."""

    def __init__(self, issuer_cose_key: dict[int, Any]):
        """Initialize credential verifier with issuer's COSE key.

        Args:
            issuer_cose_key: Issuer's COSE key dictionary containing public key components
        """
        self.issuer_key = issuer_cose_key
        self._verifier = ES256Verifier(issuer_cose_key[-2], issuer_cose_key[-3])

    def verify(self, sd_cwt: bytes) -> tuple[bool, Optional[dict[int, Any]]]:
        """Verify SD-CWT credential signature.

        Args:
            sd_cwt: CBOR-encoded SD-CWT credential

        Returns:
            Tuple of (is_valid, payload_dict) where payload_dict contains decoded claims
        """
        is_valid, payload_bytes = cose_sign1_verify(sd_cwt, self._verifier)
        if is_valid and payload_bytes:
            payload = cbor_utils.decode(payload_bytes)
            return True, payload
        return False, None


class PresentationVerifier:
    """Verifies KBT presentations using holder's public key."""

    def __init__(self, holder_cose_key: dict[int, Any]):
        """Initialize presentation verifier with holder's COSE key.

        Args:
            holder_cose_key: Holder's COSE key dictionary containing public key components
        """
        self.holder_key = holder_cose_key
        self._verifier = ES256Verifier(holder_cose_key[-2], holder_cose_key[-3])

    def verify(self, kbt: bytes, audience: Optional[str] = None) -> tuple[bool, Optional[dict[int, Any]]]:
        """Verify KBT presentation signature and optionally validate audience.

        Args:
            kbt: CBOR-encoded Key Binding Token
            audience: Expected audience value to validate against KBT's aud claim

        Returns:
            Tuple of (is_valid, payload_dict) where payload_dict contains KBT claims

        Note:
            If audience is provided, verification will fail if the KBT's audience
            claim (field 3) doesn't match the expected value.
        """
        is_valid, payload_bytes = cose_sign1_verify(kbt, self._verifier)
        if is_valid and payload_bytes:
            payload = cbor_utils.decode(payload_bytes)

            # If audience is specified, validate it matches the KBT's aud claim
            if audience is not None:
                kbt_audience = payload.get(3)  # aud claim
                if kbt_audience != audience:
                    return False, None

            return True, payload
        return False, None


def get_presentation_verifier(
    credential: bytes,
    credential_verifier: CredentialVerifier
) -> Optional[PresentationVerifier]:
    """Extract presentation verifier from a verified credential.

    Args:
        credential: CBOR-encoded SD-CWT credential
        credential_verifier: Verifier for the credential

    Returns:
        PresentationVerifier if credential is valid and contains holder key, None otherwise
    """
    # Verify the credential first
    is_valid, payload = credential_verifier.verify(credential)
    if not is_valid or not payload:
        return None

    # Extract cnf claim containing holder key
    cnf_claim = payload.get(8)  # cnf claim
    if not cnf_claim:
        return None

    # Extract holder key from cnf claim
    holder_key = None
    if 1 in cnf_claim:  # Full COSE key
        holder_key = cnf_claim[1]
    elif 3 in cnf_claim:  # COSE Key Thumbprint - not supported for verification
        # Thumbprint cannot be used directly for verification
        return None

    if not holder_key:
        return None

    # Create and return presentation verifier
    return PresentationVerifier(holder_key)

