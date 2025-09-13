"""Signers for SD-CWT credentials and presentations.

This module provides safe signer classes that accept COSE key dictionaries:
- CredentialSigner: Signs SD-CWT credentials using issuer's private key
- PresentationSigner: Signs KBT presentations using holder's private key
"""

from typing import Any

from .cose_sign1 import ES256Signer


class CredentialSigner:
    """Signs SD-CWT credentials using issuer's private COSE key."""

    def __init__(self, issuer_cose_key: dict[int, Any]):
        """Initialize credential signer with issuer's COSE key.

        Args:
            issuer_cose_key: Issuer's COSE key dictionary containing private key component (-4)

        Raises:
            KeyError: If private key component is missing
            ValueError: If key type is not supported
        """
        if -4 not in issuer_cose_key:
            raise KeyError("Private key component (-4) missing from COSE key")

        kty = issuer_cose_key.get(1)
        if kty != 2:
            raise ValueError(f"Only EC2 keys are supported, got kty: {kty}")

        alg = issuer_cose_key.get(3)
        if alg != -7:
            raise ValueError(f"Only ES256 algorithm is supported, got alg: {alg}")

        self.issuer_key = issuer_cose_key
        self._signer = ES256Signer(issuer_cose_key[-4])

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the issuer's private key.

        Args:
            message: The message to sign

        Returns:
            The signature bytes
        """
        return self._signer.sign(message)

    @property
    def algorithm(self) -> int:
        """Get the COSE algorithm identifier.

        Returns:
            COSE algorithm identifier (-7 for ES256)
        """
        return self._signer.algorithm


class PresentationSigner:
    """Signs KBT presentations using holder's private COSE key."""

    def __init__(self, holder_cose_key: dict[int, Any]):
        """Initialize presentation signer with holder's COSE key.

        Args:
            holder_cose_key: Holder's COSE key dictionary containing private key component (-4)

        Raises:
            KeyError: If private key component is missing
            ValueError: If key type is not supported
        """
        if -4 not in holder_cose_key:
            raise KeyError("Private key component (-4) missing from COSE key")

        kty = holder_cose_key.get(1)
        if kty != 2:
            raise ValueError(f"Only EC2 keys are supported, got kty: {kty}")

        alg = holder_cose_key.get(3)
        if alg != -7:
            raise ValueError(f"Only ES256 algorithm is supported, got alg: {alg}")

        self.holder_key = holder_cose_key
        self._signer = ES256Signer(holder_cose_key[-4])

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the holder's private key.

        Args:
            message: The message to sign

        Returns:
            The signature bytes
        """
        return self._signer.sign(message)

    @property
    def algorithm(self) -> int:
        """Get the COSE algorithm identifier.

        Returns:
            COSE algorithm identifier (-7 for ES256)
        """
        return self._signer.algorithm


def create_credential_signer(issuer_cose_key: dict[int, Any]) -> CredentialSigner:
    """Create a credential signer from an issuer's COSE key.

    Args:
        issuer_cose_key: Issuer's COSE key dictionary with private component

    Returns:
        CredentialSigner instance
    """
    return CredentialSigner(issuer_cose_key)


def create_presentation_signer(holder_cose_key: dict[int, Any]) -> PresentationSigner:
    """Create a presentation signer from a holder's COSE key.

    Args:
        holder_cose_key: Holder's COSE key dictionary with private component

    Returns:
        PresentationSigner instance
    """
    return PresentationSigner(holder_cose_key)
