"""Signers for SD-CWT credentials and presentations.

This module provides safe signer classes that accept COSE key dictionaries:
- CredentialSigner: Signs SD-CWT credentials using issuer's private key
- PresentationSigner: Signs KBT presentations using holder's private key
"""

from typing import Any

from .cose_sign1 import signer_for_cose_key


class CredentialSigner:
    """Signs SD-CWT credentials using issuer's private COSE key."""

    def __init__(self, issuer_cose_key: dict[int, Any]):
        """Initialize credential signer with issuer's COSE key.

        Args:
            issuer_cose_key: Issuer's COSE key dictionary containing private key component (-4)

        Raises:
            KeyError: If private key component is missing
            ValueError: If the key type or algorithm is not supported
        """
        # The algorithm comes from the key, not from an assumption. ES256, ES384
        # and ES512 are all supported; the spec's own Issuer key is P-384.
        self._signer = signer_for_cose_key(issuer_cose_key)

        self.issuer_key = issuer_cose_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the issuer's private key.

        Args:
            message: The message to sign

        Returns:
            The signature bytes
        """
        signature: bytes = self._signer.sign(message)
        return signature

    @property
    def algorithm(self) -> int:
        """Get the COSE algorithm identifier.

        Returns:
            COSE algorithm identifier (-7 ES256, -35 ES384, -36 ES512)
        """
        algorithm: int = self._signer.algorithm
        return algorithm


class PresentationSigner:
    """Signs KBT presentations using holder's private COSE key."""

    def __init__(self, holder_cose_key: dict[int, Any]):
        """Initialize presentation signer with holder's COSE key.

        Args:
            holder_cose_key: Holder's COSE key dictionary containing private key component (-4)

        Raises:
            KeyError: If private key component is missing
            ValueError: If the key type or algorithm is not supported
        """
        # The algorithm comes from the key, not from an assumption. ES256, ES384
        # and ES512 are all supported; the spec's own Issuer key is P-384.
        self._signer = signer_for_cose_key(holder_cose_key)

        self.holder_key = holder_cose_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the holder's private key.

        Args:
            message: The message to sign

        Returns:
            The signature bytes
        """
        signature: bytes = self._signer.sign(message)
        return signature

    @property
    def algorithm(self) -> int:
        """Get the COSE algorithm identifier.

        Returns:
            COSE algorithm identifier (-7 ES256, -35 ES384, -36 ES512)
        """
        algorithm: int = self._signer.algorithm
        return algorithm


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
