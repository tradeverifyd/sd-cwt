"""Verifiers for SD-CWT credentials and presentations.

This module provides safe verifier classes for SD-CWT verification:
- CredentialVerifier: Verifies SD-CWT credentials using issuer's key
- PresentationVerifier: Verifies KBT presentations using holder's key
"""

from typing import Any, Callable, Optional, cast

from . import cbor_utils
from .cose_sign1 import ES256Verifier, cose_sign1_verify


class CredentialVerifier:
    """Verifies SD-CWT credentials using a public key resolver."""

    def __init__(self, public_key_resolver: Callable[[bytes], dict[int, Any]]):
        """Initialize credential verifier with a public key resolver.

        Args:
            public_key_resolver: Function that takes a key identifier and returns
                               the corresponding COSE key dictionary
        """
        self.public_key_resolver = public_key_resolver

    def verify(self, sd_cwt: bytes) -> tuple[bool, Optional[dict[int, Any]]]:
        """Verify SD-CWT credential signature.

        Args:
            sd_cwt: CBOR-encoded SD-CWT credential

        Returns:
            Tuple of (is_valid, payload_dict) where payload_dict contains decoded claims
        """
        # Decode COSE Sign1 structure to extract protected header
        try:
            cose_sign1 = cbor_utils.decode(sd_cwt)

            # Handle CBOR tag wrapping
            if cbor_utils.is_tag(cose_sign1):
                cose_sign1_value = cbor_utils.get_tag_value(cose_sign1)
            else:
                cose_sign1_value = cose_sign1

            if not isinstance(cose_sign1_value, list) or len(cose_sign1_value) != 4:
                return False, None

            # Extract protected header
            protected_header_bytes = cose_sign1_value[0]
            if not protected_header_bytes:
                return False, None

            protected_header = cbor_utils.decode(protected_header_bytes)

            # Extract key identifier (kid) from protected header (key 4)
            kid = protected_header.get(4)
            if not kid:
                return False, None

            # Resolve the public key using the key identifier
            try:
                issuer_key = self.public_key_resolver(kid)
            except ValueError:
                return False, None

            # Create verifier with resolved key
            verifier = ES256Verifier(issuer_key[-2], issuer_key[-3])

            # Verify signature
            is_valid, payload_bytes = cose_sign1_verify(sd_cwt, verifier)
            if is_valid and payload_bytes:
                payload = cbor_utils.decode(payload_bytes)
                # Handle case where payload is double-encoded CBOR
                if isinstance(payload, bytes):
                    payload = cbor_utils.decode(payload)
                return True, payload
            return False, None

        except Exception:
            return False, None


class PresentationVerifier:
    """Verifies KBT presentations using a public key resolver."""

    def __init__(self, public_key_resolver: Callable[[bytes], dict[int, Any]]):
        """Initialize presentation verifier with a public key resolver.

        Args:
            public_key_resolver: Function that takes a key identifier and returns
                               the corresponding COSE key dictionary
        """
        self.public_key_resolver = public_key_resolver

    def verify(
        self, kbt: bytes, audience: Optional[str] = None
    ) -> tuple[bool, Optional[dict[int, Any]]]:
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
        # Decode COSE Sign1 structure to extract protected header
        try:
            cose_sign1 = cbor_utils.decode(kbt)

            # Handle CBOR tag wrapping
            if cbor_utils.is_tag(cose_sign1):
                cose_sign1_value = cbor_utils.get_tag_value(cose_sign1)
            else:
                cose_sign1_value = cose_sign1

            if not isinstance(cose_sign1_value, list) or len(cose_sign1_value) != 4:
                return False, None

            # Extract protected header
            protected_header_bytes = cose_sign1_value[0]
            if not protected_header_bytes:
                return False, None

            protected_header = cbor_utils.decode(protected_header_bytes)

            # Extract key identifier (kid) from protected header (key 4)
            kid = protected_header.get(4)
            if not kid:
                return False, None

            # Resolve the public key using the key identifier
            try:
                holder_key = self.public_key_resolver(kid)
            except ValueError:
                return False, None

            # Create verifier with resolved key
            verifier = ES256Verifier(holder_key[-2], holder_key[-3])

            # Verify signature
            is_valid, payload_bytes = cose_sign1_verify(kbt, verifier)
            if is_valid and payload_bytes:
                payload = cbor_utils.decode(payload_bytes)

                # If audience is specified, validate it matches the KBT's aud claim
                if audience is not None:
                    kbt_audience = payload.get(3)  # aud claim
                    if kbt_audience != audience:
                        return False, None

                return True, payload
            return False, None

        except Exception:
            return False, None


def get_presentation_verifier(
    credential: bytes,
    credential_verifier: CredentialVerifier,
    holder_key_resolver: Optional[Callable[[bytes], dict[int, Any]]] = None,
) -> Optional[PresentationVerifier]:
    """Extract presentation verifier from a verified credential.

    Args:
        credential: CBOR-encoded SD-CWT credential
        credential_verifier: Verifier for the credential
        holder_key_resolver: Optional function to resolve holder keys by identifier.
                           Required only for thumbprint-based cnf claims.

    Returns:
        PresentationVerifier if credential is valid and contains holder key, None otherwise
    """
    # Verify the credential first
    is_valid, payload = credential_verifier.verify(credential)
    if not is_valid or not payload:
        return None

    # Extract cnf claim containing holder key reference
    cnf_claim = payload.get(8)  # cnf claim
    if not cnf_claim:
        return None

    # Check if cnf contains a key thumbprint (key 3) for resolution
    if 3 in cnf_claim:  # COSE Key Thumbprint
        # Use the provided holder key resolver to get the actual key
        if holder_key_resolver is None:
            raise ValueError("holder_key_resolver is required for thumbprint-based cnf claims")

        # Extract the thumbprint from cnf claim
        holder_ckt = cnf_claim[3]  # COSE Key Thumbprint from cnf

        # Resolve the actual key using the thumbprint
        try:
            holder_key = holder_key_resolver(holder_ckt)
        except ValueError:
            return None  # Key not found in resolver

        # Create a resolver for KBT verification using the resolved key's thumbprint
        from .thumbprint import CoseKeyThumbprint

        holder_thumbprint = CoseKeyThumbprint.compute(holder_key, "sha256")

        def ckt_based_resolver(kid: bytes) -> dict[int, Any]:
            # KBTs should use the key's computed thumbprint as kid
            if kid == holder_thumbprint:
                return holder_key
            raise ValueError(f"Key not found: {kid.hex()}")

        return PresentationVerifier(ckt_based_resolver)
    elif 1 in cnf_claim:  # Full COSE key embedded - create single-key resolver
        holder_key = cnf_claim[1]
        # Create a simple resolver for this embedded key using its thumbprint as kid
        from .thumbprint import CoseKeyThumbprint

        holder_thumbprint = CoseKeyThumbprint.compute(holder_key, "sha256")

        def single_key_resolver(kid: bytes) -> dict[int, Any]:
            if kid == holder_thumbprint:
                return cast(dict[int, Any], holder_key)
            raise ValueError(f"Key not found: {kid.hex()}")

        return PresentationVerifier(single_key_resolver)

    return None
