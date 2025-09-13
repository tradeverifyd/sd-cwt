"""Resolvers for COSE keys and credential verifiers using thumbprints.

This module provides resolution functions that use COSE key thumbprints
to dynamically resolve keys and verifiers from SD-CWT protected headers.
"""

from typing import Any, Callable

from . import cbor_utils
from .thumbprint import CoseKeyThumbprint


def cose_key_thumbprint_resolver(cose_keys: list[bytes]) -> Callable[[bytes], dict[int, Any]]:
    """Create a resolver function for COSE keys based on computed thumbprints.

    Args:
        cose_keys: List of CBOR-encoded COSE keys

    Returns:
        Resolver function that takes a thumbprint and returns the corresponding
        COSE key dictionary

    Raises:
        ValueError: If resolver is called with a thumbprint that doesn't match any key

    Note:
        The resolver computes SHA-256 thumbprints for all provided keys and
        uses cose_key_kid_resolver internally for consistent implementation.
    """
    # Build kid-key pairs using thumbprints as kids
    kid_key_pairs: list[tuple[bytes, bytes]] = []

    for cose_key_cbor in cose_keys:
        # Decode COSE key
        cose_key = cbor_utils.decode(cose_key_cbor)

        # Compute thumbprint to use as kid
        computed_thumbprint = CoseKeyThumbprint.compute(cose_key, "sha256")

        # Add to kid-key pairs with thumbprint as kid
        kid_key_pairs.append((computed_thumbprint, cose_key_cbor))

    # Use cose_key_kid_resolver for the actual resolution
    return cose_key_kid_resolver(kid_key_pairs)


def cose_key_kid_resolver(
    kid_key_pairs: list[tuple[bytes, bytes]],
) -> Callable[[bytes], dict[int, Any]]:
    """Create a resolver function for COSE keys based on key identifiers (kid).

    Args:
        kid_key_pairs: List of tuples where first item is kid in bytestring format
                      and second is cose_key in bytestring format

    Returns:
        Resolver function that takes a kid and returns the corresponding
        COSE key dictionary

    Raises:
        ValueError: If resolver is called with a kid that doesn't match any key

    Note:
        The resolver builds a lookup table mapping kid values to COSE keys.
    """
    # Build lookup table by mapping kids to decoded COSE keys
    kid_to_key: dict[bytes, dict[int, Any]] = {}

    for kid, cose_key_cbor in kid_key_pairs:
        # Decode COSE key
        cose_key = cbor_utils.decode(cose_key_cbor)

        # Store in lookup table
        kid_to_key[kid] = cose_key

    def resolve_public_key(requested_kid: bytes) -> dict[int, Any]:
        """Resolve COSE key by kid.

        Args:
            requested_kid: The key identifier to look up

        Returns:
            COSE key dictionary

        Raises:
            ValueError: If kid is not found in the lookup table
        """
        if requested_kid not in kid_to_key:
            available_kids = [kid.hex()[:16] + "..." for kid in kid_to_key]
            raise ValueError(
                f"Kid not found: {requested_kid.hex()[:16]}... "
                f"Available kids: {', '.join(available_kids)}"
            )

        return kid_to_key[requested_kid]

    return resolve_public_key
