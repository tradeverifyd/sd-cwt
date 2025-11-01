"""EDN redaction and disclosure handling for SD-CWT."""

import hashlib
import secrets
from typing import Any, Optional, Protocol

from . import cbor_utils, edn_utils

# CBOR tags for redaction (from SD-CWT spec and guide.md)
REDACTED_CLAIM_KEY_TAG = 58  # Tag for to-be-redacted claim keys in EDN
REDACTED_CLAIM_ELEMENT_TAG = 58  # Tag for to-be-redacted array elements in EDN


class SaltGenerator(Protocol):
    """Protocol for generating cryptographic salts for disclosures."""

    def generate_salt(self, length: int = 16) -> bytes:
        """Generate a cryptographic salt.

        Args:
            length: Salt length in bytes (default 16 for 128 bits)

        Returns:
            Random salt bytes
        """


class SecureSaltGenerator:
    """Cryptographically secure salt generator using secrets module."""

    def generate_salt(self, length: int = 16) -> bytes:
        """Generate a cryptographically secure salt.

        Args:
            length: Salt length in bytes (default 16 for 128 bits)

        Returns:
            Cryptographically secure random salt bytes
        """
        return secrets.token_bytes(length)


class SeededSaltGenerator:
    """Deterministic salt generator for testing purposes.

    WARNING: This generator is NOT cryptographically secure and should
    only be used for testing and reproducible examples.
    """

    def __init__(self, seed: int = 42):
        """Initialize with a seed value.

        Args:
            seed: Integer seed for deterministic salt generation
        """
        import random

        self._random = random.Random(seed)

    def generate_salt(self, length: int = 16) -> bytes:
        """Generate a deterministic salt based on the seed.

        Args:
            length: Salt length in bytes (default 16 for 128 bits)

        Returns:
            Deterministic salt bytes (NOT cryptographically secure)
        """
        return bytes(self._random.getrandbits(8) for _ in range(length))


# Default secure salt generator instance
_default_salt_generator = SecureSaltGenerator()


def parse_edn_to_cbor(edn_string: str) -> bytes:
    """Parse EDN string to CBOR bytes.

    Args:
        edn_string: Extended Diagnostic Notation string

    Returns:
        CBOR-encoded bytes
    """
    return edn_utils.diag_to_cbor(edn_string)


def cbor_to_dict(cbor_bytes: bytes) -> dict[Any, Any]:
    """Convert CBOR bytes to dictionary.

    Args:
        cbor_bytes: CBOR-encoded bytes

    Returns:
        Decoded dictionary
    """
    return cbor_utils.decode(cbor_bytes)


def generate_salt(length: int = 16, salt_generator: Optional[SaltGenerator] = None) -> bytes:
    """Generate cryptographically secure random salt.

    Args:
        length: Salt length in bytes (default 16 for 128 bits)
        salt_generator: Optional custom salt generator (uses secure default if None)

    Returns:
        Random salt bytes
    """
    if salt_generator is None:
        salt_generator = _default_salt_generator
    return salt_generator.generate_salt(length)


def create_disclosure(salt: bytes, claim_name: Any, claim_value: Any) -> bytes:
    """Create a disclosure array for a claim.

    SD-CWT format: [salt, value, key]

    Args:
        salt: Random salt bytes
        claim_name: Name/key of the claim
        claim_value: Value of the claim

    Returns:
        CBOR-encoded disclosure array
    """
    disclosure_array = [salt, claim_value, claim_name]
    return cbor_utils.encode(disclosure_array)


def hash_disclosure(disclosure: bytes, hash_alg: str = "sha-256") -> bytes:
    """Hash a disclosure.

    Args:
        disclosure: CBOR-encoded disclosure array
        hash_alg: Hash algorithm name

    Returns:
        Hash digest bytes
    """
    if hash_alg == "sha-256":
        return hashlib.sha256(disclosure).digest()
    elif hash_alg == "sha-384":
        return hashlib.sha384(disclosure).digest()
    elif hash_alg == "sha-512":
        return hashlib.sha512(disclosure).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_alg}")


def find_redacted_claims(claims: dict[Any, Any]) -> list[tuple[list[Any], Any]]:
    """Recursively find all redacted claims in a claims dictionary.

    Per SD-CWT specification: cnf (8), cnonce (39), and standard claims
    other than subject (2) MUST NOT be redacted.

    Args:
        claims: Claims dictionary potentially containing redaction tags

    Returns:
        List of (path, value) tuples for redacted claims
    """
    # Claims that are mandatory to disclose (MUST NOT be redacted) per specification
    MANDATORY_TO_DISCLOSE_CLAIMS = {
        1,  # iss - issuer
        3,  # aud - audience
        4,  # exp - expiration
        5,  # nbf - not before
        6,  # iat - issued at
        7,  # cti - CWT ID
        8,  # cnf - confirmation (holder binding)
        39,  # cnonce - client nonce
    }

    redacted = []

    def _traverse(obj: Any, path: list[Any]) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = path + [key]

                # Skip mandatory-to-disclose claims at top level (path is empty)
                if not path and key in MANDATORY_TO_DISCLOSE_CLAIMS:
                    # Continue traversing into the value but don't redact the key
                    if isinstance(value, (dict, list)):
                        _traverse(value, current_path)
                    continue

                # Check if value is tagged for redaction
                if cbor_utils.is_tag(value):
                    if value.tag == REDACTED_CLAIM_KEY_TAG:
                        # This is a redacted claim - the key should be redacted
                        redacted.append((path, key))
                    elif value.tag == REDACTED_CLAIM_ELEMENT_TAG:
                        # This is a redacted key where the value is an array/object
                        # The key itself should be redacted, not the elements
                        redacted.append((path, key))
                elif isinstance(value, (dict, list)):
                    _traverse(value, current_path)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if cbor_utils.is_tag(item, REDACTED_CLAIM_ELEMENT_TAG):
                    redacted.append((path + [i], item.value))
                elif isinstance(item, (dict, list)):
                    _traverse(item, path + [i])

    _traverse(claims, [])
    return redacted


def process_redactions(
    claims: dict[Any, Any],
    redacted_paths: list[tuple[list[Any], Any]],
    salt_generator: Optional[SaltGenerator] = None,
) -> tuple[dict[Any, Any], list[bytes], list[bytes]]:
    """Process redactions and create disclosures.

    Args:
        claims: Original claims dictionary
        redacted_paths: List of (path, key/value) tuples to redact
        salt_generator: Optional custom salt generator (uses secure default if None)

    Returns:
        Tuple of (redacted_claims, disclosures, map_key_hashes)
        map_key_hashes: Only the hashes for redacted map keys (for simple(59))
    """

    # Manual deep copy to handle CBOR tags
    def deep_copy_claims(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: deep_copy_claims(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [deep_copy_claims(item) for item in obj]
        elif cbor_utils.is_tag(obj):
            # Unwrap CBOR tags during copy
            return deep_copy_claims(obj.value)
        else:
            return obj

    redacted_claims = deep_copy_claims(claims)
    disclosures = []
    map_key_hashes = []  # Only for redacted map keys (goes into simple(59))

    # Sort paths by depth (deepest first) to avoid modifying parent before child
    sorted_paths = sorted(redacted_paths, key=lambda x: len(x[0]), reverse=True)

    for path, claim_key in sorted_paths:
        # Navigate to the container
        container = redacted_claims
        parent = None
        last_step = None

        for step in path:
            parent = container
            last_step = step
            container = container[step]

        # Handle different redaction cases
        if path:  # Nested redaction
            if isinstance(container, dict) and claim_key in container:
                # Redacting a key in nested dict
                salt = generate_salt(salt_generator=salt_generator)
                claim_value = container[claim_key]

                disclosure = create_disclosure(salt, claim_key, claim_value)
                disclosures.append(disclosure)

                hash_digest = hash_disclosure(disclosure)
                map_key_hashes.append(hash_digest)  # Map key hash goes to simple(59)

                del container[claim_key]
            elif isinstance(parent, list) and isinstance(last_step, int):
                # Redacting an array element
                salt = generate_salt(salt_generator=salt_generator)

                # The claim_key here is actually the value for array elements
                disclosure = create_disclosure(salt, last_step, claim_key)
                disclosures.append(disclosure)

                hash_digest = hash_disclosure(disclosure)
                # Array element hash does NOT go to simple(59) - it's replaced in-place with tag 60

                # Replace array element with tag 60 wrapped hash (per specification)
                parent[last_step] = cbor_utils.create_tag(60, hash_digest)
        else:  # Top-level redaction
            if isinstance(redacted_claims, dict) and claim_key in redacted_claims:
                salt = generate_salt(salt_generator=salt_generator)
                claim_value = redacted_claims[claim_key]

                disclosure = create_disclosure(salt, claim_key, claim_value)
                disclosures.append(disclosure)

                hash_digest = hash_disclosure(disclosure)
                map_key_hashes.append(hash_digest)  # Top-level map key hash goes to simple(59)

                del redacted_claims[claim_key]

    # No need to clean arrays - redacted elements are replaced with tag 60 hashes

    return redacted_claims, disclosures, map_key_hashes


def build_sd_cwt_claims(claims: dict[Any, Any], map_key_hashes: list[bytes]) -> dict[Any, Any]:
    """Build SD-CWT claims with redacted map key hashes.

    Args:
        claims: Claims dictionary with redacted items processed
        map_key_hashes: List of hashes for redacted map keys only

    Returns:
        SD-CWT claims dictionary with simple value 59 for map key hashes
    """
    sd_cwt_claims = claims.copy()

    if map_key_hashes:
        # Use CBOR simple value 59 as the key for redacted map key hashes only
        sd_cwt_claims[cbor_utils.create_simple_value(59)] = map_key_hashes

    return sd_cwt_claims


def edn_to_redacted_cbor(
    edn_string: str, salt_generator: Optional[SaltGenerator] = None
) -> tuple[bytes, list[bytes]]:
    """Convert EDN with redaction tags to redacted CBOR claims.

    This is the main spanning function that:
    1. Parses EDN to CBOR
    2. Identifies redacted claims
    3. Creates disclosures
    4. Builds final SD-CWT claims

    Args:
        edn_string: EDN string with redaction tags
        salt_generator: Optional custom salt generator (uses secure default if None)

    Returns:
        Tuple of (cbor_claims, disclosures)
    """
    # Parse EDN to CBOR and then to dict
    cbor_bytes = parse_edn_to_cbor(edn_string)
    claims = cbor_to_dict(cbor_bytes)

    # Find all redacted claims
    redacted_paths = find_redacted_claims(claims)

    # Process redactions
    redacted_claims, disclosures, map_key_hashes = process_redactions(
        claims, redacted_paths, salt_generator
    )

    # Build SD-CWT claims
    sd_cwt_claims = build_sd_cwt_claims(redacted_claims, map_key_hashes)

    # Encode to CBOR
    cbor_claims = cbor_utils.encode(sd_cwt_claims)

    return cbor_claims, disclosures
