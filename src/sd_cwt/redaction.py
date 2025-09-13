"""EDN redaction and disclosure handling for SD-CWT."""

import hashlib
import secrets
from typing import Any, Optional, Protocol

import cbor2
import cbor_diag  # type: ignore[import-untyped]


# CBOR tags for redaction (from SD-CWT spec)
REDACTED_CLAIM_KEY_TAG = 59  # Simple value for redacted claim keys
REDACTED_CLAIM_ELEMENT_TAG = 60  # Tag for redacted array elements


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
    return cbor_diag.diag2cbor(edn_string)


def cbor_to_dict(cbor_bytes: bytes) -> dict[Any, Any]:
    """Convert CBOR bytes to dictionary.

    Args:
        cbor_bytes: CBOR-encoded bytes

    Returns:
        Decoded dictionary
    """
    return cbor2.loads(cbor_bytes)


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
    return cbor2.dumps(disclosure_array)


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

    Args:
        claims: Claims dictionary potentially containing redaction tags

    Returns:
        List of (path, value) tuples for redacted claims
    """
    redacted = []

    def _traverse(obj: Any, path: list[Any]) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = path + [key]

                # Check if value is tagged for redaction
                if isinstance(value, cbor2.CBORTag):
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
                if isinstance(item, cbor2.CBORTag) and item.tag == REDACTED_CLAIM_ELEMENT_TAG:
                    redacted.append((path + [i], item.value))
                elif isinstance(item, (dict, list)):
                    _traverse(item, path + [i])

    _traverse(claims, [])
    return redacted


def process_redactions(
    claims: dict[Any, Any],
    redacted_paths: list[tuple[list[Any], Any]],
    salt_generator: Optional[SaltGenerator] = None
) -> tuple[dict[Any, Any], list[bytes], list[bytes]]:
    """Process redactions and create disclosures.

    Args:
        claims: Original claims dictionary
        redacted_paths: List of (path, key/value) tuples to redact
        salt_generator: Optional custom salt generator (uses secure default if None)

    Returns:
        Tuple of (redacted_claims, disclosures, hashes)
    """
    # Manual deep copy to handle CBOR tags
    def deep_copy_claims(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: deep_copy_claims(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [deep_copy_claims(item) for item in obj]
        elif isinstance(obj, cbor2.CBORTag):
            # Unwrap CBOR tags during copy
            return deep_copy_claims(obj.value)
        else:
            return obj

    redacted_claims = deep_copy_claims(claims)
    disclosures = []
    hashes = []

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
                hashes.append(hash_digest)

                del container[claim_key]
            elif isinstance(parent, list) and isinstance(last_step, int):
                # Redacting an array element
                salt = generate_salt(salt_generator=salt_generator)

                # The claim_key here is actually the value for array elements
                disclosure = create_disclosure(salt, last_step, claim_key)
                disclosures.append(disclosure)

                hash_digest = hash_disclosure(disclosure)
                hashes.append(hash_digest)

                # Remove the element from array (careful with indices)
                # For now, replace with None and filter later
                parent[last_step] = None
        else:  # Top-level redaction
            if isinstance(redacted_claims, dict) and claim_key in redacted_claims:
                salt = generate_salt(salt_generator=salt_generator)
                claim_value = redacted_claims[claim_key]

                disclosure = create_disclosure(salt, claim_key, claim_value)
                disclosures.append(disclosure)

                hash_digest = hash_disclosure(disclosure)
                hashes.append(hash_digest)

                del redacted_claims[claim_key]

    # Clean up None values from arrays
    def clean_arrays(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: clean_arrays(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [clean_arrays(item) for item in obj if item is not None]
        else:
            return obj

    redacted_claims = clean_arrays(redacted_claims)

    return redacted_claims, disclosures, hashes


def build_sd_cwt_claims(
    claims: dict[Any, Any],
    sd_hashes: list[bytes]
) -> dict[Any, Any]:
    """Build SD-CWT claims with redaction hashes.

    Args:
        claims: Claims dictionary with redacted items removed
        sd_hashes: List of disclosure hashes

    Returns:
        SD-CWT claims dictionary with simple value 59 for hashes
    """
    sd_cwt_claims = claims.copy()

    if sd_hashes:
        # Use CBOR simple value 59 as the key for redacted claim hashes
        sd_cwt_claims[cbor2.CBORSimpleValue(59)] = sd_hashes

    return sd_cwt_claims


def edn_to_redacted_cbor(
    edn_string: str,
    salt_generator: Optional[SaltGenerator] = None
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
    redacted_claims, disclosures, hashes = process_redactions(
        claims, redacted_paths, salt_generator
    )

    # Build SD-CWT claims
    sd_cwt_claims = build_sd_cwt_claims(redacted_claims, hashes)

    # Encode to CBOR
    cbor_claims = cbor2.dumps(sd_cwt_claims)

    return cbor_claims, disclosures