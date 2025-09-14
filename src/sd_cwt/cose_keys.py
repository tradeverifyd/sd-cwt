from . import cbor_utils

"""COSE Key generation and management."""

from typing import Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# Constants for ES256/P-256 only
COSE_ALG_ES256 = -7
COSE_KTY_EC2 = 2
COSE_CRV_P256 = 1


def cose_key_generate(key_id: Optional[bytes] = None) -> bytes:
    """Generate an ES256/P-256 COSE key pair in CBOR format.

    Args:
        key_id: Optional key identifier (kid parameter)

    Returns:
        CBOR-encoded COSE_Key containing both private and public key material for ES256/P-256
    """
    # Generate ES256/P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Get private key value (32 bytes for P-256)
    private_value = private_key.private_numbers().private_value
    d = private_value.to_bytes(32, byteorder='big')

    # Get public key coordinates (32 bytes each for P-256)
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    x = public_numbers.x.to_bytes(32, byteorder='big')
    y = public_numbers.y.to_bytes(32, byteorder='big')

    # Build COSE_Key structure for ES256/P-256
    cose_key = {
        1: COSE_KTY_EC2,    # kty: EC2
        3: COSE_ALG_ES256,  # alg: ES256
        -1: COSE_CRV_P256,  # crv: P-256
        -2: x,              # x: x-coordinate
        -3: y,              # y: y-coordinate
        -4: d,              # d: private key
    }

    # Add key ID if provided
    if key_id is not None:
        cose_key[2] = key_id  # kid: Key ID

    return cbor_utils.encode(cose_key)




def cose_key_from_dict(key_dict: dict[int, Any]) -> bytes:
    """Convert a COSE key dictionary to CBOR bytes.

    Args:
        key_dict: COSE key as a dictionary

    Returns:
        CBOR-encoded COSE_Key
    """
    return cbor_utils.encode(key_dict)


def cose_key_to_dict(cose_key: bytes) -> dict[int, Any]:
    """Convert a CBOR-encoded COSE key to a dictionary.

    Args:
        cose_key: CBOR-encoded COSE_Key

    Returns:
        COSE key as a dictionary
    """
    return cbor_utils.decode(cose_key)


def cose_key_get_public(cose_key: bytes) -> bytes:
    """Extract the public key from a COSE key.

    Args:
        cose_key: CBOR-encoded COSE_Key

    Returns:
        CBOR-encoded COSE_Key containing only public key material
    """
    key_dict = cose_key_to_dict(cose_key)

    # Remove private key parameter
    if -4 in key_dict:
        del key_dict[-4]

    return cose_key_from_dict(key_dict)


def cose_key_thumbprint(cose_key: bytes, hash_algorithm: str = "sha-256") -> bytes:
    """Calculate the thumbprint of an ES256/P-256 COSE key.

    Args:
        cose_key: CBOR-encoded COSE_Key (must be ES256/P-256)
        hash_algorithm: Hash algorithm to use (default: "sha-256")

    Returns:
        Thumbprint bytes
    """
    import hashlib

    # Get public key only
    public_key = cose_key_get_public(cose_key)
    key_dict = cose_key_to_dict(public_key)

    # Verify this is an EC2 key
    kty = key_dict.get(1)
    if kty != COSE_KTY_EC2:
        raise ValueError("Only EC2 keys are supported")

    # For EC2 (P-256): kty, crv, x, y
    canonical = {
        1: key_dict[1],   # kty
        -1: key_dict[-1], # crv
        -2: key_dict[-2], # x
        -3: key_dict[-3], # y
    }

    # Encode canonically
    canonical_cbor = cbor_utils.encode(canonical)

    # Calculate hash
    if hash_algorithm == "sha-256":
        return hashlib.sha256(canonical_cbor).digest()
    elif hash_algorithm == "sha-384":
        return hashlib.sha384(canonical_cbor).digest()
    elif hash_algorithm == "sha-512":
        return hashlib.sha512(canonical_cbor).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
