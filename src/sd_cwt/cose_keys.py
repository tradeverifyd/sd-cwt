"""COSE Key generation and management."""

from enum import IntEnum
from typing import Any, Optional

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from cryptography.hazmat.backends import default_backend


class CoseAlgorithm(IntEnum):
    """COSE Algorithm identifiers."""

    ES256 = -7   # ECDSA w/ SHA-256
    ES384 = -35  # ECDSA w/ SHA-384
    ES512 = -36  # ECDSA w/ SHA-512
    EdDSA = -8   # EdDSA (Ed25519 or Ed448)
    Ed25519 = -8  # Alias for EdDSA with Ed25519
    Ed448 = -8    # Note: Both use -8, curve is determined by key type


class CoseKeyType(IntEnum):
    """COSE Key Type identifiers."""

    OKP = 1  # Octet Key Pair (EdDSA)
    EC2 = 2  # Elliptic Curve Keys w/ x,y coordinate pair


class CoseEllipticCurve(IntEnum):
    """COSE Elliptic Curve identifiers."""

    P256 = 1   # NIST P-256
    P384 = 2   # NIST P-384
    P521 = 3   # NIST P-521
    X25519 = 4  # X25519 for ECDH only
    X448 = 5    # X448 for ECDH only
    Ed25519 = 6  # Ed25519 for EdDSA
    Ed448 = 7    # Ed448 for EdDSA


def cose_key_generate(
    algorithm: CoseAlgorithm = CoseAlgorithm.ES256,
    key_id: Optional[bytes] = None
) -> bytes:
    """Generate a COSE key pair in CBOR format.

    Args:
        algorithm: The COSE algorithm to use (defaults to ES256)
        key_id: Optional key identifier (kid parameter)

    Returns:
        CBOR-encoded COSE_Key containing both private and public key material

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm == CoseAlgorithm.ES256:
        return _generate_ec_key(ec.SECP256R1(), CoseEllipticCurve.P256, algorithm, key_id)
    elif algorithm == CoseAlgorithm.ES384:
        return _generate_ec_key(ec.SECP384R1(), CoseEllipticCurve.P384, algorithm, key_id)
    elif algorithm == CoseAlgorithm.ES512:
        return _generate_ec_key(ec.SECP521R1(), CoseEllipticCurve.P521, algorithm, key_id)
    elif algorithm in (CoseAlgorithm.EdDSA, CoseAlgorithm.Ed25519):
        return _generate_okp_key(ed25519.Ed25519PrivateKey, CoseEllipticCurve.Ed25519, algorithm, key_id)
    elif algorithm == CoseAlgorithm.Ed448:
        return _generate_okp_key(ed448.Ed448PrivateKey, CoseEllipticCurve.Ed448, algorithm, key_id)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _generate_ec_key(
    curve: ec.EllipticCurve,
    crv_id: CoseEllipticCurve,
    alg: CoseAlgorithm,
    key_id: Optional[bytes] = None
) -> bytes:
    """Generate an EC2 COSE key.

    Args:
        curve: The elliptic curve to use
        crv_id: COSE curve identifier
        alg: COSE algorithm identifier
        key_id: Optional key identifier

    Returns:
        CBOR-encoded COSE_Key
    """
    # Generate private key
    private_key = ec.generate_private_key(curve, default_backend())

    # Get private key value
    private_value = private_key.private_numbers().private_value

    # Determine byte length based on curve
    if isinstance(curve, ec.SECP256R1):
        byte_length = 32
    elif isinstance(curve, ec.SECP384R1):
        byte_length = 48
    elif isinstance(curve, ec.SECP521R1):
        byte_length = 66  # P-521 uses 521 bits = 66 bytes
    else:
        raise ValueError(f"Unsupported curve: {curve}")

    d = private_value.to_bytes(byte_length, byteorder='big')

    # Get public key coordinates
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    x = public_numbers.x.to_bytes(byte_length, byteorder='big')
    y = public_numbers.y.to_bytes(byte_length, byteorder='big')

    # Build COSE_Key structure
    cose_key = {
        1: CoseKeyType.EC2,  # kty: EC2
        3: int(alg),         # alg: Algorithm
        -1: int(crv_id),     # crv: Curve
        -2: x,               # x: x-coordinate
        -3: y,               # y: y-coordinate
        -4: d,               # d: private key
    }

    # Add key ID if provided
    if key_id is not None:
        cose_key[2] = key_id  # kid: Key ID

    return cbor2.dumps(cose_key)


def _generate_okp_key(
    key_class: type,
    crv_id: CoseEllipticCurve,
    alg: CoseAlgorithm,
    key_id: Optional[bytes] = None
) -> bytes:
    """Generate an OKP COSE key.

    Args:
        key_class: The key class to use (Ed25519PrivateKey or Ed448PrivateKey)
        crv_id: COSE curve identifier
        alg: COSE algorithm identifier
        key_id: Optional key identifier

    Returns:
        CBOR-encoded COSE_Key
    """
    # Generate private key
    if key_class == ed25519.Ed25519PrivateKey:
        private_key = ed25519.Ed25519PrivateKey.generate()
        # Get raw private key bytes (32 bytes for Ed25519)
        d = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Get public key bytes
        public_key = private_key.public_key()
        x = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    elif key_class == ed448.Ed448PrivateKey:
        private_key = ed448.Ed448PrivateKey.generate()
        # Get raw private key bytes (57 bytes for Ed448)
        d = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Get public key bytes
        public_key = private_key.public_key()
        x = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        raise ValueError(f"Unsupported key class: {key_class}")

    # Build COSE_Key structure for OKP
    cose_key = {
        1: CoseKeyType.OKP,  # kty: OKP
        3: int(alg),         # alg: Algorithm
        -1: int(crv_id),     # crv: Curve
        -2: x,               # x: public key
        -4: d,               # d: private key
    }

    # Add key ID if provided
    if key_id is not None:
        cose_key[2] = key_id  # kid: Key ID

    return cbor2.dumps(cose_key)


def cose_key_from_dict(key_dict: dict[int, Any]) -> bytes:
    """Convert a COSE key dictionary to CBOR bytes.

    Args:
        key_dict: COSE key as a dictionary

    Returns:
        CBOR-encoded COSE_Key
    """
    return cbor2.dumps(key_dict)


def cose_key_to_dict(cose_key: bytes) -> dict[int, Any]:
    """Convert a CBOR-encoded COSE key to a dictionary.

    Args:
        cose_key: CBOR-encoded COSE_Key

    Returns:
        COSE key as a dictionary
    """
    return cbor2.loads(cose_key)


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
    """Calculate the thumbprint of a COSE key.

    Args:
        cose_key: CBOR-encoded COSE_Key
        hash_algorithm: Hash algorithm to use (default: "sha-256")

    Returns:
        Thumbprint bytes
    """
    import hashlib

    # Get public key only
    public_key = cose_key_get_public(cose_key)
    key_dict = cose_key_to_dict(public_key)

    # Create canonical representation (sorted by key)
    # Only include required members for thumbprint
    kty = key_dict.get(1)

    if kty == CoseKeyType.EC2:
        # For EC2: kty, crv, x, y
        canonical = {
            1: key_dict[1],   # kty
            -1: key_dict[-1], # crv
            -2: key_dict[-2], # x
            -3: key_dict[-3], # y
        }
    elif kty == CoseKeyType.OKP:
        # For OKP: kty, crv, x
        canonical = {
            1: key_dict[1],   # kty
            -1: key_dict[-1], # crv
            -2: key_dict[-2], # x
        }
    else:
        raise ValueError(f"Unsupported key type: {kty}")

    # Encode canonically
    canonical_cbor = cbor2.dumps(canonical)

    # Calculate hash
    if hash_algorithm == "sha-256":
        return hashlib.sha256(canonical_cbor).digest()
    elif hash_algorithm == "sha-384":
        return hashlib.sha384(canonical_cbor).digest()
    elif hash_algorithm == "sha-512":
        return hashlib.sha512(canonical_cbor).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")