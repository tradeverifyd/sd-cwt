from . import cbor_utils
"""COSE Key Thumbprint computation according to RFC 9679."""

import hashlib
from typing import Any



class CoseKeyThumbprint:
    """Compute COSE Key Thumbprints according to RFC 9679."""

    # Required members for each key type according to RFC 9679
    REQUIRED_MEMBERS = {
        # OKP (kty = 1)
        1: [1, -1, -2],  # kty, crv, x
        # EC2 (kty = 2)
        2: [1, -1, -2, -3],  # kty, crv, x, y
        # RSA (kty = 3)
        3: [1, -1, -2],  # kty, n, e
        # Symmetric (kty = 4)
        4: [1, -1],  # kty, k
    }

    @staticmethod
    def canonical_cbor(cose_key: dict[int, Any]) -> bytes:
        """Create canonical CBOR representation of COSE key for thumbprint.

        Args:
            cose_key: COSE key as a dictionary with integer labels

        Returns:
            Canonical CBOR encoding of the key

        Raises:
            ValueError: If key type is unsupported or required fields are missing
        """
        # Get key type
        kty = cose_key.get(1)
        if kty not in CoseKeyThumbprint.REQUIRED_MEMBERS:
            raise ValueError(f"Unsupported key type: {kty}")

        # Get required members for this key type
        required = CoseKeyThumbprint.REQUIRED_MEMBERS[kty]

        # Create filtered key with only required members
        filtered_key = {}
        for label in required:
            if label not in cose_key:
                raise ValueError(f"Required field {label} missing from COSE key")
            filtered_key[label] = cose_key[label]

        # Sort by key label for canonical ordering
        sorted_key = dict(sorted(filtered_key.items()))

        # Encode to CBOR
        return cbor_utils.encode(sorted_key, canonical=True)

    @staticmethod
    def compute(cose_key: dict[int, Any], hash_alg: str = "sha256") -> bytes:
        """Compute COSE Key Thumbprint.

        Args:
            cose_key: COSE key as a dictionary with integer labels
            hash_alg: Hash algorithm to use (sha256, sha384, sha512)

        Returns:
            Thumbprint as bytes

        Raises:
            ValueError: If hash algorithm is unsupported
        """
        # Get canonical CBOR
        canonical = CoseKeyThumbprint.canonical_cbor(cose_key)

        # Hash the canonical representation
        if hash_alg == "sha256":
            return hashlib.sha256(canonical).digest()
        elif hash_alg == "sha384":
            return hashlib.sha384(canonical).digest()
        elif hash_alg == "sha512":
            return hashlib.sha512(canonical).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

    @staticmethod
    def uri(cose_key: dict[int, Any], hash_alg: str = "sha256") -> str:
        """Compute COSE Key Thumbprint URI.

        Args:
            cose_key: COSE key as a dictionary with integer labels
            hash_alg: Hash algorithm to use

        Returns:
            Thumbprint URI as defined in RFC 9679
        """
        import base64

        thumbprint = CoseKeyThumbprint.compute(cose_key, hash_alg)
        b64url = base64.urlsafe_b64encode(thumbprint).rstrip(b"=").decode("ascii")

        # URI format: urn:ietf:params:oauth:ckt:hash_alg:base64url_thumbprint
        return f"urn:ietf:params:oauth:ckt:{hash_alg}:{b64url}"

    @staticmethod
    def from_pem(pem_data: bytes, key_type: str = "EC2") -> dict[int, Any]:
        """Convert PEM key to COSE key format.

        Args:
            pem_data: PEM encoded key
            key_type: Type of key (EC2, RSA, etc.)

        Returns:
            COSE key dictionary
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        # Load the PEM key
        try:
            # Try loading as public key first
            key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        except Exception:
            # Try loading as private key
            private_key = serialization.load_pem_private_key(
                pem_data, password=None, backend=default_backend()
            )
            if hasattr(private_key, "public_key"):
                key = private_key.public_key()
            else:
                raise ValueError("Could not extract public key from private key") from None

        # Convert to COSE format based on key type
        if isinstance(key, ec.EllipticCurvePublicKey):
            # EC2 key
            public_numbers = key.public_numbers()
            curve = public_numbers.curve

            # Map curve to COSE curve identifier
            if isinstance(curve, ec.SECP256R1):
                crv = 1  # P-256
            elif isinstance(curve, ec.SECP384R1):
                crv = 2  # P-384
            elif isinstance(curve, ec.SECP521R1):
                crv = 3  # P-521
            else:
                raise ValueError(f"Unsupported curve: {curve.name}")

            # Get x and y coordinates as bytes
            x_bytes = public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, "big")
            y_bytes = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, "big")

            return {
                1: 2,  # kty: EC2
                -1: crv,  # crv
                -2: x_bytes,  # x
                -3: y_bytes,  # y
            }

        elif isinstance(key, rsa.RSAPublicKey):
            # RSA key
            rsa_public_numbers = key.public_numbers()

            n_bytes = rsa_public_numbers.n.to_bytes(
                (rsa_public_numbers.n.bit_length() + 7) // 8, "big"
            )
            e_bytes = rsa_public_numbers.e.to_bytes(
                (rsa_public_numbers.e.bit_length() + 7) // 8, "big"
            )

            return {
                1: 3,  # kty: RSA
                -1: n_bytes,  # n
                -2: e_bytes,  # e
            }

        else:
            raise ValueError(f"Unsupported key type: {type(key)}")
