from . import cbor_utils
"""COSE Key Thumbprint computation according to RFC 9679."""

import hashlib
from typing import Any



class CoseKeyThumbprint:
    """Compute COSE Key Thumbprints for ES256/P-256 keys according to RFC 9679."""

    # Required members for EC2 (kty = 2) only
    REQUIRED_MEMBERS = [1, -1, -2, -3]  # kty, crv, x, y

    @staticmethod
    def canonical_cbor(cose_key: dict[int, Any]) -> bytes:
        """Create canonical CBOR representation of EC2/P-256 COSE key for thumbprint.

        Args:
            cose_key: COSE key as a dictionary with integer labels (must be EC2)

        Returns:
            Canonical CBOR encoding of the key

        Raises:
            ValueError: If key type is not EC2 or required fields are missing
        """
        # Verify this is an EC2 key
        kty = cose_key.get(1)
        if kty != 2:
            raise ValueError(f"Only EC2 keys are supported, got kty: {kty}")

        # Create filtered key with only required members for EC2
        filtered_key = {}
        for label in CoseKeyThumbprint.REQUIRED_MEMBERS:
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
    def from_pem(pem_data: bytes) -> dict[int, Any]:
        """Convert PEM EC key to COSE EC2/P-256 key format.

        Args:
            pem_data: PEM encoded EC key (must be P-256)

        Returns:
            COSE key dictionary for EC2/P-256
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

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

        # Only support EC keys
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("Only EC keys are supported")

        public_numbers = key.public_numbers()
        curve = public_numbers.curve

        # Only support P-256
        if not isinstance(curve, ec.SECP256R1):
            raise ValueError("Only P-256 curve is supported")

        # Get x and y coordinates as 32-byte values for P-256
        x_bytes = public_numbers.x.to_bytes(32, "big")
        y_bytes = public_numbers.y.to_bytes(32, "big")

        return {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            -2: x_bytes,  # x
            -3: y_bytes,  # y
        }
