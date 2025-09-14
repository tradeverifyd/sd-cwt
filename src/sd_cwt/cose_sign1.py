"""COSE Sign1 implementation with pluggable signers and verifiers.

This module provides generic COSE Sign1 signing and verification functions
that accept signer and verifier functions, allowing keys to be managed externally.
"""

from typing import Any, Optional, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import cbor_utils


class Signer(Protocol):
    """Protocol for COSE Sign1 signers."""

    def sign(self, message: bytes) -> bytes:
        """Sign a message and return the signature.

        Args:
            message: The message to sign

        Returns:
            The signature bytes
        """

    @property
    def algorithm(self) -> int:
        """Get the COSE algorithm identifier.

        Returns:
            COSE algorithm identifier (e.g., -7 for ES256)
        """


class Verifier(Protocol):
    """Protocol for COSE Sign1 verifiers."""

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature on a message.

        Args:
            message: The message that was signed
            signature: The signature to verify

        Returns:
            True if signature is valid, False otherwise
        """


def cose_sign1_sign(
    payload: bytes,
    signer: Signer,
    protected_header: Optional[dict[int, Any]] = None,
    unprotected_header: Optional[dict[int, Any]] = None,
    external_aad: bytes = b"",
) -> bytes:
    """Create a COSE Sign1 message.

    Args:
        payload: The payload to sign
        signer: A signer object that implements the sign method
        protected_header: Protected header parameters (will be integrity protected)
        unprotected_header: Unprotected header parameters
        external_aad: External additional authenticated data

    Returns:
        CBOR-encoded COSE Sign1 message with tag 18
    """
    # Build protected header with algorithm
    if protected_header is None:
        protected_header = {}

    # Add algorithm to protected header if not present
    if 1 not in protected_header:
        protected_header[1] = signer.algorithm

    # Encode protected header
    protected_header_bytes = cbor_utils.encode(protected_header) if protected_header else b""

    # Default empty unprotected header
    if unprotected_header is None:
        unprotected_header = {}

    # Create Sig_structure for signing
    sig_structure = [
        "Signature1",  # Context string
        protected_header_bytes,  # Protected header
        external_aad,  # External AAD
        payload,  # Payload
    ]

    # Create signing input
    signing_input = cbor_utils.encode(sig_structure)

    # Sign the message
    signature = signer.sign(signing_input)

    # Create COSE_Sign1 array
    cose_sign1 = [
        protected_header_bytes,
        unprotected_header,
        payload,
        signature,
    ]

    # Encode with COSE_Sign1 tag (18)
    return cbor_utils.encode(cbor_utils.create_tag(18, cose_sign1))


def cose_sign1_verify(
    cose_sign1_message: bytes,
    verifier: Verifier,
    external_aad: bytes = b"",
) -> tuple[bool, Optional[bytes]]:
    """Verify a COSE Sign1 message.

    Args:
        cose_sign1_message: CBOR-encoded COSE Sign1 message
        verifier: A verifier object that implements the verify method
        external_aad: External additional authenticated data used during signing

    Returns:
        Tuple of (verification_result, payload if verified successfully)
    """
    try:
        # Decode CBOR
        decoded = cbor_utils.decode(cose_sign1_message)

        # Handle tagged or untagged COSE_Sign1
        if cbor_utils.is_tag(decoded):
            if cbor_utils.get_tag_number(decoded) != 18:
                return False, None
            cose_sign1 = cbor_utils.get_tag_value(decoded)
        else:
            cose_sign1 = decoded

        # Extract components
        if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
            return False, None

        protected_header_bytes, _, payload, signature = cose_sign1

        # Recreate Sig_structure for verification
        sig_structure = [
            "Signature1",  # Context string
            protected_header_bytes,  # Protected header
            external_aad,  # External AAD
            payload,  # Payload
        ]

        # Create signing input
        signing_input = cbor_utils.encode(sig_structure)

        # Verify signature
        if verifier.verify(signing_input, signature):
            return True, payload
        return False, None

    except (ValueError, TypeError, cbor_utils.CBORDecodeError):
        return False, None


class ES256Signer:
    """ECDSA P-256 SHA-256 signer implementation."""

    def __init__(self, private_key_bytes: bytes):
        """Initialize ES256 signer with private key.

        Args:
            private_key_bytes: The private key bytes (32 bytes for P-256)
        """
        # Create private key from bytes
        private_value = int.from_bytes(private_key_bytes, byteorder='big')
        self.private_key = ec.derive_private_key(
            private_value,
            ec.SECP256R1(),
            default_backend()
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a message with ES256."""
        # Sign the message
        signature_der = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # Convert DER to raw (r||s) format for COSE
        r, s = utils.decode_dss_signature(signature_der)
        signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')

        return signature

    @property
    def algorithm(self) -> int:
        """Get COSE algorithm identifier for ES256."""
        return -7  # ES256


class ES256Verifier:
    """ECDSA P-256 SHA-256 verifier implementation."""

    def __init__(self, public_key_x: bytes, public_key_y: bytes):
        """Initialize ES256 verifier with public key coordinates.

        Args:
            public_key_x: X coordinate of public key (32 bytes)
            public_key_y: Y coordinate of public key (32 bytes)
        """
        # Create public key from coordinates
        x = int.from_bytes(public_key_x, byteorder='big')
        y = int.from_bytes(public_key_y, byteorder='big')

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        self.public_key = public_numbers.public_key(default_backend())

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with ES256."""
        try:
            # Convert raw (r||s) signature to DER format
            if len(signature) != 64:
                return False

            r = int.from_bytes(signature[:32], byteorder='big')
            s = int.from_bytes(signature[32:], byteorder='big')
            signature_der = utils.encode_dss_signature(r, s)

            # Verify the signature
            self.public_key.verify(
                signature_der,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True

        except InvalidSignature:
            return False
        except (ValueError, TypeError):
            return False


def generate_es256_key_pair() -> tuple[bytes, bytes, bytes]:
    """Generate an ES256 (ECDSA P-256) key pair.

    Returns:
        Tuple of (private_key_bytes, public_key_x, public_key_y)
    """
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Get private key bytes
    private_value = private_key.private_numbers().private_value
    private_key_bytes = private_value.to_bytes(32, byteorder='big')

    # Get public key coordinates
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    public_key_x = public_numbers.x.to_bytes(32, byteorder='big')
    public_key_y = public_numbers.y.to_bytes(32, byteorder='big')

    return private_key_bytes, public_key_x, public_key_y
