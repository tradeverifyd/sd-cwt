"""Tests for COSE Sign1 functionality."""

import cbor2
import pytest

from sd_cwt import (
    cose_sign1_sign,
    cose_sign1_verify,
)
from sd_cwt.cose_sign1 import (
    ES256Signer,
    ES256Verifier,
    generate_es256_key_pair,
)


class TestCoseSign1Sanity:
    """Sanity tests for COSE Sign1 operations."""

    def test_generate_sign_verify_flow(self) -> None:
        """Test complete flow: generate keys, sign, and verify."""
        # Generate key pair
        private_key, public_x, public_y = generate_es256_key_pair()

        # Verify key sizes
        assert len(private_key) == 32, "Private key should be 32 bytes"
        assert len(public_x) == 32, "Public key X coordinate should be 32 bytes"
        assert len(public_y) == 32, "Public key Y coordinate should be 32 bytes"

        # Create signer and verifier
        signer = ES256Signer(private_key)
        verifier = ES256Verifier(public_x, public_y)

        # Create a test payload
        payload = b"Hello, COSE Sign1!"

        # Sign the payload
        cose_sign1_message = cose_sign1_sign(payload, signer)

        # Verify the signature
        is_valid, recovered_payload = cose_sign1_verify(cose_sign1_message, verifier)

        # Assertions
        assert is_valid, "Signature should be valid"
        assert recovered_payload == payload, "Recovered payload should match original"

    def test_sign_with_custom_headers(self) -> None:
        """Test signing with custom protected and unprotected headers."""
        # Generate keys
        private_key, public_x, public_y = generate_es256_key_pair()
        signer = ES256Signer(private_key)
        verifier = ES256Verifier(public_x, public_y)

        # Custom headers
        protected_header = {
            1: -7,  # Algorithm (ES256)
            4: b"test-key-id",  # Key ID
        }
        unprotected_header = {
            "custom": "value",
        }

        payload = b"Test payload with headers"

        # Sign with custom headers
        cose_sign1_message = cose_sign1_sign(
            payload,
            signer,
            protected_header=protected_header,
            unprotected_header=unprotected_header,
        )

        # Verify
        is_valid, recovered_payload = cose_sign1_verify(cose_sign1_message, verifier)

        assert is_valid, "Signature with custom headers should be valid"
        assert recovered_payload == payload, "Payload should be recovered correctly"

    def test_sign_with_external_aad(self) -> None:
        """Test signing with external additional authenticated data."""
        # Generate keys
        private_key, public_x, public_y = generate_es256_key_pair()
        signer = ES256Signer(private_key)
        verifier = ES256Verifier(public_x, public_y)

        payload = b"Payload with AAD"
        external_aad = b"External context data"

        # Sign with external AAD
        cose_sign1_message = cose_sign1_sign(
            payload,
            signer,
            external_aad=external_aad,
        )

        # Verify with correct AAD
        is_valid, recovered_payload = cose_sign1_verify(
            cose_sign1_message,
            verifier,
            external_aad=external_aad,
        )

        assert is_valid, "Signature with matching AAD should be valid"
        assert recovered_payload == payload, "Payload should be recovered"

        # Verify with wrong AAD should fail
        is_valid_wrong, _ = cose_sign1_verify(
            cose_sign1_message,
            verifier,
            external_aad=b"Wrong AAD",
        )

        assert not is_valid_wrong, "Signature with wrong AAD should be invalid"

    def test_verify_invalid_signature(self) -> None:
        """Test that verification fails with tampered signature."""
        # Generate two different key pairs
        private_key1, _, _ = generate_es256_key_pair()
        _, public_x2, public_y2 = generate_es256_key_pair()

        signer = ES256Signer(private_key1)
        verifier = ES256Verifier(public_x2, public_y2)  # Different key

        payload = b"Test payload"

        # Sign with first key
        cose_sign1_message = cose_sign1_sign(payload, signer)

        # Try to verify with second key (should fail)
        is_valid, recovered_payload = cose_sign1_verify(cose_sign1_message, verifier)

        assert not is_valid, "Verification with wrong key should fail"
        assert recovered_payload is None, "No payload should be returned on failure"

    def test_verify_tampered_payload(self) -> None:
        """Test that verification fails with tampered payload."""
        # Generate keys
        private_key, public_x, public_y = generate_es256_key_pair()
        signer = ES256Signer(private_key)
        verifier = ES256Verifier(public_x, public_y)

        payload = b"Original payload"

        # Sign
        cose_sign1_message = cose_sign1_sign(payload, signer)

        # Decode and tamper with payload
        decoded = cbor2.loads(cose_sign1_message)
        if isinstance(decoded, cbor2.CBORTag):
            cose_array = decoded.value
        else:
            cose_array = decoded

        # Tamper with the payload (index 2)
        cose_array[2] = b"Tampered payload"

        # Re-encode
        tampered_message = cbor2.dumps(cbor2.CBORTag(18, cose_array))

        # Try to verify tampered message
        is_valid, _ = cose_sign1_verify(tampered_message, verifier)

        assert not is_valid, "Verification of tampered message should fail"

    def test_multiple_sign_verify_operations(self) -> None:
        """Test multiple sign/verify operations with same keys."""
        # Generate keys once
        private_key, public_x, public_y = generate_es256_key_pair()
        signer = ES256Signer(private_key)
        verifier = ES256Verifier(public_x, public_y)

        # Sign and verify multiple different payloads
        payloads = [
            b"First message",
            b"Second message with more content",
            b"",  # Empty payload
            b"\x00\x01\x02\x03",  # Binary data
        ]

        for payload in payloads:
            # Sign
            signed_message = cose_sign1_sign(payload, signer)

            # Verify
            is_valid, recovered = cose_sign1_verify(signed_message, verifier)

            assert is_valid, f"Signature should be valid for payload: {payload!r}"
            assert recovered == payload, f"Recovered payload should match: {payload!r}"

    def test_cose_sign1_structure(self) -> None:
        """Test that generated COSE Sign1 has correct structure."""
        # Generate keys and sign
        private_key, _, _ = generate_es256_key_pair()
        signer = ES256Signer(private_key)

        payload = b"Test payload"
        cose_sign1_message = cose_sign1_sign(payload, signer)

        # Decode and check structure
        decoded = cbor2.loads(cose_sign1_message)

        # Should be tagged with tag 18
        assert isinstance(decoded, cbor2.CBORTag), "Should be a CBOR tag"
        assert decoded.tag == 18, "Should be tag 18 (COSE_Sign1)"

        # Check array structure
        cose_array = decoded.value
        assert isinstance(cose_array, list), "COSE_Sign1 should be an array"
        assert len(cose_array) == 4, "COSE_Sign1 should have 4 elements"

        # Check protected header is bytes
        assert isinstance(cose_array[0], bytes), "Protected header should be bytes"

        # Decode protected header and check algorithm
        if cose_array[0]:
            protected = cbor2.loads(cose_array[0])
            assert 1 in protected, "Algorithm should be in protected header"
            assert protected[1] == -7, "Algorithm should be -7 (ES256)"

        # Check unprotected header is dict
        assert isinstance(cose_array[1], dict), "Unprotected header should be dict"

        # Check payload
        assert cose_array[2] == payload, "Payload should match"

        # Check signature is bytes and has correct length
        assert isinstance(cose_array[3], bytes), "Signature should be bytes"
        assert len(cose_array[3]) == 64, "ES256 signature should be 64 bytes"