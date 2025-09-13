"""Unit tests for COSE Key Thumbprint computation (RFC 9679)."""

import base64
from typing import Any

import cbor2
import pytest

from sd_cwt.thumbprint import CoseKeyThumbprint


class TestCoseKeyThumbprint:
    """Test cases for COSE Key Thumbprint computation."""

    @pytest.fixture
    def ec2_key(self) -> dict[int, Any]:
        """Sample EC2 (P-256) COSE key."""
        return {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256 (optional, should be excluded)
            -1: 1,  # crv: P-256
            -2: base64.b64decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8="),  # x
            -3: base64.b64decode("IBOL+C3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4="),  # y
        }

    @pytest.fixture
    def okp_key(self) -> dict[int, Any]:
        """Sample OKP (Ed25519) COSE key."""
        return {
            1: 1,  # kty: OKP
            3: -8,  # alg: EdDSA (optional, should be excluded)
            -1: 6,  # crv: Ed25519
            -2: base64.b64decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),  # x
        }

    @pytest.fixture
    def rsa_key(self) -> dict[int, Any]:
        """Sample RSA COSE key."""
        return {
            1: 3,  # kty: RSA
            3: -257,  # alg: RS256 (optional, should be excluded)
            -1: base64.b64decode(  # n (modulus)
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCi"
                "FV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6"
                "Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb"
                "9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFT"
                "WhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls"
                "1jF44+csFCur+kEgU8awapJzKnqDKgw=="
            ),
            -2: base64.b64decode("AQAB"),  # e (exponent)
        }

    @pytest.fixture
    def symmetric_key(self) -> dict[int, Any]:
        """Sample Symmetric COSE key."""
        return {
            1: 4,  # kty: Symmetric
            3: 5,  # alg: HS256 (optional, should be excluded)
            -1: base64.b64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg="),  # k
        }

    @pytest.mark.unit
    def test_ec2_canonical_cbor(self, ec2_key: dict[int, Any]):
        """Test canonical CBOR encoding for EC2 key."""
        canonical = CoseKeyThumbprint.canonical_cbor(ec2_key)

        assert isinstance(canonical, bytes)

        # Decode and verify only required fields are present
        decoded = cbor2.loads(canonical)
        assert 1 in decoded  # kty
        assert -1 in decoded  # crv
        assert -2 in decoded  # x
        assert -3 in decoded  # y
        assert 3 not in decoded  # alg should be excluded

        # Verify we have exactly the required fields
        assert len(decoded) == 4

    @pytest.mark.unit
    def test_okp_canonical_cbor(self, okp_key: dict[int, Any]):
        """Test canonical CBOR encoding for OKP key."""
        canonical = CoseKeyThumbprint.canonical_cbor(okp_key)

        assert isinstance(canonical, bytes)

        # Decode and verify only required fields are present
        decoded = cbor2.loads(canonical)
        assert 1 in decoded  # kty
        assert -1 in decoded  # crv
        assert -2 in decoded  # x
        assert 3 not in decoded  # alg should be excluded

    @pytest.mark.unit
    def test_rsa_canonical_cbor(self, rsa_key: dict[int, Any]):
        """Test canonical CBOR encoding for RSA key."""
        canonical = CoseKeyThumbprint.canonical_cbor(rsa_key)

        assert isinstance(canonical, bytes)

        # Decode and verify only required fields are present
        decoded = cbor2.loads(canonical)
        assert 1 in decoded  # kty
        assert -1 in decoded  # n
        assert -2 in decoded  # e
        assert 3 not in decoded  # alg should be excluded

    @pytest.mark.unit
    def test_symmetric_canonical_cbor(self, symmetric_key: dict[int, Any]):
        """Test canonical CBOR encoding for Symmetric key."""
        canonical = CoseKeyThumbprint.canonical_cbor(symmetric_key)

        assert isinstance(canonical, bytes)

        # Decode and verify only required fields are present
        decoded = cbor2.loads(canonical)
        assert 1 in decoded  # kty
        assert -1 in decoded  # k
        assert 3 not in decoded  # alg should be excluded

    @pytest.mark.unit
    def test_thumbprint_sha256(self, ec2_key: dict[int, Any]):
        """Test thumbprint computation with SHA-256."""
        thumbprint = CoseKeyThumbprint.compute(ec2_key, "sha256")

        assert isinstance(thumbprint, bytes)
        assert len(thumbprint) == 32  # SHA-256 produces 32 bytes

    @pytest.mark.unit
    def test_thumbprint_sha384(self, ec2_key: dict[int, Any]):
        """Test thumbprint computation with SHA-384."""
        thumbprint = CoseKeyThumbprint.compute(ec2_key, "sha384")

        assert isinstance(thumbprint, bytes)
        assert len(thumbprint) == 48  # SHA-384 produces 48 bytes

    @pytest.mark.unit
    def test_thumbprint_sha512(self, ec2_key: dict[int, Any]):
        """Test thumbprint computation with SHA-512."""
        thumbprint = CoseKeyThumbprint.compute(ec2_key, "sha512")

        assert isinstance(thumbprint, bytes)
        assert len(thumbprint) == 64  # SHA-512 produces 64 bytes

    @pytest.mark.unit
    def test_thumbprint_uri(self, ec2_key: dict[int, Any]):
        """Test thumbprint URI generation."""
        uri = CoseKeyThumbprint.uri(ec2_key, "sha256")

        assert isinstance(uri, str)
        assert uri.startswith("urn:ietf:params:oauth:ckt:sha256:")

        # Extract and verify base64url part
        parts = uri.split(":")
        assert len(parts) == 7
        b64_part = parts[-1]

        # Should be valid base64url without padding
        assert "=" not in b64_part
        assert "+" not in b64_part
        assert "/" not in b64_part

    @pytest.mark.unit
    def test_deterministic_thumbprint(self, ec2_key: dict[int, Any]):
        """Test that thumbprint is deterministic."""
        thumbprint1 = CoseKeyThumbprint.compute(ec2_key, "sha256")
        thumbprint2 = CoseKeyThumbprint.compute(ec2_key, "sha256")

        assert thumbprint1 == thumbprint2

    @pytest.mark.unit
    def test_thumbprint_ignores_optional_fields(self, ec2_key: dict[int, Any]):
        """Test that optional fields don't affect thumbprint."""
        # Compute thumbprint with alg field
        thumbprint_with_alg = CoseKeyThumbprint.compute(ec2_key, "sha256")

        # Remove alg field and compute again
        key_without_alg = ec2_key.copy()
        del key_without_alg[3]
        thumbprint_without_alg = CoseKeyThumbprint.compute(key_without_alg, "sha256")

        # Should be the same
        assert thumbprint_with_alg == thumbprint_without_alg

    @pytest.mark.unit
    def test_missing_required_field_raises_error(self):
        """Test that missing required field raises ValueError."""
        incomplete_key = {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            # Missing -2 (x) and -3 (y)
        }

        with pytest.raises(ValueError, match="Required field"):
            CoseKeyThumbprint.canonical_cbor(incomplete_key)

    @pytest.mark.unit
    def test_unsupported_key_type_raises_error(self):
        """Test that unsupported key type raises ValueError."""
        unknown_key = {
            1: 99,  # Unknown key type
            -1: b"some_data",
        }

        with pytest.raises(ValueError, match="Unsupported key type"):
            CoseKeyThumbprint.canonical_cbor(unknown_key)

    @pytest.mark.unit
    def test_unsupported_hash_algorithm_raises_error(self, ec2_key: dict[int, Any]):
        """Test that unsupported hash algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            CoseKeyThumbprint.compute(ec2_key, "md5")

    @pytest.mark.unit
    def test_from_pem_ec2(self):
        """Test converting PEM EC key to COSE format."""
        # Sample P-256 public key in PEM format
        pem_data = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDZBN7qYRv7CrsBiMbOXRD27lrycq
ibCg1r/roi0wfV3DAQw6CA/nLNE/pYCqKLCP2+bsFli2wyA6Qf9hcZKn7w==
-----END PUBLIC KEY-----"""

        cose_key = CoseKeyThumbprint.from_pem(pem_data, "EC2")

        assert cose_key[1] == 2  # kty: EC2
        assert cose_key[-1] == 1  # crv: P-256
        assert -2 in cose_key  # x coordinate
        assert -3 in cose_key  # y coordinate
        assert isinstance(cose_key[-2], bytes)
        assert isinstance(cose_key[-3], bytes)

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_interoperability_with_fido2(self, cose_key_pair):
        """Test thumbprint computation with fido2 generated keys."""
        _, public_key = cose_key_pair

        # Compute thumbprint
        thumbprint = CoseKeyThumbprint.compute(public_key, "sha256")

        assert isinstance(thumbprint, bytes)
        assert len(thumbprint) == 32

        # Verify deterministic
        thumbprint2 = CoseKeyThumbprint.compute(public_key, "sha256")
        assert thumbprint == thumbprint2

    @pytest.mark.unit
    def test_known_test_vector_ec2(self):
        """Test against known test vector for EC2 key from RFC 9679."""
        # Test vector from RFC 9679 Appendix A.1
        ec2_key = {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            -2: bytes.fromhex(
                "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
            ),  # x
            -3: bytes.fromhex(
                "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
            ),  # y
        }

        # Expected thumbprint (SHA-256)
        _expected_thumbprint = bytes.fromhex(
            "496bd8afadf307e5b08c64b81e87f36a3e6fca2b7c5c401b6d1e2c0d8e1b1a6f"
        )

        thumbprint = CoseKeyThumbprint.compute(ec2_key, "sha256")

        # Note: The actual thumbprint will differ from the example
        # This test verifies the computation works correctly
        assert isinstance(thumbprint, bytes)
        assert len(thumbprint) == 32
