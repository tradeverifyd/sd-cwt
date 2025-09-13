"""Tests for COSE key generation and management."""

import cbor2
import pytest

from sd_cwt import (
    CoseAlgorithm,
    CoseEllipticCurve,
    CoseKeyType,
    cose_key_from_dict,
    cose_key_generate,
    cose_key_get_public,
    cose_key_thumbprint,
    cose_key_to_dict,
)


class TestCoseKeyGeneration:
    """Tests for COSE key generation."""

    def test_generate_es256_default(self) -> None:
        """Test generating ES256 key (default)."""
        # Generate key with default algorithm
        cose_key = cose_key_generate()

        # Parse the key
        key_dict = cose_key_to_dict(cose_key)

        # Check key type and algorithm
        assert key_dict[1] == CoseKeyType.EC2, "Should be EC2 key type"
        assert key_dict[3] == CoseAlgorithm.ES256, "Should be ES256 algorithm"
        assert key_dict[-1] == CoseEllipticCurve.P256, "Should be P-256 curve"

        # Check key components
        assert -2 in key_dict, "Should have x coordinate"
        assert -3 in key_dict, "Should have y coordinate"
        assert -4 in key_dict, "Should have private key"

        # Check sizes
        assert len(key_dict[-2]) == 32, "X coordinate should be 32 bytes"
        assert len(key_dict[-3]) == 32, "Y coordinate should be 32 bytes"
        assert len(key_dict[-4]) == 32, "Private key should be 32 bytes"

    def test_generate_es384(self) -> None:
        """Test generating ES384 key."""
        cose_key = cose_key_generate(CoseAlgorithm.ES384)
        key_dict = cose_key_to_dict(cose_key)

        assert key_dict[1] == CoseKeyType.EC2, "Should be EC2 key type"
        assert key_dict[3] == CoseAlgorithm.ES384, "Should be ES384 algorithm"
        assert key_dict[-1] == CoseEllipticCurve.P384, "Should be P-384 curve"

        # Check sizes for P-384
        assert len(key_dict[-2]) == 48, "X coordinate should be 48 bytes"
        assert len(key_dict[-3]) == 48, "Y coordinate should be 48 bytes"
        assert len(key_dict[-4]) == 48, "Private key should be 48 bytes"

    def test_generate_es512(self) -> None:
        """Test generating ES512 key."""
        cose_key = cose_key_generate(CoseAlgorithm.ES512)
        key_dict = cose_key_to_dict(cose_key)

        assert key_dict[1] == CoseKeyType.EC2, "Should be EC2 key type"
        assert key_dict[3] == CoseAlgorithm.ES512, "Should be ES512 algorithm"
        assert key_dict[-1] == CoseEllipticCurve.P521, "Should be P-521 curve"

        # Check sizes for P-521 (521 bits = 66 bytes)
        assert len(key_dict[-2]) == 66, "X coordinate should be 66 bytes"
        assert len(key_dict[-3]) == 66, "Y coordinate should be 66 bytes"
        assert len(key_dict[-4]) == 66, "Private key should be 66 bytes"

    def test_generate_eddsa(self) -> None:
        """Test generating EdDSA (Ed25519) key."""
        cose_key = cose_key_generate(CoseAlgorithm.EdDSA)
        key_dict = cose_key_to_dict(cose_key)

        assert key_dict[1] == CoseKeyType.OKP, "Should be OKP key type"
        assert key_dict[3] == CoseAlgorithm.EdDSA, "Should be EdDSA algorithm"
        assert key_dict[-1] == CoseEllipticCurve.Ed25519, "Should be Ed25519 curve"

        # Check key components for OKP
        assert -2 in key_dict, "Should have x (public key)"
        assert -4 in key_dict, "Should have d (private key)"
        assert -3 not in key_dict, "Should not have y coordinate"

        # Check sizes for Ed25519
        assert len(key_dict[-2]) == 32, "Public key should be 32 bytes"
        assert len(key_dict[-4]) == 32, "Private key should be 32 bytes"

    def test_get_public_key(self) -> None:
        """Test extracting public key from COSE key."""
        # Generate a key with private material
        cose_key = cose_key_generate(CoseAlgorithm.ES256)
        key_dict = cose_key_to_dict(cose_key)

        # Verify it has private key
        assert -4 in key_dict, "Original should have private key"

        # Get public key only
        public_key = cose_key_get_public(cose_key)
        public_dict = cose_key_to_dict(public_key)

        # Check that private key is removed
        assert -4 not in public_dict, "Public key should not have private material"

        # Check that public components are preserved
        assert public_dict[1] == key_dict[1], "Key type should be preserved"
        assert public_dict[3] == key_dict[3], "Algorithm should be preserved"
        assert public_dict[-1] == key_dict[-1], "Curve should be preserved"
        assert public_dict[-2] == key_dict[-2], "X coordinate should be preserved"
        assert public_dict[-3] == key_dict[-3], "Y coordinate should be preserved"

    def test_key_thumbprint(self) -> None:
        """Test COSE key thumbprint calculation."""
        # Generate a key
        cose_key = cose_key_generate(CoseAlgorithm.ES256)

        # Calculate thumbprint
        thumbprint = cose_key_thumbprint(cose_key)

        # Check thumbprint properties
        assert isinstance(thumbprint, bytes), "Thumbprint should be bytes"
        assert len(thumbprint) == 32, "SHA-256 thumbprint should be 32 bytes"

        # Thumbprint should be same for public and full key
        public_key = cose_key_get_public(cose_key)
        public_thumbprint = cose_key_thumbprint(public_key)
        assert thumbprint == public_thumbprint, "Thumbprint should be same for public key"

        # Different key should have different thumbprint
        other_key = cose_key_generate(CoseAlgorithm.ES256)
        other_thumbprint = cose_key_thumbprint(other_key)
        assert thumbprint != other_thumbprint, "Different keys should have different thumbprints"

    def test_key_dict_conversion(self) -> None:
        """Test converting between COSE key dict and bytes."""
        # Create a key dict manually
        key_dict = {
            1: CoseKeyType.EC2,
            3: CoseAlgorithm.ES256,
            -1: CoseEllipticCurve.P256,
            -2: b"x" * 32,
            -3: b"y" * 32,
        }

        # Convert to bytes
        cose_key = cose_key_from_dict(key_dict)
        assert isinstance(cose_key, bytes), "Should produce bytes"

        # Convert back to dict
        recovered_dict = cose_key_to_dict(cose_key)

        # Check all fields match
        assert recovered_dict[1] == key_dict[1], "Key type should match"
        assert recovered_dict[3] == key_dict[3], "Algorithm should match"
        assert recovered_dict[-1] == key_dict[-1], "Curve should match"
        assert recovered_dict[-2] == key_dict[-2], "X coordinate should match"
        assert recovered_dict[-3] == key_dict[-3], "Y coordinate should match"

    def test_multiple_algorithms(self) -> None:
        """Test generating keys with all supported algorithms."""
        algorithms = [
            (CoseAlgorithm.ES256, CoseKeyType.EC2, 32),
            (CoseAlgorithm.ES384, CoseKeyType.EC2, 48),
            (CoseAlgorithm.ES512, CoseKeyType.EC2, 66),
            (CoseAlgorithm.EdDSA, CoseKeyType.OKP, 32),
        ]

        for alg, expected_kty, expected_size in algorithms:
            cose_key = cose_key_generate(alg)
            key_dict = cose_key_to_dict(cose_key)

            assert key_dict[1] == expected_kty, f"Wrong key type for {alg}"
            assert key_dict[3] == alg, f"Wrong algorithm for {alg}"

            if expected_kty == CoseKeyType.EC2:
                assert len(key_dict[-2]) == expected_size, f"Wrong X size for {alg}"
                assert len(key_dict[-3]) == expected_size, f"Wrong Y size for {alg}"
            else:  # OKP
                assert len(key_dict[-2]) == expected_size, f"Wrong public key size for {alg}"

    def test_unsupported_algorithm(self) -> None:
        """Test that unsupported algorithm raises error."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            cose_key_generate(9999)  # Invalid algorithm